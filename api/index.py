"""
Domain Intelligence API - passive domain reconnaissance with a findings engine.

Everything is passive or ordinary client traffic: DNS queries, public APIs, one
TLS handshake and one HTTP request per target. No crawling, no brute force.

Sources (all free, no API key):
  RDAP    IANA bootstrap -> authoritative registry RDAP, port-43 WHOIS fallback
  DNS     Cloudflare / Google DNS-over-HTTPS
  TLS     direct socket handshake, protocol + ALPN probing
  HTTP    redirect chain, header audit, cookies, robots.txt / security.txt
  IP      Team Cymru ASN-over-DNS, PTR, ipwho.is geolocation
  Email   SPF / DMARC / DKIM / MTA-STS / TLS-RPT / BIMI
  Subs    crt.sh + HackerTarget + AlienVault OTX, dangling-CNAME hints

Endpoints:
  GET /api/domain/info?domain=example.com[&modules=dns,whois,tls,http,ip,email,subs]
  GET /api/domain/whois|dns|subs|ssl|email|findings?domain=...
  GET /api/health
"""

import concurrent.futures as cf
import datetime as dt
import hashlib
import html as htmllib
import ipaddress
import os
import random
import re
import socket
import ssl
import string
import time
import urllib.parse
import warnings

import requests as rq
from flask import Flask, Response, jsonify, request

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))
MAX_IPS = int(os.getenv("MAX_IPS", "6"))
MAX_RESOLVE = int(os.getenv("MAX_RESOLVE", "120"))
UA = os.getenv("UA", "Mozilla/5.0 (compatible; domain-intel/2.0)")
CORS_ALLOW = os.getenv("CORS_ALLOW", "*")
MONITOR_URL = os.getenv("MONITOR_URL", "")

app = Flask(__name__)

ALL_MODULES = ["dns", "whois", "tls", "http", "ip", "email", "subs"]
SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}

CREATED_CAVEAT = (
    "Registry-reported first registration date for the current registration. "
    "If a domain lapsed, was deleted and re-registered, the original date is "
    "not published by any registry and cannot be recovered."
)


# ══════════════════════════════════════════════════════════════ helpers
def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def parse_dt(s):
    """Parse the many date layouts seen in RDAP/WHOIS into aware UTC."""
    if not s:
        return None
    s = re.sub(r"\s*\(.*?\)\s*$", "", str(s).strip())
    s = re.sub(r"\s+(UTC|GMT)$", "", s)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    d = None
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y.%m.%d %H:%M:%S", "%d-%b-%Y %H:%M:%S",
                    "%d-%b-%Y", "%Y-%m-%d", "%Y.%m.%d", "%Y/%m/%d", "%d/%m/%Y",
                    "%b %d %Y", "%d.%m.%Y"):
            try:
                d = dt.datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%d %H:%M:%SZ") if d else None


def uniq(seq):
    return list(dict.fromkeys(seq))


def short_err(e):
    s = str(getattr(e, "reason", e) or e).strip()
    return s.splitlines()[0][:180] if s else type(e).__name__


def is_public_ip(ip):
    """Block private/loopback/link-local so this cannot probe internal networks."""
    try:
        o = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (o.is_private or o.is_loopback or o.is_link_local or o.is_multicast
                or o.is_reserved or o.is_unspecified)


# ══════════════════════════════════════════════════════════════ target parsing
MULTI_SUFFIXES = set("""
co.uk org.uk me.uk ltd.uk plc.uk ac.uk gov.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au co.nz org.nz net.nz co.za org.za
com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn com.hk com.sg com.my
com.tw com.tr com.mx com.ar com.co com.pk com.bd com.np com.lk com.ng
co.jp ne.jp or.jp ac.jp co.kr or.kr co.id or.id co.th in.th co.il org.il
co.ke co.in net.in org.in firm.in gen.in ind.in ac.in edu.in res.in gov.in nic.in
""".split())

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def registrable_domain(host):
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def parse_target(raw):
    s = (raw or "").strip()
    if not s:
        raise ValueError("empty input")
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)
    s = re.split(r"[/?#]", s, maxsplit=1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.startswith("["):
        host = s[1:s.find("]")] if "]" in s else s[1:]
    elif s.count(":") == 1:
        host = s.split(":")[0]
    else:
        host = s
    host = host.strip().rstrip(".").lower()
    try:
        ip = str(ipaddress.ip_address(host))
        return {"host": ip, "unicode": ip, "registrable": ip, "is_ip": True}
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid internationalised domain name")
    labels = ascii_host.split(".")
    if (len(ascii_host) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or not all(LABEL_RE.match(x) for x in labels)):
        raise ValueError("not a valid domain name")
    uni = ascii_host.encode("ascii").decode("idna")
    return {"host": ascii_host, "unicode": uni,
            "registrable": registrable_domain(ascii_host), "is_ip": False}


# ══════════════════════════════════════════════════════════════ DNS
RTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
             "AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48, "CAA": 257}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DOH = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
NAME_TYPES = {"NS", "CNAME", "PTR", "MX", "SOA", "SRV"}


def _txt_clean(v):
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', v)
    return "".join(parts) if parts else v.strip('"')


def _decode_caa(v):
    try:
        raw = bytes.fromhex("".join(v.split()[2:]))
        tl = raw[1]
        return '%d %s "%s"' % (raw[0], raw[2:2 + tl].decode(), raw[2 + tl:].decode())
    except Exception:
        return v


def _norm_value(rtype, v):
    if rtype == "TXT":
        return _txt_clean(v)
    if rtype in NAME_TYPES:
        return re.sub(r"(?<=[A-Za-z0-9])\.(?=\s|$)", "", v)
    if rtype == "CAA" and v.startswith("\\#"):
        return _decode_caa(v)
    return v


def dns_query(name, rtype):
    rtype = rtype.upper()
    last = None
    for ep in DOH:
        try:
            r = rq.get(ep, params={"name": name, "type": rtype},
                       headers={"Accept": "application/dns-json", "User-Agent": UA},
                       timeout=REQUEST_TIMEOUT)
            data = r.json()
        except Exception as e:
            last = short_err(e)
            continue
        recs = [{"value": _norm_value(rtype, a.get("data", "")), "ttl": a.get("TTL")}
                for a in (data.get("Answer") or []) if a.get("type") == RTYPE_NUM[rtype]]
        return {"records": recs, "status": RCODES.get(data.get("Status", 0), "?"),
                "error": None, "via": ep.split("/")[2]}
    return {"records": [], "status": "ERROR", "error": last, "via": "doh"}


def dns_values(name, rtype):
    return [r["value"] for r in dns_query(name, rtype)["records"]]


def rand_label(n=14):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _mx_sort(v):
    try:
        return (int(v.split()[0]), v)
    except (ValueError, IndexError):
        return (0, v)


def mod_dns(t):
    if t["is_ip"]:
        return {"skipped": "IP target"}
    host, reg = t["host"], t["registrable"]
    types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    out = {"records": {}, "status": {}, "errors": {}, "backend": None}
    with cf.ThreadPoolExecutor(10) as ex:
        futs = {ty: ex.submit(dns_query, host, ty) for ty in types}
        zone = {} if reg == host else {ty: ex.submit(dns_query, reg, ty)
                                        for ty in ("NS", "SOA")}
        ds_f = ex.submit(dns_query, reg, "DS")
        key_f = ex.submit(dns_query, reg, "DNSKEY")
        wild_f = ex.submit(dns_query, "%s.%s" % (rand_label(), reg), "A")
        for ty, f in futs.items():
            r = f.result()
            out["records"][ty] = r["records"]
            out["status"][ty] = r["status"]
            out["backend"] = r.get("via")
            if r.get("error"):
                out["errors"][ty] = r["error"]
        out["zone"] = {ty: f.result()["records"] for ty, f in zone.items()}
        ds, key, wild = ds_f.result(), key_f.result(), wild_f.result()

    out["records"]["MX"].sort(key=lambda r: _mx_sort(r["value"]))
    for ty in ("A", "AAAA", "NS", "TXT", "CAA"):
        out["records"][ty].sort(key=lambda r: r["value"])
    out["exists"] = out["status"].get("A") != "NXDOMAIN"
    out["dnssec"] = {"ds": [r["value"] for r in ds["records"]],
                     "dnskey": len(key["records"]), "signed": bool(ds["records"])}
    out["wildcard"] = bool(wild["records"])

    ns_names = [r["value"].lower()
                for r in (out["zone"].get("NS") or out["records"]["NS"])]
    ns_names = [n for n in ns_names if n][:12]
    with cf.ThreadPoolExecutor(6) as ex:
        out["ns_addresses"] = dict(ex.map(
            lambda n: (n, dns_values(n, "A") + dns_values(n, "AAAA")), ns_names))
    if all(s in ("ERROR", "TIMEOUT") for s in out["status"].values()):
        out["error"] = "DNS resolution failed: %s" % next(
            iter(out["errors"].values()), "no response")
    return out


# ══════════════════════════════════════════════════════════════ RDAP / WHOIS
_bootstrap_cache = {}


def rdap_base(domain):
    """Resolve the authoritative registry RDAP base from the IANA bootstrap."""
    if "v" not in _bootstrap_cache:
        try:
            r = rq.get("https://data.iana.org/rdap/dns.json",
                       headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT)
            _bootstrap_cache["v"] = r.json().get("services", [])
        except Exception:
            _bootstrap_cache["v"] = []
    tld = domain.rsplit(".", 1)[-1].lower()
    try:
        for tlds, urls in _bootstrap_cache["v"]:
            if tld in tlds and urls:
                return sorted(urls, key=lambda u: not u.startswith("https"))[0].rstrip("/") + "/"
    except Exception:
        pass
    return "https://rdap.org/"


def _vcard(ent):
    out = {}
    arr = (ent.get("vcardArray") or [None, []])[1]
    for item in arr:
        if len(item) >= 4:
            val = item[3]
            if isinstance(val, list):
                val = " ".join(str(x) for x in val if x)
            out.setdefault(item[0], val)
    return out


def _walk_entities(ents, acc):
    for e in ents or []:
        card = _vcard(e)
        info = {"name": card.get("fn") or card.get("org"), "org": card.get("org"),
                "email": card.get("email"), "phone": card.get("tel"),
                "handle": e.get("handle")}
        for pid in e.get("publicIds") or []:
            if "iana" in str(pid.get("type", "")).lower():
                info["iana_id"] = pid.get("identifier")
        for role in e.get("roles", []):
            acc.setdefault(role, info)
        _walk_entities(e.get("entities"), acc)


def rdap_lookup(domain):
    out = {"ok": False, "source": "rdap", "errors": []}
    try:
        r = rq.get(rdap_base(domain) + "domain/" + domain,
                   headers={"Accept": "application/rdap+json", "User-Agent": UA},
                   timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        d = r.json()
    except Exception as e:
        out["errors"].append("RDAP %s: %s" % (domain, short_err(e)))
        out["error"] = "; ".join(out["errors"])
        return out

    ev = {}
    for e in d.get("events") or []:
        ev.setdefault(e.get("eventAction"), e.get("eventDate"))
    ents = {}
    _walk_entities(d.get("entities"), ents)
    out.update({
        "ok": True, "queried": domain,
        "handle": d.get("handle"), "ldhName": d.get("ldhName"),
        "unicodeName": d.get("unicodeName"),
        "registrar": ents.get("registrar"), "registrant": ents.get("registrant"),
        "abuse": ents.get("abuse"), "technical": ents.get("technical"),
        "admin": ents.get("administrative"),
        "status": d.get("status") or [],
        "nameservers": sorted({(n.get("ldhName") or "").lower()
                               for n in d.get("nameservers") or [] if n.get("ldhName")}),
        "secure_dns": bool(d.get("secureDNS")),
        "created": ev.get("registration"), "updated": ev.get("last changed"),
        "expires": ev.get("expiration"), "transferred": ev.get("transfer"),
        "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")}
                   for e in d.get("events") or [] if e.get("eventDate")],
    })
    return out


WHOIS_KEYS = {
    "registrar": ["Registrar", "Sponsoring Registrar", "registrar name"],
    "created": ["Creation Date", "Created On", "created", "Registered on",
                "Domain Registration Date", "Registration Time"],
    "updated": ["Updated Date", "Last Updated On", "last-update", "Last Modified",
                "modified", "Last Update"],
    "expires": ["Registry Expiry Date", "Registrar Registration Expiration Date",
                "Expiry Date", "Expiration Date", "paid-till", "Expires On",
                "Expiration Time", "renewal date"],
    "dnssec": ["DNSSEC"],
    "registrant": ["Registrant Organization", "Registrant Name", "Registrant"],
    "abuse_email": ["Registrar Abuse Contact Email"],
}


def whois_query(server, query):
    with socket.create_connection((server, 43), timeout=12) as s:
        s.settimeout(12)
        s.sendall((query + "\r\n").encode())
        data = b""
        while len(data) < 400000:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    return data.decode("utf-8", "replace")


def whois_raw(domain):
    """IANA -> registry WHOIS -> registrar WHOIS (two-hop referral chain)."""
    tld = domain.rsplit(".", 1)[-1]
    iana = whois_query("whois.iana.org", tld)
    m = re.search(r"^\s*whois:\s*(\S+)", iana, re.M | re.I)
    if not m:
        raise ValueError("no WHOIS server known for .%s" % tld)
    server = m.group(1)
    text = whois_query(server, domain)
    m2 = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.I)
    if m2 and m2.group(1).lower().rstrip(".") != server.lower():
        try:
            more = whois_query(m2.group(1), domain)
            if len(more) > 200:
                text, server = more, m2.group(1)
        except OSError:
            pass
    return server, text


def parse_whois_text(text):
    out = {}
    for field, keys in WHOIS_KEYS.items():
        for k in keys:
            m = re.search(r"^\s*%s\s*:\s*(.+?)\s*$" % re.escape(k), text, re.M | re.I)
            if m:
                out[field] = m.group(1)
                break
    out["status"] = uniq(s.split()[0] for s in re.findall(
        r"^\s*(?:Domain )?Status\s*:\s*(.+?)\s*$", text, re.M | re.I))
    out["nameservers"] = sorted({n.split()[0].lower().rstrip(".") for n in re.findall(
        r"^\s*(?:Name Server|nserver)\s*:\s*(.+?)\s*$", text, re.M | re.I)})
    return out


def _derive_dates(o):
    c, e, u = parse_dt(o.get("created")), parse_dt(o.get("expires")), parse_dt(o.get("updated"))
    n = now_utc()
    o["created_iso"], o["expires_iso"], o["updated_iso"] = iso(c), iso(e), iso(u)
    o["age_days"] = (n - c).days if c else None
    o["days_to_expiry"] = (e - n).days if e else None


def mod_whois(t, cross_check=True):
    if t["is_ip"]:
        return {"skipped": "IP target"}
    out = {"errors": []}
    r = rdap_lookup(t["registrable"])
    if r.get("ok"):
        out.update(r)
    else:
        out["errors"].extend(r.get("errors") or [])
        try:
            server, text = whois_raw(t["registrable"])
            out.update(parse_whois_text(text))
            out["source"] = "whois"
            out["queried"] = t["registrable"]
            out["whois_server"] = server
            if re.search(r"no match|not found|no data found|status:\s*free|available",
                         text[:600], re.I) and not out.get("created"):
                out["registered"] = False
        except Exception as e:
            out["errors"].append("WHOIS: %s" % short_err(e))

    if cross_check:
        try:
            _srv, wtext = whois_raw(t["registrable"])
            wc = parse_dt(parse_whois_text(wtext).get("created"))
            rc = parse_dt(out.get("created"))
            out["whois_created"] = iso(wc)
            out["created_verified"] = bool(wc)
            if rc and wc and rc.date() != wc.date():
                out["created_discrepancy"] = {
                    "rdap": out.get("created"), "whois": iso(wc),
                    "note": "sources disagree; registry RDAP is authoritative"}
        except Exception:
            out["created_verified"] = False
    else:
        out["created_verified"] = None

    if not out.get("source"):
        out["error"] = "; ".join(out["errors"]) or "no registration data"
        return out
    out.setdefault("created_source", out.get("source"))
    _derive_dates(out)
    out["created_caveat"] = CREATED_CAVEAT
    return out


# ══════════════════════════════════════════════════════════════ TLS
def _rdn(seq):
    out = {}
    for rdn in seq or ():
        for k, v in rdn:
            out.setdefault(k, v)
    return out


def _host_matches(host, names):
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and "." in host and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def _fp(der, algo):
    return ":".join("%02X" % b for b in hashlib.new(algo, der).digest())


def _handshake(ctx, host, port, sni):
    with socket.create_connection((host, port), timeout=12) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as s:
            return {"version": s.version(), "cipher": s.cipher(),
                    "alpn": s.selected_alpn_protocol(),
                    "der": s.getpeercert(binary_form=True),
                    "cert": s.getpeercert() or None}


def _unverified_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_inspect(host, port, is_ip):
    sni = None if is_ip else host
    info = {"host": host, "port": port, "verified": False, "verify_error": None}
    hs = None
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        hs = _handshake(ctx, host, port, sni)
        info["verified"] = True
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = getattr(e, "verify_message", None) or short_err(e)
    except (ssl.SSLError, OSError) as e:
        return {"error": "TLS connection failed on port %d: %s" % (port, short_err(e))}
    if hs is None:
        try:
            hs = _handshake(_unverified_ctx(), host, port, sni)
        except (ssl.SSLError, OSError) as e:
            info["error"] = short_err(e)
            return info
    der, cert = hs["der"], hs["cert"]
    c = hs["cipher"] or (None, None, None)
    info.update(tls_version=hs["version"], alpn=hs["alpn"],
                cipher={"name": c[0], "protocol": c[1], "bits": c[2]},
                sha256_fingerprint=_fp(der, "sha256"),
                sha1_fingerprint=_fp(der, "sha1"))
    if not cert:
        info["note"] = "certificate could not be decoded"
        return info
    subj, iss = _rdn(cert.get("subject")), _rdn(cert.get("issuer"))
    sans = [v for k, v in (cert.get("subjectAltName") or ()) if k == "DNS"]
    ips = [v for k, v in (cert.get("subjectAltName") or ()) if k == "IP Address"]
    nb = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), dt.timezone.utc)
    na = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    names = sans or ([subj["commonName"]] if "commonName" in subj else [])
    info.update(
        subject=subj, issuer=iss,
        subject_cn=subj.get("commonName"), issuer_cn=iss.get("commonName"),
        issuer_org=iss.get("organizationName"),
        valid_from=iso(nb), valid_to=iso(na),
        days_left=(na - now_utc()).days, lifetime_days=(na - nb).days,
        expired=na < now_utc(), not_yet_valid=nb > now_utc(),
        serial=cert.get("serialNumber"), version=cert.get("version"),
        sans=sans, san_ips=ips, san_count=len(set(sans)),
        wildcard=any(s.startswith("*.") for s in sans),
        self_signed=bool(subj) and subj == iss,
        hostname_match=True if info["verified"] else (
            (host in ips) if is_ip else _host_matches(host, names)),
        ocsp=list(cert.get("OCSP") or ()),
        crl=list(cert.get("crlDistributionPoints") or ()),
    )
    return info


def probe_protocols(host, port, is_ip):
    """Detect support for legacy TLS versions - a real compliance finding."""
    sni = None if is_ip else host
    versions = [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]

    def probe(item):
        name, ver = item
        ctx = _unverified_ctx()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ctx.maximum_version = ver
        except (ValueError, ssl.SSLError):
            return name, "untestable"
        try:
            _handshake(ctx, host, port, sni)
            return name, "accepted"
        except ssl.SSLError:
            return name, "rejected"
        except OSError:
            return name, "error"

    with cf.ThreadPoolExecutor(4) as ex:
        return dict(ex.map(probe, versions))


def mod_tls(t):
    info = tls_inspect(t["host"], 443, t["is_ip"])
    if "error" not in info or "tls_version" in info:
        try:
            info["protocols"] = probe_protocols(t["host"], 443, t["is_ip"])
        except Exception as e:
            info["protocols"] = {"error": short_err(e)}
    return info


# ══════════════════════════════════════════════════════════════ HTTP
HEADER_TECH = [("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"),
               ("x-vercel-id", "Vercel"), ("x-nf-request-id", "Netlify"),
               ("x-github-request-id", "GitHub Pages"), ("fly-request-id", "Fly.io"),
               ("x-azure-ref", "Azure Front Door"), ("x-sucuri-id", "Sucuri"),
               ("x-akamai-transformed", "Akamai"), ("x-wix-request-id", "Wix"),
               ("x-shopify-stage", "Shopify"), ("x-drupal-cache", "Drupal"),
               ("x-served-by", "Fastly/Varnish"),
               ("x-envoy-upstream-service-time", "Envoy"),
               ("x-render-origin-server", "Render"), ("x-railway-edge", "Railway")]
BODY_TECH = [("wp-content", "WordPress"), ("wp-includes", "WordPress"),
             ("/_next/", "Next.js"), ("__NEXT_DATA__", "Next.js"), ("/_nuxt/", "Nuxt"),
             ("cdn.shopify.com", "Shopify"), ("Drupal.settings", "Drupal"),
             ('content="Joomla', "Joomla"), ("googletagmanager.com", "Google Tag Manager"),
             ("google-analytics.com", "Google Analytics"),
             ("static.wixstatic.com", "Wix"), ("squarespace.com", "Squarespace"),
             ("data-reactroot", "React"), ("ng-version", "Angular"),
             ("cdn.jsdelivr.net/npm/bootstrap", "Bootstrap"),
             ("cloudflareinsights.com", "Cloudflare Web Analytics")]
SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options",
               "x-content-type-options", "referrer-policy", "permissions-policy",
               "cross-origin-opener-policy", "cross-origin-resource-policy"]


def detect_tech(h, body):
    tech = [name for k, name in HEADER_TECH if k in h]
    server = h.get("server", "")
    if server and re.search(r"cloudflare", server, re.I):
        tech.append("Cloudflare")
    for k in ("x-powered-by", "x-generator", "x-aspnet-version", "x-runtime"):
        if h.get(k):
            tech.append("%s: %s" % (k, h[k]))
    if server:
        tech.append("server: %s" % server)
    tech += [name for needle, name in BODY_TECH if needle in body]
    m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)", body, re.I)
    if m:
        tech.append("generator: %s" % m.group(1)[:80])
    return uniq(tech)


def audit_headers(h):
    """Real issues, not just a header count."""
    res = {k: h.get(k) for k in SEC_HEADERS}
    issues = []
    hsts = h.get("strict-transport-security")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < 15552000:
            issues.append("HSTS max-age is %d (< 180 days recommended)" % age)
        if "includesubdomains" not in hsts.lower():
            issues.append("HSTS lacks includeSubDomains")
    csp = h.get("content-security-policy")
    if csp:
        if "'unsafe-inline'" in csp:
            issues.append("CSP allows 'unsafe-inline'")
        if "'unsafe-eval'" in csp:
            issues.append("CSP allows 'unsafe-eval'")
    framing = h.get("x-frame-options") or ("frame-ancestors" in (csp or "").lower())
    if not framing:
        issues.append("no clickjacking protection (X-Frame-Options / frame-ancestors)")
    if (h.get("x-content-type-options") or "").lower() != "nosniff":
        issues.append("X-Content-Type-Options: nosniff missing")
    return {"headers": res, "present": sum(1 for v in res.values() if v),
            "total": len(res), "issues": issues,
            "score": round(sum(1 for v in res.values() if v) / len(res) * 100)}


def parse_cookies(pairs):
    out = []
    for k, v in pairs:
        if k.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in v.split(";")]
        flags = {p.split("=")[0].lower(): (p.split("=", 1)[1] if "=" in p else True)
                 for p in parts[1:]}
        out.append({"name": parts[0].split("=", 1)[0], "secure": "secure" in flags,
                    "httponly": "httponly" in flags, "samesite": flags.get("samesite")})
    return out


def http_fetch(url, max_bytes=262144, verify=True, allow_redirects=True):
    t0 = time.perf_counter()
    try:
        r = rq.get(url, headers={"User-Agent": UA, "Accept": "*/*"},
                   timeout=REQUEST_TIMEOUT, allow_redirects=allow_redirects,
                   verify=verify, stream=True)
        body = r.raw.read(max_bytes, decode_content=True) or b""
        hdrs = [(k, v) for k, v in r.headers.items()]
        out = {"url": r.url, "status": r.status_code, "headers": hdrs,
               "body": body, "ms": round((time.perf_counter() - t0) * 1000)}
        r.close()
        return out
    except Exception as e:
        raise RuntimeError(short_err(e))


def probe_site(url, max_hops=10):
    """Follow the redirect chain by hand so every hop is reported."""
    chain, seen, verify, insecure = [], set(), True, False
    cur = url
    while len(chain) <= max_hops:
        if cur in seen:
            chain.append({"url": cur, "error": "redirect loop"})
            break
        try:
            r = http_fetch(cur, verify=verify, allow_redirects=False)
        except Exception as e:
            msg = str(e)
            if "certificate" in msg.lower() and verify:
                verify, insecure = False, True
                continue
            chain.append({"url": cur, "error": msg})
            break
        seen.add(cur)
        hd = {}
        for k, v in r["headers"]:
            hd.setdefault(k.lower(), v)
        loc = hd.get("location")
        chain.append({"url": cur, "status": r["status"], "ms": r["ms"],
                      "server": hd.get("server"), "location": loc})
        if r["status"] in (301, 302, 303, 307, 308) and loc:
            cur = urllib.parse.urljoin(cur, loc)
            continue
        body = r["body"].decode("utf-8", "replace")
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        res = {"chain": chain, "insecure_tls_used": insecure, "error": None,
               "final_url": cur, "status": r["status"], "response_ms": r["ms"],
               "headers": {k: v for k, v in hd.items() if k != "set-cookie"},
               "title": (re.sub(r"\s+", " ", htmllib.unescape(m.group(1))).strip()[:200]
                         if m else None),
               "technologies": detect_tech(hd, body),
               "security": audit_headers(hd),
               "cookies": parse_cookies(r["headers"])}
        return res
    return {"chain": chain, "error": chain[-1].get("error") if chain else "too many redirects",
            "insecure_tls_used": insecure}


def probe_files(base):
    out = {}
    try:
        r = http_fetch(base + "/.well-known/security.txt", max_bytes=65536)
        body = r["body"].decode("utf-8", "replace")
        out["security_txt"] = bool(r["status"] == 200 and
                                   re.search(r"^\s*Contact\s*:", body, re.M | re.I))
        if out["security_txt"]:
            out["security_txt_contact"] = re.findall(
                r"^\s*Contact\s*:\s*(.+)$", body, re.M | re.I)[:3]
    except Exception:
        out["security_txt"] = None
    try:
        r = http_fetch(base + "/robots.txt", max_bytes=262144)
        body = r["body"].decode("utf-8", "replace")
        ok = r["status"] == 200 and "<html" not in body[:300].lower()
        out["robots_txt"] = ok
        if ok:
            out["robots_disallow"] = len(re.findall(r"^\s*Disallow\s*:\s*\S", body, re.M | re.I))
            out["sitemaps"] = re.findall(r"^\s*Sitemap\s*:\s*(\S+)", body, re.M | re.I)[:5]
    except Exception:
        out["robots_txt"] = None
    return out


def mod_http(t):
    if t["is_ip"]:
        return {"skipped": "IP target"}
    with cf.ThreadPoolExecutor(2) as ex:
        fh = ex.submit(probe_site, "https://%s/" % t["host"])
        fp = ex.submit(probe_site, "http://%s/" % t["host"])
        out = {"https": fh.result(), "http": fp.result()}
    hp = out["http"]
    out["http_redirects_to_https"] = (
        any(c["url"].startswith("https://") for c in hp["chain"][1:])
        if not hp.get("error") else None)
    good = out["https"] if not out["https"].get("error") else (
        out["http"] if not out["http"].get("error") else None)
    if good:
        p = urllib.parse.urlsplit(good["final_url"])
        out["files"] = probe_files("%s://%s" % (p.scheme, p.netloc))
    return out


# ══════════════════════════════════════════════════════════════ IP intelligence
HOST_HINTS = [("cloudflare", "Cloudflare"), ("amazon", "AWS"), ("google", "Google"),
              ("microsoft", "Microsoft Azure"), ("akamai", "Akamai"), ("fastly", "Fastly"),
              ("digitalocean", "DigitalOcean"), ("ovh", "OVH"), ("hetzner", "Hetzner"),
              ("linode", "Linode"), ("vultr", "Vultr"), ("github", "GitHub"),
              ("oracle", "Oracle Cloud"), ("alibaba", "Alibaba Cloud"),
              ("incapsula", "Imperva"), ("netlify", "Netlify"), ("godaddy", "GoDaddy"),
              ("bharti", "Airtel"), ("reliance", "Reliance/Jio"), ("tata", "Tata")]


def asn_lookup(ip):
    """Team Cymru ASN-over-DNS: authoritative ASN + prefix + allocation date."""
    a = ipaddress.ip_address(ip)
    rp = a.reverse_pointer
    q = ((rp[:-len(".in-addr.arpa")] + ".origin.asn.cymru.com") if a.version == 4
         else (rp[:-len(".ip6.arpa")] + ".origin6.asn.cymru.com"))
    vals = dns_values(q, "TXT")
    if not vals:
        return None
    p = [x.strip() for x in vals[0].split("|")]
    asns = p[0].split()
    out = {"asn": ["AS" + x for x in asns],
           "prefix": p[1] if len(p) > 1 else None,
           "country": p[2] if len(p) > 2 else None,
           "registry": p[3] if len(p) > 3 else None,
           "allocated": p[4] if len(p) > 4 else None,
           "name": None}
    if asns:
        nm = dns_values("AS%s.asn.cymru.com" % asns[0], "TXT")
        if nm:
            q2 = [x.strip() for x in nm[0].split("|")]
            out["name"] = q2[4] if len(q2) > 4 else None
    return out


def geo_lookup(ip):
    try:
        r = rq.get("https://ipwho.is/%s" % ip, timeout=10, headers={"User-Agent": UA})
        d = r.json()
        if d.get("success") is False:
            return {"error": d.get("message", "lookup failed")}
        conn = d.get("connection") or {}
        return {"country": d.get("country"), "country_code": d.get("country_code"),
                "region": d.get("region"), "city": d.get("city"),
                "lat": d.get("latitude"), "lon": d.get("longitude"),
                "timezone": (d.get("timezone") or {}).get("id"),
                "isp": conn.get("isp"), "org": conn.get("org"), "asn": conn.get("asn")}
    except Exception as e:
        return {"error": short_err(e)}


def ip_profile(ip):
    a = ipaddress.ip_address(ip)
    prof = {"ip": ip, "version": a.version, "global": a.is_global, "private": a.is_private}
    if not a.is_global:
        return prof
    with cf.ThreadPoolExecutor(3) as ex:
        f1 = ex.submit(dns_values, a.reverse_pointer, "PTR")
        f2 = ex.submit(asn_lookup, ip)
        f3 = ex.submit(geo_lookup, ip)
        prof["ptr"], prof["asn"], prof["geo"] = f1.result(), f2.result(), f3.result()
    blob = " ".join(filter(None, [(prof["asn"] or {}).get("name"), (prof["geo"] or {}).get("org"),
                                  (prof["geo"] or {}).get("isp")])).lower()
    prof["hosting_hint"] = next((n for k, n in HOST_HINTS if k in blob), None)
    return prof


def mod_ip(t):
    if t["is_ip"]:
        ips = [t["host"]]
    else:
        ips, sts = [], []
        for ty in ("A", "AAAA"):
            r = dns_query(t["host"], ty)
            ips += [x["value"] for x in r["records"]]
            sts.append(r["status"])
        if not ips and all(x in ("ERROR", "TIMEOUT", "SERVFAIL") for x in sts):
            return {"error": "DNS lookup failed - cannot resolve addresses"}
    public = [x for x in uniq(ips) if is_public_ip(x)]
    private = [x for x in uniq(ips) if not is_public_ip(x)]
    if not ips:
        return {"addresses": [], "note": "no A/AAAA records"}
    with cf.ThreadPoolExecutor(4) as ex:
        addrs = list(ex.map(ip_profile, public[:MAX_IPS]))
    out = {"addresses": addrs, "public_count": len(public)}
    if private:
        out["non_public_addresses"] = private
    return out


# ══════════════════════════════════════════════════════════════ e-mail security
MX_PROVIDERS = [("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
                ("protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft 365"),
                ("zoho.", "Zoho Mail"), ("pphosted.com", "Proofpoint"), ("mimecast", "Mimecast"),
                ("secureserver.net", "GoDaddy"), ("yahoodns.net", "Yahoo"),
                ("protonmail", "Proton Mail"), ("mailgun.org", "Mailgun"),
                ("sendgrid.net", "SendGrid"), ("icloud.com", "iCloud"),
                ("fastmail", "Fastmail"), ("zoho.in", "Zoho Mail (IN)"),
                ("emailsrvr.com", "Rackspace"), ("barracudanetworks.com", "Barracuda"),
                ("messagelabs.com", "Broadcom/Symantec")]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "k3",
                  "s1", "s2", "mail", "dkim", "smtp", "mandrill", "mxvault", "zoho",
                  "mailjet", "sendgrid", "amazonses", "mta", "email", "cm", "dkim1",
                  "dkim2", "protonmail", "protonmail2", "protonmail3"]


def _spf_records(domain):
    return [v for v in dns_values(domain, "TXT") if v.lower().startswith("v=spf1")]


def spf_count(record, seen, depth=0):
    """Count DNS lookups an SPF record needs (the RFC limit is 10)."""
    n = 0
    for term in record.split()[1:]:
        t2 = term.lstrip("+-~?")
        name = re.split(r"[:=/]", t2.lower(), maxsplit=1)[0]
        if name in ("a", "mx", "ptr", "exists"):
            n += 1
        elif name in ("include", "redirect"):
            n += 1
            target = re.split(r"[:=]", t2, maxsplit=1)[1].lower() if re.search(r"[:=]", t2) else ""
            if target and "%{" not in target and target not in seen and depth < 10:
                seen.add(target)
                recs = _spf_records(target)
                if recs:
                    n += spf_count(recs[0], seen, depth + 1)
    return n


def parse_tags(txt):
    return {k.strip().lower(): v.strip()
            for k, _, v in (p.partition("=") for p in txt.split(";") if p.strip())}


def mod_email(t):
    if t["is_ip"]:
        return {"skipped": "IP target"}
    d = t["registrable"]
    chk = dns_query(d, "NS")
    if chk["status"] in ("ERROR", "TIMEOUT", "SERVFAIL"):
        return {"error": "DNS lookup failed - e-mail records cannot be evaluated"}
    out = {"domain": d}
    mx = sorted(dns_values(d, "MX"), key=_mx_sort)
    hosts = [m.split(None, 1)[-1].lower() for m in mx]
    out["mx"] = mx
    out["mx_provider"] = uniq(n for h in hosts for k, n in MX_PROVIDERS if k in h) or None
    out["null_mx"] = mx in (["0 ."], ["0"])

    spf = _spf_records(d)
    s = {"records": spf, "present": bool(spf), "multiple": len(spf) > 1}
    if spf:
        rec = spf[0]
        allt = next((x for x in rec.split()[1:] if re.fullmatch(r"[+\-~?]?all", x, re.I)), None)
        s.update(policy=allt, lookups=spf_count(rec, {d}),
                 includes=[x.split(":", 1)[1] for x in rec.split()
                           if x.lower().lstrip("+-~?").startswith("include:")])
        s["lookups_exceeded"] = s["lookups"] > 10
    out["spf"] = s

    dm_txt = [v for v in dns_values("_dmarc." + d, "TXT") if v.lower().startswith("v=dmarc1")]
    dm = {"present": bool(dm_txt)}
    if dm_txt:
        tags = parse_tags(dm_txt[0])
        dm.update(record=dm_txt[0], policy=tags.get("p"), subdomain_policy=tags.get("sp"),
                  pct=tags.get("pct", "100"), rua=tags.get("rua"), ruf=tags.get("ruf"),
                  adkim=tags.get("adkim", "r"), aspf=tags.get("aspf", "r"))
    out["dmarc"] = dm

    def dkim(sel):
        for v in dns_values("%s._domainkey.%s" % (sel, d), "TXT"):
            if "p=" in v or "v=dkim1" in v.lower():
                return sel
        return None

    with cf.ThreadPoolExecutor(10) as ex:
        out["dkim_selectors_found"] = [x for x in ex.map(dkim, DKIM_SELECTORS) if x]
    out["dkim_note"] = ("only %d common selectors probed - selectors cannot be enumerated"
                        % len(DKIM_SELECTORS))

    sts = {"dns": [v for v in dns_values("_mta-sts." + d, "TXT")
                   if v.lower().startswith("v=stsv1")]}
    if sts["dns"]:
        try:
            r = http_fetch("https://mta-sts.%s/.well-known/mta-sts.txt" % d, max_bytes=32768)
            body = r["body"].decode("utf-8", "replace")
            mm = re.search(r"^mode\s*:\s*(\w+)", body, re.M | re.I)
            ma = re.search(r"^max_age\s*:\s*(\d+)", body, re.M | re.I)
            sts["mode"] = mm.group(1) if mm else None
            sts["max_age"] = int(ma.group(1)) if ma else None
        except Exception as e:
            sts["policy_error"] = str(e)
    out["mta_sts"] = sts
    out["tls_rpt"] = [v for v in dns_values("_smtp._tls." + d, "TXT")
                      if v.lower().startswith("v=tlsrptv1")]
    out["bimi"] = [v for v in dns_values("default._bimi." + d, "TXT")
                   if v.lower().startswith("v=bimi1")]
    return out


# ══════════════════════════════════════════════════════════════ subdomains
TAKEOVER = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3 website",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Service",
    "cloudapp.azure.com": "Azure VM", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "pantheonsite.io": "Pantheon", "netlify.app": "Netlify", "readthedocs.io": "Read the Docs",
    "surge.sh": "Surge", "bitbucket.io": "Bitbucket", "ghost.io": "Ghost",
    "helpscoutdocs.com": "Help Scout", "statuspage.io": "Statuspage", "zendesk.com": "Zendesk",
    "myshopify.com": "Shopify", "unbouncepages.com": "Unbounce", "fastly.net": "Fastly",
    "cloudfront.net": "CloudFront",
}


def takeover_hint(cname):
    c = (cname or "").lower()
    return next((v for k, v in TAKEOVER.items() if k in c), None)


def _src_crtsh(base):
    # params= (not string formatting) so the leading % is encoded correctly.
    # crt.sh is frequently flaky (502/503) so retry a few times.
    last = None
    for attempt in range(3):
        try:
            r = rq.get("https://crt.sh/", params={"q": "%%.%s" % base, "output": "json"},
                       headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT + 20)
            if r.status_code == 200:
                names = set()
                for row in r.json():
                    for n in str(row.get("name_value", "")).splitlines():
                        names.add(re.sub(r"^\*\.", "", n.strip().lower()))
                return names
            last = "http %s" % r.status_code
        except Exception as e:
            last = short_err(e)
        time.sleep(1.5 * (attempt + 1))
    raise RuntimeError("crt.sh %s" % last)


def _src_hackertarget(base):
    r = rq.get("https://api.hackertarget.com/hostsearch/",
               params={"q": base}, headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT)
    text = r.text
    if "API count exceeded" in text or text.lower().startswith("error"):
        raise RuntimeError(text.strip()[:80])
    return {ln.split(",")[0].strip().lower() for ln in text.splitlines() if "," in ln}


def _src_otx(base):
    r = rq.get("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns" % base,
               headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return {str(x.get("hostname", "")).strip().lower()
            for x in (r.json().get("passive_dns") or [])}


def resolve_host(h):
    try:
        canon, _aliases, ips = socket.gethostbyname_ex(h)
        return {"host": h, "ips": ips,
                "cname": canon if canon.lower() != h else None, "resolves": True}
    except (socket.gaierror, UnicodeError, OSError):
        pass
    ips = [v for v in dns_values(h, "A") if is_public_ip(v)] + dns_values(h, "AAAA")
    cname = (dns_values(h, "CNAME") or [None])[0]
    res = {"host": h, "ips": ips, "cname": cname, "resolves": bool(ips)}
    if not ips and cname:
        res["takeover_hint"] = takeover_hint(cname)
    return res


def mod_subs(t):
    if t["is_ip"]:
        return {"skipped": "IP target"}
    base = t["registrable"]
    found, status = {}, {}
    sources = {"crt.sh": _src_crtsh, "hackertarget": _src_hackertarget,
               "alienvault-otx": _src_otx}
    with cf.ThreadPoolExecutor(3) as ex:
        futs = {n: ex.submit(f, base) for n, f in sources.items()}
        for n, fu in futs.items():
            try:
                names = {x for x in fu.result() if x.endswith("." + base) or x == base}
                names = {x for x in names if re.fullmatch(r"[a-z0-9_.-]+", x) and ".." not in x}
                status[n] = len(names)
                for x in names:
                    found.setdefault(x, set()).add(n)
            except Exception as e:
                status[n] = "error: %s" % short_err(e)

    wild = resolve_host("%s.%s" % (rand_label(), base))
    wild_ips = set(wild["ips"]) if wild["resolves"] else set()
    names = sorted(found)
    with cf.ThreadPoolExecutor(20) as ex:
        resolved = list(ex.map(resolve_host, names[:MAX_RESOLVE]))
    for r in resolved:
        if wild_ips and set(r["ips"]) and set(r["ips"]) <= wild_ips:
            r["wildcard_suspect"] = True
        r["sources"] = sorted(found[r["host"]])
    return {
        "base": base, "total": len(names), "resolved_checked": len(resolved),
        "sources": status, "wildcard_dns": bool(wild_ips),
        "subdomains": resolved,
        "unchecked": names[MAX_RESOLVE:],
        "dangling_candidates": [r for r in resolved if r.get("takeover_hint")],
    }


# ══════════════════════════════════════════════════════════════ findings
def analyze(m):
    """Turn raw module output into severity-rated findings."""
    F = []
    add = lambda sev, mod, msg: F.append({"severity": sev, "module": mod, "message": msg})
    w = m.get("whois") or {}
    d = m.get("dns") or {}
    s = m.get("tls") or m.get("ssl") or {}
    h = m.get("http") or {}
    e = m.get("email") or {}
    ip = m.get("ip") or {}
    sub = m.get("subs") or {}

    dte = w.get("days_to_expiry")
    if dte is not None:
        if dte < 0:
            add("high", "whois", "Domain registration expired %d days ago" % -dte)
        elif dte < 30:
            add("high", "whois", "Domain expires in %d days" % dte)
        elif dte < 90:
            add("medium", "whois", "Domain expires in %d days" % dte)
    if w.get("age_days") is not None and w["age_days"] < 30:
        add("medium", "whois", "Newly registered domain (%d days old)" % w["age_days"])
    st = [x.lower().replace(" ", "") for x in (w.get("status") or [])]
    if st and not any("transferprohibited" in x for x in st):
        add("low", "whois", "No registrar transfer lock in status flags")
    if w.get("created_discrepancy"):
        add("low", "whois", "Creation date differs between RDAP and WHOIS: %s vs %s"
            % (w["created_discrepancy"].get("rdap"), w["created_discrepancy"].get("whois")))

    if d and not d.get("skipped") and not d.get("error"):
        if not d.get("exists", True):
            add("high", "dns", "Domain does not exist (NXDOMAIN)")
        recs = d.get("records", {})
        nsn = len(d.get("zone", {}).get("NS") or recs.get("NS") or [])
        if 0 < nsn < 2:
            add("medium", "dns", "Only one nameserver published")
        if not recs.get("CAA"):
            add("low", "dns", "No CAA records (any CA may issue certificates)")
        if not d.get("dnssec", {}).get("signed"):
            add("low", "dns", "DNSSEC not enabled (no DS record at parent)")
        if d.get("wildcard"):
            add("info", "dns", "Wildcard DNS is configured")
        if recs.get("A") and not recs.get("AAAA"):
            add("info", "dns", "No IPv6 (AAAA) records")

    if s and not s.get("skipped"):
        if s.get("error") and "tls_version" not in s:
            add("info", "tls", s["error"])
        else:
            if s.get("expired"):
                add("high", "tls", "Certificate has expired")
            elif (s.get("days_left") or 999) < 14:
                add("high", "tls", "Certificate expires in %d days" % s["days_left"])
            elif (s.get("days_left") or 999) < 30:
                add("medium", "tls", "Certificate expires in %d days" % s["days_left"])
            if not s.get("verified"):
                add("high", "tls", "Certificate failed verification: %s" % s.get("verify_error"))
            if s.get("hostname_match") is False:
                add("high", "tls", "Certificate does not cover this hostname")
            if s.get("self_signed"):
                add("medium", "tls", "Self-signed certificate")
            if s.get("wildcard"):
                add("info", "tls", "Certificate is a wildcard certificate")
            for v in ("TLSv1.0", "TLSv1.1"):
                if (s.get("protocols") or {}).get(v) == "accepted":
                    add("medium", "tls", "Legacy protocol %s is accepted" % v)
            if (s.get("protocols") or {}).get("TLSv1.3") == "rejected":
                add("low", "tls", "TLS 1.3 not supported")

    if h and not h.get("skipped"):
        hs = h.get("https", {})
        if hs.get("error"):
            add("medium" if not (h.get("http") or {}).get("error") else "info",
                "http", "HTTPS unreachable: %s" % hs["error"])
        else:
            if hs.get("insecure_tls_used"):
                add("medium", "http",
                    "HTTPS only reachable with certificate validation disabled")
            sec = hs.get("security", {})
            hdr = sec.get("headers", {})
            if not hdr.get("strict-transport-security"):
                add("medium", "http", "HSTS header missing")
            if not hdr.get("content-security-policy"):
                add("low", "http", "Content-Security-Policy missing")
            for iss in sec.get("issues", []):
                add("low", "http", iss)
            if not hdr.get("referrer-policy"):
                add("info", "http", "Referrer-Policy missing")
            hd = hs.get("headers", {})
            if re.search(r"/\d", hd.get("server", "")):
                add("low", "http", "Server header discloses version: %s" % hd["server"])
            if hd.get("x-powered-by"):
                add("low", "http", "X-Powered-By discloses stack: %s" % hd["x-powered-by"])
            bad = [c["name"] for c in (hs.get("cookies") or [])
                   if not c["secure"] or not c["httponly"]]
            if bad:
                add("low", "http", "Cookies missing Secure/HttpOnly: %s" % ", ".join(bad[:6]))
        if h.get("http_redirects_to_https") is False and not hs.get("error"):
            add("medium", "http", "Plain HTTP does not redirect to HTTPS")

    if e and not e.get("skipped") and not e.get("error"):
        has_mx = bool(e.get("mx")) and not e.get("null_mx")
        sp = e.get("spf", {})
        if not sp.get("present"):
            add("medium" if has_mx else "low", "email", "No SPF record")
        else:
            if sp.get("multiple"):
                add("high", "email", "Multiple SPF records (SPF evaluates to permerror)")
            pol = (sp.get("policy") or "").lower()
            if pol == "+all":
                add("high", "email", "SPF ends in +all (anyone can send as this domain)")
            elif pol in ("?all", ""):
                add("medium", "email", "SPF has no enforcing 'all' mechanism")
            if sp.get("lookups_exceeded"):
                add("medium", "email", "SPF needs %d DNS lookups (limit is 10)" % sp["lookups"])
        dm = e.get("dmarc", {})
        if not dm.get("present"):
            add("medium" if has_mx else "low", "email", "No DMARC record")
        else:
            if (dm.get("policy") or "").lower() == "none":
                add("low", "email", "DMARC policy is p=none (monitoring only)")
            if dm.get("pct") not in (None, "100"):
                add("low", "email", "DMARC applies to only %s%% of mail" % dm["pct"])
            if not dm.get("rua"):
                add("info", "email", "DMARC has no aggregate-report address (rua)")
        if has_mx and not (e.get("mta_sts") or {}).get("dns"):
            add("info", "email", "MTA-STS not configured")

    for a in (ip.get("addresses") or []):
        if a.get("private"):
            add("medium", "ip", "DNS points to a non-public address: %s" % a["ip"])
    for x in (ip.get("non_public_addresses") or []):
        add("medium", "ip", "Public DNS points to a non-public address: %s" % x)
    if ip.get("non_public_addresses") and ip.get("addresses"):
        add("high", "ip", "Mixed public and private A records - possible DNS rebinding")

    for r in (sub.get("dangling_candidates") or []):
        add("medium", "subs", "Possible dangling CNAME: %s -> %s (%s) - verify manually"
            % (r["host"], r["cname"], r["takeover_hint"]))

    F.sort(key=lambda x: SEV[x["severity"]])
    return F


# ══════════════════════════════════════════════════════════════ presentation
SEV_WEIGHT = {"high": 25, "medium": 10, "low": 3, "info": 0}


def human_duration(days):
    """Turn a day count into something a person reads faster: '18.9 years'."""
    if days is None:
        return None
    d = abs(int(days))
    sign = "-" if days < 0 else ""
    if d < 1:
        return "today"
    if d < 45:
        return "%s%d days" % (sign, d)
    if d < 365:
        return "%s%d months" % (sign, round(d / 30.44))
    if d < 3650:
        return "%s%.1f years" % (sign, d / 365.25)
    return "%s%.1f decades" % (sign, d / 3652.5)


def date_only(s):
    if not s:
        return None
    m = re.match(r"(\d{4}-\d{2}-\d{2})", str(s))
    return m.group(1) if m else str(s)[:10]


def trim(values, keep=6):
    """Shorten long lists but say how many were dropped - no silent truncation."""
    if not isinstance(values, list):
        return values, None
    return values[:keep], (len(values) - keep if len(values) > keep else 0)


def risk_score(findings, age_days=None):
    score = 100
    for f in findings:
        score -= SEV_WEIGHT.get(f.get("severity"), 0)
    # very new domains are a risk signal on their own
    if age_days is not None and 0 <= age_days < 60:
        score -= 10
    score = max(0, min(100, score))
    band = ("critical" if score < 40 else "poor" if score < 70
            else "fair" if score < 90 else "good")
    return score, band


def build_digest(t, m, findings):
    """Compact, human-readable view. Full raw data stays available via ?view=full."""
    w = m.get("whois") or {}
    d = m.get("dns") or {}
    s = m.get("tls") or {}
    h = m.get("http") or {}
    e = m.get("email") or {}
    ip = m.get("ip") or {}
    sub = m.get("subs") or {}

    reg = w.get("registrar")
    reg_name = reg.get("name") if isinstance(reg, dict) else reg

    recs = d.get("records", {}) or {}
    ipv4 = [x["value"] for x in recs.get("A", []) if is_public_ip(x["value"])]
    ipv6 = [x["value"] for x in recs.get("AAAA", [])]

    first = (ip.get("addresses") or [{}])[0]
    asn = first.get("asn") or {}
    geo = first.get("geo") or {}
    asn_txt = None
    if asn:
        asn_txt = "%s %s" % (", ".join(asn.get("asn") or []), asn.get("name") or "")
        asn_txt = asn_txt.strip()

    https = h.get("https", {}) or {}
    sec = https.get("security", {}) or {}
    protos = [k for k, v in (s.get("protocols") or {}).items() if v == "accepted"]
    tech = https.get("technologies") or []
    tech, _ = trim([t for t in tech if not t.startswith("server:")], 8)

    mx = e.get("mx") or []
    subs = sub.get("subdomains") or []
    hosts = [x["host"] for x in subs]
    hosts, more_hosts = trim(hosts, 8)

    dangling = sub.get("dangling_candidates") or []
    score, band = risk_score(findings, w.get("age_days"))

    return {
        "domain": t["registrable"],
        "host": t["host"],
        "risk": {
            "score": score,
            "band": band,
            "counts": {k: sum(1 for f in findings if f["severity"] == k) for k in SEV},
            "total": len(findings),
        },
        "registration": None if w.get("skipped") else {
            "created": date_only(w.get("created_iso") or w.get("created")),
            "age": human_duration(w.get("age_days")),
            "expires": date_only(w.get("expires_iso") or w.get("expires")),
            "expires_in": human_duration(w.get("days_to_expiry")),
            "registrar": reg_name,
            "status": w.get("status") or [],
            "nameservers": (w.get("nameservers") or [])[:4],
            "nameservers_more": max(0, len(w.get("nameservers") or []) - 4),
            "source": w.get("created_source"),
            "verified": w.get("created_verified"),
        },
        "infrastructure": {
            "ipv4": ipv4[:4],
            "ipv6_count": len(ipv6),
            "asn": asn_txt,
            "asn_prefix": asn.get("prefix"),
            "hosting": first.get("hosting_hint"),
            "location": ", ".join(x for x in [geo.get("city"), geo.get("country")] if x) or None,
            "ptr": (first.get("ptr") or [None])[0],
            "dnssec": (d.get("dnssec") or {}).get("signed"),
            "caa": [x["value"] for x in recs.get("CAA", [])][:4],
            "wildcard_dns": d.get("wildcard"),
        },
        "tls": None if s.get("skipped") else {
            "issuer": s.get("issuer_org") or s.get("issuer_cn"),
            "valid_to": date_only(s.get("valid_to")),
            "days_left": s.get("days_left"),
            "protocols": protos,
            "legacy_protocols": [k for k in ("TLSv1.0", "TLSv1.1")
                                 if (s.get("protocols") or {}).get(k) == "accepted"],
            "cipher": (s.get("cipher") or {}).get("name"),
            "alpn": s.get("alpn"),
            "verified": s.get("verified"),
            "self_signed": s.get("self_signed"),
            "wildcard_cert": s.get("wildcard"),
            "san_count": s.get("san_count"),
        },
        "web": None if h.get("skipped") else {
            "status": https.get("status"),
            "title": https.get("title"),
            "server": (https.get("headers") or {}).get("server"),
            "redirects": len(https.get("chain") or []),
            "http_redirects_to_https": h.get("http_redirects_to_https"),
            "insecure_tls_used": https.get("insecure_tls_used"),
            "technologies": tech,
            "security_score": sec.get("score"),
            "security_issues": (sec.get("issues") or [])[:6],
            "cookies_weak": [c["name"] for c in (https.get("cookies") or [])
                             if not c["secure"] or not c["httponly"]][:6],
            "security_txt": (h.get("files") or {}).get("security_txt"),
            "robots_txt": (h.get("files") or {}).get("robots_txt"),
        },
        "email_security": None if e.get("skipped") else {
            "mx_count": len(mx),
            "mx_provider": e.get("mx_provider"),
            "null_mx": e.get("null_mx"),
            "spf_present": (e.get("spf") or {}).get("present"),
            "spf_policy": (e.get("spf") or {}).get("policy"),
            "spf_lookups": (e.get("spf") or {}).get("lookups"),
            "dmarc_present": (e.get("dmarc") or {}).get("present"),
            "dmarc_policy": (e.get("dmarc") or {}).get("policy"),
            "dkim_selectors": len(e.get("dkim_selectors_found") or []),
            "mta_sts": bool((e.get("mta_sts") or {}).get("dns")),
            "tls_rpt": bool(e.get("tls_rpt")),
            "bimi": bool(e.get("bimi")),
        },
        "subdomains": None if sub.get("skipped") else {
            "total": sub.get("total"),
            "resolved_checked": sub.get("resolved_checked"),
            "sources": {k: v for k, v in (sub.get("sources") or {}).items()},
            "sample": hosts,
            "sample_omitted": more_hosts or 0,
            "dangling_cname": [{"host": x["host"], "target": x.get("cname"),
                                "risk": x.get("takeover_hint")}
                               for x in dangling[:5]],
        },
        "findings": findings,
        "errors": {k: v.get("error") for k, v in m.items()
                   if isinstance(v, dict) and v.get("error")},
        "_full": "append &view=full for raw module data",
    }


SEV_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def render_report(t, digest):
    """Plain-text report - readable without a JSON viewer."""
    L = []
    add = L.append
    r = digest["risk"]
    add("=" * 68)
    add("  DOMAIN INTELLIGENCE REPORT")
    add("  %s" % digest["domain"])
    add("=" * 68)
    add("")
    add("  RISK  %d/100 (%s)   %d high  %d medium  %d low  %d info"
        % (r["score"], r["band"].upper(), r["counts"]["high"], r["counts"]["medium"],
           r["counts"]["low"], r["counts"]["info"]))
    add("")

    def section(title, rows):
        rows = [(k, v) for k, v in rows if v not in (None, "", [], {})]
        if not rows:
            return
        add("-- %s " % title + "-" * max(0, 64 - len(title)))
        for k, v in rows:
            add("  %-18s %s" % (k, v))
        add("")

    g = digest.get("registration") or {}
    section("REGISTRATION", [
        ("created", g.get("created")),
        ("age", g.get("age")),
        ("expires", g.get("expires")),
        ("expires in", g.get("expires_in")),
        ("registrar", g.get("registrar")),
        ("status", ", ".join(g.get("status") or []) or None),
        ("nameservers", ", ".join(g.get("nameservers") or []) or None),
        ("date source", "%s (verified=%s)" % (g.get("source"), g.get("verified"))
            if g.get("source") else None),
    ])

    i = digest.get("infrastructure") or {}
    section("INFRASTRUCTURE", [
        ("ipv4", ", ".join(i.get("ipv4") or []) or None),
        ("asn", i.get("asn")),
        ("asn prefix", i.get("asn_prefix")),
        ("hosting", i.get("hosting")),
        ("location", i.get("location")),
        ("reverse dns", i.get("ptr")),
        ("dnssec", "signed" if i.get("dnssec") else "not signed"),
        ("wildcard dns", i.get("wildcard_dns")),
        ("caa", ", ".join(i.get("caa") or []) or None),
    ])

    s = digest.get("tls") or {}
    section("TLS CERTIFICATE", [
        ("issuer", s.get("issuer")),
        ("valid to", "%s (%s days left)" % (s.get("valid_to"), s.get("days_left"))
            if s.get("valid_to") else None),
        ("protocols", ", ".join(s.get("protocols") or []) or None),
        ("legacy accepted", ", ".join(s.get("legacy_protocols") or []) or None),
        ("cipher", s.get("cipher")),
        ("alpn", s.get("alpn")),
        ("verified", s.get("verified")),
        ("self signed", s.get("self_signed")),
        ("wildcard", s.get("wildcard_cert")),
        ("sans", s.get("san_count")),
    ])

    w = digest.get("web") or {}
    section("WEB", [
        ("status", w.get("status")),
        ("title", w.get("title")),
        ("server", w.get("server")),
        ("redirects", w.get("redirects")),
        ("http->https", w.get("http_redirects_to_https")),
        ("insecure tls", w.get("insecure_tls_used")),
        ("technologies", ", ".join(w.get("technologies") or []) or None),
        ("security score", "%s/100" % w.get("security_score") if w.get("security_score") is not None else None),
        ("header issues", "; ".join(w.get("security_issues") or []) or None),
        ("weak cookies", ", ".join(w.get("cookies_weak") or []) or None),
        ("security.txt", w.get("security_txt")),
        ("robots.txt", w.get("robots_txt")),
    ])

    e = digest.get("email_security") or {}
    section("EMAIL SECURITY", [
        ("mx provider", ", ".join(e.get("mx_provider") or []) or None),
        ("mx records", e.get("mx_count")),
        ("spf", ("%s (%s lookups)" % (e.get("spf_policy"), e.get("spf_lookups"))
                 if e.get("spf_present") else "absent")),
        ("dmarc", e.get("dmarc_policy") if e.get("dmarc_present") else "absent"),
        ("dkim selectors", e.get("dkim_selectors")),
        ("mta-sts", e.get("mta_sts")),
        ("tls-rpt", e.get("tls_rpt")),
        ("bimi", e.get("bimi")),
    ])

    sd = digest.get("subdomains") or {}
    section("SUBDOMAINS", [
        ("total found", sd.get("total")),
        ("resolved", sd.get("resolved_checked")),
        ("sources", ", ".join("%s=%s" % (k, v) for k, v in (sd.get("sources") or {}).items()) or None),
        ("dangling cname", len(sd.get("dangling_cname") or []) or None),
    ])
    if sd.get("sample"):
        add("  sample:")
        for hst in sd["sample"]:
            add("    - %s" % hst)
        if sd.get("sample_omitted"):
            add("    ... and %d more" % sd["sample_omitted"])
        add("")

    if digest.get("findings"):
        add("-- FINDINGS " + "-" * 56)
        for f in digest["findings"]:
            add("  [%-6s] %-6s %s" % (SEV_LABEL.get(f["severity"], "?"),
                                       f["module"], f["message"]))
        add("")

    if digest.get("errors"):
        add("-- ERRORS " + "-" * 58)
        for k, v in digest["errors"].items():
            add("  %-10s %s" % (k, str(v)[:100]))
        add("")

    add("=" * 68)
    return "\n".join(L)

MODFN = {"dns": mod_dns, "tls": mod_tls, "http": mod_http,
         "ip": mod_ip, "email": mod_email, "subs": mod_subs}


def log_monitor(endpoint, status, elapsed, error=None):
    if not MONITOR_URL:
        return
    try:
        rq.post(f"{MONITOR_URL}/api/log", json={
            "api": "DomainIntel", "endpoint": endpoint, "status_code": status,
            "response_time": elapsed, "error": error}, timeout=4)
    except Exception:
        pass


def run_modules(t, mods):
    """Modules fan out in parallel; whois is serial because it shares WHOIS sockets."""
    mods = [m for m in mods if m in ALL_MODULES]
    out = {}
    other = [m for m in mods if m != "whois"]
    if other:
        with cf.ThreadPoolExecutor(min(7, len(other))) as ex:
            futs = {m: ex.submit(MODFN[m], t) for m in other}
            for m, f in futs.items():
                try:
                    out[m] = f.result()
                except Exception as e:
                    out[m] = {"error": short_err(e)}
    if "whois" in mods:
        out["whois"] = mod_whois(t, cross_check=CROSS_CHECK)
    return out


@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = CORS_ALLOW
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Api-Key"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


def ok(pd):
    return jsonify({"rs": "S", "rc": "OK", "rd": "Success", "pd": pd}), 200


def err(rc, rd, status=400):
    return jsonify({"rs": "E", "rc": rc, "rd": rd, "pd": None}), status


def target_arg():
    raw = request.args.get("domain") or request.args.get("q") or ""
    return parse_target(raw)


def wanted_modules():
    raw = request.args.get("modules")
    if not raw:
        return list(ALL_MODULES)
    mods = [m.strip().lower() for m in raw.split(",") if m.strip()]
    bad = [m for m in mods if m not in ALL_MODULES]
    if bad:
        raise ValueError("unknown module(s): %s (valid: %s)"
                         % (", ".join(bad), ", ".join(ALL_MODULES)))
    return mods


@app.route("/", methods=["GET", "OPTIONS"])
def index():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "service": "Domain Intelligence API",
        "version": "3.0.0",
        "modules": ALL_MODULES,
        "endpoints": {
            "report": "GET /api/domain/report?domain=<domain>   plain-text report",
            "info": "GET /api/domain/info?domain=<domain>[&view=digest|full]",
            "findings": "GET /api/domain/findings?domain=<domain>",
            "whois": "GET /api/domain/whois?domain=<domain>",
            "dns": "GET /api/domain/dns?domain=<domain>",
            "subs": "GET /api/domain/subs?domain=<domain>",
            "ssl": "GET /api/domain/ssl?domain=<domain>",
            "email": "GET /api/domain/email?domain=<domain>",
            "ip": "GET /api/domain/ip?domain=<domain>",
            "http": "GET /api/domain/http?domain=<domain>",
            "health": "GET /api/health",
        },
        "notes": {
            "view": "/info returns a compact digest by default; use &view=full for raw data",
            "report": "/report returns a formatted plain-text report - easiest to read",
            "modules": "add &modules=dns,whois,tls to scan only what you need",
            "cross_check": "append &cross_check=0 to skip the second WHOIS lookup",
            "passive": "no crawling and no brute force; one DNS/TLS/HTTP request per target",
        },
    }), 200


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "domain-intel"}), 200


@app.route("/<path:_p>", methods=["GET", "POST", "OPTIONS"])
def fallback(_p):
    if request.method == "OPTIONS":
        return "", 204
    return err("NOT_FOUND", "Endpoint not found", 404)


@app.route("/api/domain/info", methods=["GET", "OPTIONS"])
def r_info():
    global CROSS_CHECK
    CROSS_CHECK = request.args.get("cross_check", "1") not in ("0", "false", "no")
    t0 = time.time()
    if request.method == "OPTIONS":
        return "", 204
    try:
        t = target_arg()
        mods = wanted_modules()
    except ValueError as ex:
        log_monitor("/api/domain/info", 400, time.time() - t0, str(ex))
        return err("INVALID_INPUT", str(ex))
    view = request.args.get("view", "digest").lower()
    m = run_modules(t, mods)
    findings = analyze(m)
    elapsed = round((time.time() - t0) * 1000)

    if view == "full":
        counts = {k: sum(1 for f in findings if f["severity"] == k) for k in SEV}
        pd = {"domain": t["registrable"], "host": t["host"], "unicode": t["unicode"],
              "is_ip": t["is_ip"], "view": "full", "modules": mods,
              "summary": {"finding_counts": counts, "total_findings": len(findings),
                          "worst_severity": findings[0]["severity"] if findings else None},
              "findings": findings, "data": m}
    else:
        pd = build_digest(t, m, findings)
        pd["modules"] = mods

    log_monitor("/api/domain/info", 200, elapsed)
    resp = jsonify({"rs": "S", "rc": "OK", "rd": "Success", "pd": pd})
    resp.headers["X-Elapsed-Ms"] = str(elapsed)
    return resp, 200


@app.route("/api/domain/report", methods=["GET", "OPTIONS"])
def r_report():
    global CROSS_CHECK
    CROSS_CHECK = request.args.get("cross_check", "1") not in ("0", "false", "no")
    if request.method == "OPTIONS":
        return "", 204
    try:
        t = target_arg()
        mods = wanted_modules()
    except ValueError as ex:
        return err("INVALID_INPUT", str(ex))
    m = run_modules(t, mods)
    findings = analyze(m)
    text = render_report(t, build_digest(t, m, findings))
    if request.args.get("format", "text").lower() == "json":
        return ok(build_digest(t, m, findings))
    return Response(text, mimetype="text/plain; charset=utf-8")


@app.route("/api/domain/findings", methods=["GET", "OPTIONS"])
def r_findings():
    global CROSS_CHECK
    CROSS_CHECK = request.args.get("cross_check", "1") not in ("0", "false", "no")
    if request.method == "OPTIONS":
        return "", 204
    try:
        t = target_arg()
        mods = wanted_modules()
    except ValueError as ex:
        return err("INVALID_INPUT", str(ex))
    m = run_modules(t, mods)
    f = analyze(m)
    counts = {k: sum(1 for x in f if x["severity"] == k) for k in SEV}
    score, band = risk_score(f, (m.get("whois") or {}).get("age_days"))
    return ok({"domain": t["registrable"], "modules": mods, "total": len(f),
               "risk_score": score, "risk_band": band, "counts": counts, "findings": f})


def _single(module, fn):
    endpoint = "view_" + module

    def view():
        global CROSS_CHECK
        CROSS_CHECK = request.args.get("cross_check", "1") not in ("0", "false", "no")
        if request.method == "OPTIONS":
            return "", 204
        try:
            t = target_arg()
        except ValueError as ex:
            return err("INVALID_INPUT", str(ex))
        try:
            return ok({"domain": t["registrable"], module: fn(t)})
        except Exception as ex:
            return err("LOOKUP_FAILED", short_err(ex), 502)

    app.add_url_rule("/api/domain/" + module, endpoint, view, methods=["GET", "OPTIONS"])
    return view


_single("dns", lambda t: mod_dns(t))
_single("subs", lambda t: mod_subs(t))
_single("ssl", lambda t: mod_tls(t))
_single("tls", lambda t: mod_tls(t))
_single("email", lambda t: mod_email(t))
_single("ip", lambda t: mod_ip(t))
_single("http", lambda t: mod_http(t))


@app.route("/api/domain/whois", methods=["GET", "OPTIONS"])
def r_whois():
    global CROSS_CHECK
    CROSS_CHECK = request.args.get("cross_check", "1") not in ("0", "false", "no")
    if request.method == "OPTIONS":
        return "", 204
    try:
        t = target_arg()
    except ValueError as ex:
        return err("INVALID_INPUT", str(ex))
    reg = mod_whois(t, cross_check=CROSS_CHECK)
    if reg.get("error") and not reg.get("created"):
        return err("REGISTRY_UNAVAILABLE", reg["error"], 502)
    return ok({"domain": t["registrable"], "whois": reg})


CROSS_CHECK = True

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5060")), debug=False)



