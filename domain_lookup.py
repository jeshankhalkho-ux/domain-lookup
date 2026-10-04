#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
domain_lookup.py - all-in-one domain intelligence lookup (passive recon)

Modules
  dns     A/AAAA/CNAME/MX/NS/TXT/SOA/CAA, NS glue IPs, DNSSEC (DS/DNSKEY), wildcard-DNS test
  whois   RDAP via the IANA bootstrap (structured, official), raw WHOIS (port 43) fallback,
          domain age / days-to-expiry, registrar, status flags, abuse contact
  ssl     TLS handshake, certificate details, SANs, expiry, hostname match,
          protocol support (TLS 1.0-1.3), cipher, ALPN (h2), SHA-256/SHA-1 fingerprints
  http    http/https redirect chains, response headers, security-header audit,
          cookie flags, page title, technology / CDN hints, robots.txt, security.txt
  ip      per-IP reverse DNS, ASN + prefix (Team Cymru over DNS), geolocation, hosting hint
  email   MX provider, SPF (recursive lookup count), DMARC, DKIM (common selectors),
          MTA-STS, TLS-RPT, BIMI
  subs    passive subdomains (crt.sh, HackerTarget, AlienVault OTX), resolution,
          dangling-CNAME hints, optional DNS brute force (--brute)

Install (everything is optional - the script runs on the standard library alone):
  pip install dnspython tldextract     # recommended: native DNS + exact public-suffix handling

Examples
  python domain_lookup.py example.com
  python domain_lookup.py https://www.example.co.uk/path -m dns,whois,ssl
  python domain_lookup.py example.com --brute --wordlist words.txt
  python domain_lookup.py -l domains.txt --json -o results.json
  python domain_lookup.py 1.1.1.1                       # IP targets: rDNS, ASN, geo, TLS, HTTP

Only run this against domains you own or are authorised to assess. Everything here is
passive or ordinary client traffic (DNS queries, public APIs, one TLS/HTTP connection);
the optional --brute flag sends one DNS query per wordlist entry.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import html as htmllib
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass
from functools import lru_cache

__version__ = "1.0.0"

try:  # optional: native DNS resolver
    import dns.exception  # type: ignore
    import dns.resolver  # type: ignore

    HAVE_DNSPYTHON = True
except Exception:  # pragma: no cover
    HAVE_DNSPYTHON = False

try:  # optional: exact public-suffix list (bundled snapshot, no network)
    import tldextract  # type: ignore

    _TLD = tldextract.TLDExtract(suffix_list_urls=())
    HAVE_TLDEXTRACT = True
except Exception:  # pragma: no cover
    HAVE_TLDEXTRACT = False

CFG = {
    "timeout": 8.0,
    "resolver": None,
    "doh": False,
    "ua": "Mozilla/5.0 (compatible; domain-lookup/%s)" % __version__,
}

ALL_MODULES = ["dns", "whois", "ssl", "http", "ip", "email", "subs"]


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
class Style:
    on = False

    @classmethod
    def c(cls, code, s):
        return "\033[%sm%s\033[0m" % (code, s) if cls.on else str(s)


bold = lambda s: Style.c("1", s)
dim = lambda s: Style.c("2", s)
red = lambda s: Style.c("31", s)
green = lambda s: Style.c("32", s)
yellow = lambda s: Style.c("33", s)
cyan = lambda s: Style.c("36", s)


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def parse_dt(s):
    """Parse the many date formats seen in RDAP / WHOIS into an aware UTC datetime."""
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
        for fmt in (
            "%Y-%m-%d %H:%M:%S", "%Y.%m.%d %H:%M:%S", "%d-%b-%Y %H:%M:%S", "%d-%b-%Y",
            "%Y-%m-%d", "%Y.%m.%d", "%Y/%m/%d", "%d/%m/%Y", "%b %d %Y", "%d.%m.%Y",
        ):
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
    return s.splitlines()[0][:200] if s else type(e).__name__


class FetchError(Exception):
    def __init__(self, msg, status=None, cert_error=False):
        super().__init__(msg)
        self.status = status
        self.cert_error = cert_error


# ----------------------------------------------------------------------------
# Target parsing
# ----------------------------------------------------------------------------
MULTI_SUFFIXES = set("""
co.uk org.uk me.uk ltd.uk plc.uk ac.uk gov.uk net.uk sch.uk
com.au net.au org.au edu.au gov.au co.nz org.nz net.nz co.za org.za
com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn com.hk com.sg com.my com.tw com.tr
com.mx com.ar com.co com.pk com.bd com.np com.lk com.ng com.eg com.sa com.ua
co.jp ne.jp or.jp ac.jp co.kr or.kr co.id or.id co.th in.th co.il org.il co.ke
co.in net.in org.in firm.in gen.in ind.in ac.in edu.in res.in gov.in nic.in mil.in
""".split())

LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass
class Target:
    raw: str
    host: str          # ASCII / punycode form used for all queries
    unicode: str       # display form
    registrable: str   # e.g. example.co.uk
    is_ip: bool = False


def registrable_domain(host):
    if HAVE_TLDEXTRACT:
        ext = _TLD(host)
        if ext.domain and ext.suffix:
            return "%s.%s" % (ext.domain, ext.suffix)
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
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)       # scheme
    s = re.split(r"[/?#]", s, maxsplit=1)[0]                # path / query
    s = s.rsplit("@", 1)[-1]                                # userinfo or e-mail address
    if s.startswith("["):                                   # [v6]:port
        host = s[1:s.find("]")] if "]" in s else s[1:]
    elif s.count(":") == 1:                                 # host:port
        host = s.split(":")[0]
    else:
        host = s
    host = host.strip().rstrip(".").lower()
    try:
        ip = str(ipaddress.ip_address(host))
        return Target(raw, ip, ip, ip, True)
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid internationalised domain name: %r" % raw)
    labels = ascii_host.split(".")
    if (len(ascii_host) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or not all(LABEL_RE.match(l) for l in labels)):
        raise ValueError("not a valid domain name: %r" % raw)
    try:
        uni = ascii_host.encode("ascii").decode("idna")
    except UnicodeError:
        uni = ascii_host
    return Target(raw, ascii_host, uni, registrable_domain(ascii_host))


# ----------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ----------------------------------------------------------------------------
def _ctx(verify=True):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http_fetch(url, timeout=None, max_bytes=262144, verify=True, redirects=False, headers=None):
    timeout = timeout or CFG["timeout"]
    handlers = [urllib.request.HTTPSHandler(context=_ctx(verify))]
    if not redirects:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=dict({"User-Agent": CFG["ua"], "Accept": "*/*"}, **(headers or {})))
    t0 = time.perf_counter()
    try:
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e
        ms = round((time.perf_counter() - t0) * 1000)
        body = resp.read(max_bytes)
        status = getattr(resp, "status", None) or resp.code
        hdrs = list(resp.headers.items())
        final = resp.geturl()
        resp.close()
    except urllib.error.URLError as e:
        raise FetchError(short_err(e), cert_error=isinstance(e.reason, ssl.SSLCertVerificationError)) from None
    except ssl.SSLCertVerificationError as e:
        raise FetchError(short_err(e), cert_error=True) from None
    except (OSError, http.client.HTTPException, ValueError) as e:
        raise FetchError(short_err(e)) from None
    return {"url": final, "status": status, "headers": hdrs, "body": body, "ms": ms}


def http_json(url, headers=None, timeout=None, max_bytes=8_000_000):
    r = http_fetch(url, timeout=timeout, redirects=True, headers=headers, max_bytes=max_bytes)
    if r["status"] >= 400:
        raise FetchError("HTTP %s" % r["status"], status=r["status"])
    try:
        return json.loads(r["body"].decode("utf-8", "replace"))
    except ValueError:
        raise FetchError("invalid JSON response") from None


# ----------------------------------------------------------------------------
# DNS (dnspython when installed, DNS-over-HTTPS otherwise)
# ----------------------------------------------------------------------------
RTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
             "AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48, "CAA": 257}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DOH_ENDPOINTS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
_NAME_TYPES = {"NS", "CNAME", "PTR", "MX", "SOA", "SRV"}


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
    if rtype in _NAME_TYPES:
        return re.sub(r"(?<=[A-Za-z0-9])\.(?=\s|$)", "", v)
    if rtype == "CAA" and v.startswith("\\#"):
        return _decode_caa(v)
    return v


def _dns_native(name, rtype):
    out = {"records": [], "status": "NOERROR", "error": None, "via": "dnspython"}
    try:
        res = dns.resolver.Resolver()
        if CFG["resolver"]:
            res.nameservers = [CFG["resolver"]]
        res.lifetime = res.timeout = CFG["timeout"]
    except Exception:
        return None  # no usable resolv.conf -> caller falls back to DoH
    try:
        ans = res.resolve(name, rtype, raise_on_no_answer=False)
        if ans.rrset is not None:
            for r in ans.rrset:
                out["records"].append({"value": _norm_value(rtype, r.to_text()), "ttl": ans.rrset.ttl})
    except dns.resolver.NXDOMAIN:
        out["status"] = "NXDOMAIN"
    except dns.resolver.NoNameservers:
        out["status"] = "SERVFAIL"
    except dns.exception.Timeout:
        out["status"], out["error"] = "TIMEOUT", "query timed out"
    except Exception as e:
        out["status"], out["error"] = "ERROR", short_err(e)
    return out


def _dns_doh(name, rtype):
    last = None
    for ep in DOH_ENDPOINTS:
        url = "%s?%s" % (ep, urllib.parse.urlencode({"name": name, "type": rtype}))
        try:
            data = http_json(url, headers={"Accept": "application/dns-json"})
        except FetchError as e:
            last = str(e)
            continue
        recs = []
        for a in data.get("Answer") or []:
            if a.get("type") == RTYPE_NUM[rtype]:
                recs.append({"value": _norm_value(rtype, a.get("data", "")), "ttl": a.get("TTL")})
        st = data.get("Status", 0)
        return {"records": recs, "status": RCODES.get(st, str(st)), "error": None, "via": "doh"}
    return {"records": [], "status": "ERROR", "error": last, "via": "doh"}


@lru_cache(maxsize=8192)
def dns_query(name, rtype):
    rtype = rtype.upper()
    if HAVE_DNSPYTHON and not CFG["doh"]:
        r = _dns_native(name, rtype)
        if r is not None:
            return r
    return _dns_doh(name, rtype)


def dns_values(name, rtype):
    return [r["value"] for r in dns_query(name, rtype)["records"]]


def rand_label(n=14):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ----------------------------------------------------------------------------
# Module: DNS
# ----------------------------------------------------------------------------
def _mx_sort(v):
    try:
        return (int(v.split()[0]), v)
    except (ValueError, IndexError):
        return (0, v)


def mod_dns(t, opts):
    if t.is_ip:
        return {"skipped": "IP target"}
    host, reg = t.host, t.registrable
    types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    out = {"records": {}, "status": {}, "errors": {}, "backend": None}
    with cf.ThreadPoolExecutor(8) as ex:
        futs = {ty: ex.submit(dns_query, host, ty) for ty in types}
        zone_f = {ty: ex.submit(dns_query, reg, ty) for ty in ("NS", "SOA")} if reg != host else {}
        ds_f, key_f = ex.submit(dns_query, reg, "DS"), ex.submit(dns_query, reg, "DNSKEY")
        wild_f = ex.submit(dns_query, "%s.%s" % (rand_label(), reg), "A")
        for ty, f in futs.items():
            r = f.result()
            out["records"][ty] = r["records"]
            out["status"][ty] = r["status"]
            out["backend"] = r.get("via")
            if r.get("error"):
                out["errors"][ty] = r["error"]
        out["zone"] = {ty: f.result()["records"] for ty, f in zone_f.items()}
        ds, key, wild = ds_f.result(), key_f.result(), wild_f.result()
    out["records"]["MX"].sort(key=lambda r: _mx_sort(r["value"]))
    for ty in ("A", "AAAA", "NS", "TXT", "CAA"):
        out["records"][ty].sort(key=lambda r: r["value"])
    out["exists"] = out["status"].get("A") != "NXDOMAIN"
    out["dnssec"] = {"ds": [r["value"] for r in ds["records"]], "dnskey": len(key["records"]),
                     "signed": bool(ds["records"])}
    out["wildcard"] = bool(wild["records"])
    # glue / NS addresses
    ns_names = [r["value"].lower() for r in (out["zone"].get("NS") or out["records"]["NS"])]
    with cf.ThreadPoolExecutor(6) as ex:
        res = list(ex.map(lambda n: (n, dns_values(n, "A") + dns_values(n, "AAAA")), ns_names[:12]))
    out["ns_addresses"] = dict(res)
    if all(s in ("ERROR", "TIMEOUT") for s in out["status"].values()):
        out["error"] = "DNS resolution failed: %s" % (next(iter(out["errors"].values()), "no response"))
    return out


# ----------------------------------------------------------------------------
# Module: WHOIS / RDAP
# ----------------------------------------------------------------------------
@lru_cache(maxsize=1)
def _rdap_bootstrap():
    return http_json("https://data.iana.org/rdap/dns.json").get("services", [])


def rdap_base(domain):
    tld = domain.rsplit(".", 1)[-1].lower()
    try:
        for tlds, urls in _rdap_bootstrap():
            if tld in tlds and urls:
                return sorted(urls, key=lambda u: not u.startswith("https"))[0].rstrip("/") + "/"
    except FetchError:
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
                "email": card.get("email"), "phone": card.get("tel"), "handle": e.get("handle")}
        for pid in e.get("publicIds", []) or []:
            if "iana" in str(pid.get("type", "")).lower():
                info["iana_id"] = pid.get("identifier")
        for role in e.get("roles", []):
            acc.setdefault(role, info)
        _walk_entities(e.get("entities"), acc)


def parse_rdap(d):
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) or []}
    ents = {}
    _walk_entities(d.get("entities"), ents)
    out = {
        "domain": d.get("ldhName"), "unicode": d.get("unicodeName"), "handle": d.get("handle"),
        "status": d.get("status", []) or [],
        "created": ev.get("registration"), "updated": ev.get("last changed"),
        "expires": ev.get("expiration"), "transferred": ev.get("transfer"),
        "nameservers": sorted({(n.get("ldhName") or "").lower() for n in d.get("nameservers", []) or [] if n.get("ldhName")}),
        "dnssec_signed": (d.get("secureDNS") or {}).get("delegationSigned"),
        "registrar": ents.get("registrar"), "registrant": ents.get("registrant"),
        "abuse": ents.get("abuse"), "technical": ents.get("technical"), "admin": ents.get("administrative"),
    }
    return out


_WHOIS_KEYS = {
    "registrar": ["Registrar", "Sponsoring Registrar", "registrar name"],
    "created": ["Creation Date", "Created On", "created", "Registered on", "Domain Registration Date", "Registration Time"],
    "updated": ["Updated Date", "Last Updated On", "last-update", "Last Modified", "modified", "Last Update"],
    "expires": ["Registry Expiry Date", "Registrar Registration Expiration Date", "Expiry Date", "Expiration Date",
                "paid-till", "Expires On", "Expiration Time", "renewal date"],
    "dnssec": ["DNSSEC", "dnssec"],
    "registrant": ["Registrant Organization", "Registrant Name", "Registrant"],
    "abuse_email": ["Registrar Abuse Contact Email"],
}


def whois_query(server, query, timeout):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 400_000:
                break
    return data.decode("utf-8", "replace")


def whois_raw(domain, timeout):
    tld = domain.rsplit(".", 1)[-1]
    iana = whois_query("whois.iana.org", tld, timeout)
    m = re.search(r"^\s*whois:\s*(\S+)", iana, re.M | re.I)
    if not m:
        raise FetchError("no WHOIS server known for .%s" % tld)
    server = m.group(1)
    text = whois_query(server, domain, timeout)
    m2 = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.I)
    if m2 and m2.group(1).lower().rstrip(".") != server.lower():
        try:
            more = whois_query(m2.group(1), domain, timeout)
            if len(more) > 200:
                text, server = more, m2.group(1)
        except OSError:
            pass
    return server, text


def parse_whois_text(text):
    out = {}
    for field, keys in _WHOIS_KEYS.items():
        for k in keys:
            m = re.search(r"^\s*%s\s*:\s*(.+?)\s*$" % re.escape(k), text, re.M | re.I)
            if m:
                out[field] = m.group(1)
                break
    out["status"] = uniq(s.split()[0] for s in re.findall(r"^\s*(?:Domain )?Status\s*:\s*(.+?)\s*$", text, re.M | re.I))
    out["nameservers"] = sorted({n.split()[0].lower().rstrip(".") for n in
                                 re.findall(r"^\s*(?:Name Server|nserver)\s*:\s*(.+?)\s*$", text, re.M | re.I)})
    return out


def _derive_dates(out):
    c, e, u = parse_dt(out.get("created")), parse_dt(out.get("expires")), parse_dt(out.get("updated"))
    now = now_utc()
    out["created_iso"], out["expires_iso"], out["updated_iso"] = iso(c), iso(e), iso(u)
    out["age_days"] = (now - c).days if c else None
    out["days_to_expiry"] = (e - now).days if e else None


def mod_whois(t, opts):
    if t.is_ip:
        return {"skipped": "IP target - use an RDAP/WHOIS client for netblock data"}
    out = {"queried": None, "source": None, "errors": []}
    for cand in uniq([t.registrable, t.host]):
        try:
            data = http_json(rdap_base(cand) + "domain/" + cand, headers={"Accept": "application/rdap+json"})
            out.update(parse_rdap(data))
            out["source"], out["queried"] = "rdap", cand
            break
        except FetchError as e:
            out["errors"].append("RDAP %s: %s" % (cand, e))
    if not out["source"]:
        try:
            server, text = whois_raw(t.registrable, CFG["timeout"])
            out.update(parse_whois_text(text))
            out["source"], out["queried"], out["whois_server"] = "whois", t.registrable, server
            if re.search(r"no match|not found|no data found|status:\s*free|available", text[:600], re.I) and not out.get("created"):
                out["registered"] = False
            if getattr(opts, "raw_whois", False):
                out["raw"] = text
        except (OSError, FetchError) as e:
            out["errors"].append("WHOIS: %s" % short_err(e))
    elif getattr(opts, "raw_whois", False):
        try:
            out["whois_server"], out["raw"] = whois_raw(t.registrable, CFG["timeout"])
        except (OSError, FetchError) as e:
            out["errors"].append("WHOIS: %s" % short_err(e))
    if not out["source"]:
        out["error"] = "; ".join(out["errors"]) or "no data"
        return out
    _derive_dates(out)
    return out


# ----------------------------------------------------------------------------
# Module: SSL / TLS
# ----------------------------------------------------------------------------
def _handshake(ctx, host, port, sni):
    with socket.create_connection((host, port), timeout=CFG["timeout"]) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as s:
            return {"version": s.version(), "cipher": s.cipher(), "alpn": s.selected_alpn_protocol(),
                    "der": s.getpeercert(binary_form=True), "cert": s.getpeercert() or None}


def _decode_cert_der(der):
    """Decode an unverified peer certificate using CPython's own test decoder (no deps)."""
    if not der:
        return None
    try:
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(ssl.DER_cert_to_PEM_cert(der))
            return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        finally:
            os.unlink(path)
    except Exception:
        return None


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


def tls_inspect(host, port, is_ip):
    sni = None if is_ip else host
    info = {"host": host, "port": port, "verified": False, "verify_error": None}
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    hs = None
    try:
        hs = _handshake(ctx, host, port, sni)
        info["verified"] = True
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = getattr(e, "verify_message", None) or short_err(e)
    except (ssl.SSLError, OSError) as e:
        return {"error": "TLS connection failed on port %d: %s" % (port, short_err(e))}
    if hs is None:
        ctx2 = _ctx(False)
        ctx2.set_alpn_protocols(["h2", "http/1.1"])
        try:
            hs = _handshake(ctx2, host, port, sni)
        except (ssl.SSLError, OSError) as e:
            info["error"] = short_err(e)
            return info
    der = hs["der"]
    cert = hs["cert"] or _decode_cert_der(der)
    c = hs["cipher"] or (None, None, None)
    info.update(tls_version=hs["version"], alpn=hs["alpn"],
                cipher={"name": c[0], "protocol": c[1], "bits": c[2]},
                sha256=_fp(der, "sha256"), sha1=_fp(der, "sha1"))
    if not cert:
        info["note"] = "certificate could not be decoded"
        return info
    subj, iss = _rdn(cert.get("subject")), _rdn(cert.get("issuer"))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    ips = [v for k, v in cert.get("subjectAltName", ()) if k == "IP Address"]
    nb = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), dt.timezone.utc)
    na = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    names = sans or ([subj["commonName"]] if "commonName" in subj else [])
    info.update(
        subject=subj, issuer=iss,
        subject_cn=subj.get("commonName"), issuer_cn=iss.get("commonName"), issuer_org=iss.get("organizationName"),
        valid_from=iso(nb), valid_to=iso(na), days_left=(na - now_utc()).days,
        lifetime_days=(na - nb).days, expired=na < now_utc(), not_yet_valid=nb > now_utc(),
        serial=cert.get("serialNumber"), version=cert.get("version"),
        sans=sans, san_ips=ips, wildcard=any(s.startswith("*.") for s in sans),
        self_signed=bool(subj) and subj == iss,
        hostname_match=True if info["verified"] else ((host in ips) if is_ip else _host_matches(host, names)),
        ocsp=list(cert.get("OCSP", ())), ca_issuers=list(cert.get("caIssuers", ())),
        crl=list(cert.get("crlDistributionPoints", ())),
    )
    return info


def probe_protocols(host, port, is_ip):
    sni = None if is_ip else host
    versions = [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]

    def probe(item):
        name, ver = item
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
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


def mod_ssl(t, opts):
    port = getattr(opts, "tls_port", 443)
    info = tls_inspect(t.host, port, t.is_ip)
    if "error" not in info or "tls_version" in info:
        info["protocols"] = probe_protocols(t.host, port, t.is_ip)
    return info


# ----------------------------------------------------------------------------
# Module: HTTP
# ----------------------------------------------------------------------------
HEADER_TECH = [
    ("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-vercel-id", "Vercel"),
    ("x-nf-request-id", "Netlify"), ("x-github-request-id", "GitHub Pages"), ("fly-request-id", "Fly.io"),
    ("x-azure-ref", "Azure Front Door"), ("x-sucuri-id", "Sucuri"), ("x-akamai-transformed", "Akamai"),
    ("x-wix-request-id", "Wix"), ("x-shopify-stage", "Shopify"), ("x-drupal-cache", "Drupal"),
    ("x-served-by", "Fastly/Varnish"), ("x-envoy-upstream-service-time", "Envoy"),
    ("x-render-origin-server", "Render"), ("x-railway-edge", "Railway"),
]
BODY_TECH = [
    ("wp-content", "WordPress"), ("wp-includes", "WordPress"), ("/_next/", "Next.js"), ("__NEXT_DATA__", "Next.js"),
    ("/_nuxt/", "Nuxt"), ("cdn.shopify.com", "Shopify"), ("Drupal.settings", "Drupal"), ("content=\"Joomla", "Joomla"),
    ("googletagmanager.com", "Google Tag Manager"), ("google-analytics.com", "Google Analytics"),
    ("static.wixstatic.com", "Wix"), ("squarespace.com", "Squarespace"), ("data-reactroot", "React"),
    ("ng-version", "Angular"), ("cdn.jsdelivr.net/npm/bootstrap", "Bootstrap"), ("cloudflareinsights.com", "Cloudflare Web Analytics"),
]
SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
               "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy"]


def detect_tech(h, body):
    tech = []
    for k, name in HEADER_TECH:
        if k in h:
            tech.append(name)
    server = h.get("server", "")
    if server and re.search(r"cloudflare", server, re.I):
        tech.append("Cloudflare")
    for k in ("x-powered-by", "x-generator", "x-aspnet-version", "x-runtime"):
        if h.get(k):
            tech.append("%s: %s" % (k, h[k]))
    if server:
        tech.append("server: %s" % server)
    for needle, name in BODY_TECH:
        if needle in body:
            tech.append(name)
    m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)", body, re.I)
    if m:
        tech.append("generator: %s" % m.group(1)[:80])
    return uniq(tech)


def audit_headers(h):
    res = {k: h.get(k) for k in SEC_HEADERS}
    issues = []
    hsts = h.get("strict-transport-security")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < 15552000:
            issues.append("HSTS max-age is %d (< 180 days)" % age)
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
    return {"headers": res, "present": sum(1 for v in res.values() if v), "total": len(res), "issues": issues}


def parse_cookies(pairs):
    out = []
    for k, v in pairs:
        if k.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in v.split(";")]
        flags = {p.split("=")[0].lower(): (p.split("=", 1)[1] if "=" in p else True) for p in parts[1:]}
        out.append({"name": parts[0].split("=", 1)[0], "secure": "secure" in flags,
                    "httponly": "httponly" in flags, "samesite": flags.get("samesite")})
    return out


def probe_site(url, max_hops=10):
    chain, seen, verify, insecure = [], set(), True, False
    cur, final = url, None
    while len(chain) <= max_hops:
        if cur in seen:
            chain.append({"url": cur, "error": "redirect loop"})
            break
        try:
            r = http_fetch(cur, verify=verify)
        except FetchError as e:
            if e.cert_error and verify:
                verify, insecure = False, True
                continue
            chain.append({"url": cur, "error": str(e)})
            break
        seen.add(cur)
        hd = {}
        for k, v in r["headers"]:
            hd.setdefault(k.lower(), v)
        loc = hd.get("location")
        chain.append({"url": cur, "status": r["status"], "ms": r["ms"], "server": hd.get("server"), "location": loc})
        if r["status"] in (301, 302, 303, 307, 308) and loc:
            cur = urllib.parse.urljoin(cur, loc)
            continue
        final = (r, hd)
        break
    res = {"chain": chain, "insecure_tls_used": insecure, "error": None}
    if not final:
        res["error"] = chain[-1].get("error") if chain and "error" in chain[-1] else "too many redirects"
        return res
    r, hd = final
    body = r["body"].decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    res.update(final_url=cur, status=r["status"], response_ms=r["ms"],
               headers={k: v for k, v in hd.items() if k != "set-cookie"},
               title=re.sub(r"\s+", " ", htmllib.unescape(m.group(1))).strip()[:200] if m else None,
               tech=detect_tech(hd, body), security=audit_headers(hd), cookies=parse_cookies(r["headers"]))
    return res


def probe_files(base):
    out = {}
    try:
        r = http_fetch(base + "/.well-known/security.txt", redirects=True, max_bytes=65536)
        body = r["body"].decode("utf-8", "replace")
        out["security_txt"] = bool(r["status"] == 200 and re.search(r"^\s*Contact\s*:", body, re.M | re.I))
        if out["security_txt"]:
            out["security_txt_contact"] = re.findall(r"^\s*Contact\s*:\s*(.+)$", body, re.M | re.I)[:3]
    except FetchError:
        out["security_txt"] = None
    try:
        r = http_fetch(base + "/robots.txt", redirects=True, max_bytes=262144)
        body = r["body"].decode("utf-8", "replace")
        ok = r["status"] == 200 and "<html" not in body[:300].lower()
        out["robots_txt"] = ok
        if ok:
            out["robots_disallow"] = len(re.findall(r"^\s*Disallow\s*:\s*\S", body, re.M | re.I))
            out["sitemaps"] = re.findall(r"^\s*Sitemap\s*:\s*(\S+)", body, re.M | re.I)[:5]
    except FetchError:
        out["robots_txt"] = None
    return out


def mod_http(t, opts):
    with cf.ThreadPoolExecutor(2) as ex:
        fh, fp = ex.submit(probe_site, "https://%s/" % t.host), ex.submit(probe_site, "http://%s/" % t.host)
        out = {"https": fh.result(), "http": fp.result()}
    hp = out["http"]
    out["http_redirects_to_https"] = (any(c["url"].startswith("https://") for c in hp["chain"][1:])
                                      if not hp.get("error") else None)
    good = out["https"] if not out["https"].get("error") else (out["http"] if not out["http"].get("error") else None)
    if good:
        p = urllib.parse.urlsplit(good["final_url"])
        out["files"] = probe_files("%s://%s" % (p.scheme, p.netloc))
    return out


# ----------------------------------------------------------------------------
# Module: IP intelligence
# ----------------------------------------------------------------------------
HOST_HINTS = [("cloudflare", "Cloudflare"), ("amazon", "AWS"), ("google", "Google"), ("microsoft", "Microsoft Azure"),
              ("akamai", "Akamai"), ("fastly", "Fastly"), ("digitalocean", "DigitalOcean"), ("ovh", "OVH"),
              ("hetzner", "Hetzner"), ("linode", "Linode"), ("vultr", "Vultr"), ("github", "GitHub"),
              ("oracle", "Oracle Cloud"), ("alibaba", "Alibaba Cloud"), ("incapsula", "Imperva"), ("netlify", "Netlify"),
              ("godaddy", "GoDaddy"), ("bharti", "Airtel"), ("reliance", "Reliance/Jio"), ("tata", "Tata")]


def asn_lookup(ip):
    a = ipaddress.ip_address(ip)
    rp = a.reverse_pointer
    q = (rp[:-len(".in-addr.arpa")] + ".origin.asn.cymru.com") if a.version == 4 else \
        (rp[:-len(".ip6.arpa")] + ".origin6.asn.cymru.com")
    vals = dns_values(q, "TXT")
    if not vals:
        return None
    p = [x.strip() for x in vals[0].split("|")]
    asns = p[0].split()
    out = {"asn": ["AS" + x for x in asns], "prefix": p[1] if len(p) > 1 else None,
           "country": p[2] if len(p) > 2 else None, "registry": p[3] if len(p) > 3 else None,
           "allocated": p[4] if len(p) > 4 else None, "name": None}
    if asns:
        nm = dns_values("AS%s.asn.cymru.com" % asns[0], "TXT")
        if nm:
            q2 = [x.strip() for x in nm[0].split("|")]
            out["name"] = q2[4] if len(q2) > 4 else None
    return out


def geo_lookup(ip):
    try:
        d = http_json("https://ipwho.is/%s" % ip)
        if d.get("success") is False:
            return {"error": d.get("message", "lookup failed")}
        conn = d.get("connection") or {}
        return {"country": d.get("country"), "country_code": d.get("country_code"), "region": d.get("region"),
                "city": d.get("city"), "lat": d.get("latitude"), "lon": d.get("longitude"),
                "timezone": (d.get("timezone") or {}).get("id"), "isp": conn.get("isp"), "org": conn.get("org")}
    except FetchError as e:
        return {"error": str(e)}


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


def mod_ip(t, opts):
    if t.is_ip:
        ips = [t.host]
    else:
        ips, sts = [], []
        for ty in ("A", "AAAA"):
            r = dns_query(t.host, ty)
            ips += [x["value"] for x in r["records"]]
            sts.append(r["status"])
        if not ips and all(x in ("ERROR", "TIMEOUT", "SERVFAIL") for x in sts):
            return {"error": "DNS lookup failed - cannot resolve addresses"}
    ips = uniq(ips)[:getattr(opts, "max_ips", 8)]
    if not ips:
        return {"addresses": [], "note": "no A/AAAA records"}
    with cf.ThreadPoolExecutor(4) as ex:
        return {"addresses": list(ex.map(ip_profile, ips))}


# ----------------------------------------------------------------------------
# Module: e-mail security
# ----------------------------------------------------------------------------
MX_PROVIDERS = [("google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"),
                ("protection.outlook.com", "Microsoft 365"), ("outlook.com", "Microsoft 365"),
                ("zoho.", "Zoho Mail"), ("pphosted.com", "Proofpoint"), ("mimecast", "Mimecast"),
                ("secureserver.net", "GoDaddy"), ("yahoodns.net", "Yahoo"), ("protonmail", "Proton Mail"),
                ("mailgun.org", "Mailgun"), ("sendgrid.net", "SendGrid"), ("icloud.com", "iCloud"),
                ("fastmail", "Fastmail"), ("zoho.in", "Zoho Mail (IN)"), ("emailsrvr.com", "Rackspace"),
                ("barracudanetworks.com", "Barracuda"), ("messagelabs.com", "Broadcom/Symantec")]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim",
                  "smtp", "mandrill", "mxvault", "zoho", "mailjet", "sendgrid", "amazonses", "mta", "email",
                  "everlytickey1", "cm", "dkim1", "dkim2", "protonmail", "protonmail2", "protonmail3"]


def _spf_records(domain):
    return [v for v in dns_values(domain, "TXT") if v.lower().startswith("v=spf1")]


def spf_count(record, seen, depth=0):
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
    return {k.strip().lower(): v.strip() for k, _, v in (p.partition("=") for p in txt.split(";") if p.strip())}


def mod_email(t, opts):
    if t.is_ip:
        return {"skipped": "IP target"}
    d = t.registrable
    chk = dns_query(d, "NS")
    if chk["status"] in ("ERROR", "TIMEOUT", "SERVFAIL"):
        return {"error": "DNS lookup failed (%s) - e-mail records cannot be evaluated" % (chk.get("error") or chk["status"])}
    out = {"domain": d}
    mx = sorted(dns_values(d, "MX"), key=_mx_sort)
    hosts = [m.split(None, 1)[-1].lower() for m in mx]
    out["mx"] = mx
    out["mx_provider"] = uniq(name for h in hosts for k, name in MX_PROVIDERS if k in h) or None
    out["null_mx"] = mx == ["0 ."] or mx == ["0"]
    # SPF
    spf = _spf_records(d)
    s = {"records": spf, "present": bool(spf), "multiple": len(spf) > 1}
    if spf:
        rec = spf[0]
        allt = next((x for x in rec.split()[1:] if re.fullmatch(r"[+\-~?]?all", x, re.I)), None)
        s.update(policy=allt, lookups=spf_count(rec, {d}),
                 includes=[x.split(":", 1)[1] for x in rec.split() if x.lower().lstrip("+-~?").startswith("include:")])
        s["lookups_exceeded"] = s["lookups"] > 10
    out["spf"] = s
    # DMARC
    dm_txt, inherited = [v for v in dns_values("_dmarc." + d, "TXT") if v.lower().startswith("v=dmarc1")], False
    dm = {"present": bool(dm_txt)}
    if dm_txt:
        tags = parse_tags(dm_txt[0])
        dm.update(record=dm_txt[0], policy=tags.get("p"), subdomain_policy=tags.get("sp"), pct=tags.get("pct", "100"),
                  rua=tags.get("rua"), ruf=tags.get("ruf"), adkim=tags.get("adkim", "r"), aspf=tags.get("aspf", "r"))
    out["dmarc"] = dm
    # DKIM (selectors can't be enumerated - common ones only)
    def dkim(sel):
        for v in dns_values("%s._domainkey.%s" % (sel, d), "TXT"):
            if "p=" in v or "v=dkim1" in v.lower():
                return sel
        return None
    with cf.ThreadPoolExecutor(10) as ex:
        out["dkim_selectors_found"] = [x for x in ex.map(dkim, DKIM_SELECTORS) if x]
    out["dkim_note"] = "only %d common selectors probed" % len(DKIM_SELECTORS)
    # MTA-STS / TLS-RPT / BIMI
    sts = {"dns": [v for v in dns_values("_mta-sts." + d, "TXT") if v.lower().startswith("v=stsv1")]}
    if sts["dns"]:
        try:
            r = http_fetch("https://mta-sts.%s/.well-known/mta-sts.txt" % d, max_bytes=32768)
            body = r["body"].decode("utf-8", "replace")
            sts["mode"] = (re.search(r"^mode\s*:\s*(\w+)", body, re.M | re.I) or [None, None])[1]
            sts["max_age"] = (re.search(r"^max_age\s*:\s*(\d+)", body, re.M | re.I) or [None, None])[1]
        except FetchError as e:
            sts["policy_error"] = str(e)
    out["mta_sts"] = sts
    out["tls_rpt"] = [v for v in dns_values("_smtp._tls." + d, "TXT") if v.lower().startswith("v=tlsrptv1")]
    out["bimi"] = [v for v in dns_values("default._bimi." + d, "TXT") if v.lower().startswith("v=bimi1")]
    return out


# ----------------------------------------------------------------------------
# Module: subdomains
# ----------------------------------------------------------------------------
TAKEOVER = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3 website", "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Service", "cloudapp.azure.com": "Azure VM", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob", "elasticbeanstalk.com": "AWS Elastic Beanstalk", "pantheonsite.io": "Pantheon",
    "netlify.app": "Netlify", "readthedocs.io": "Read the Docs", "surge.sh": "Surge", "bitbucket.io": "Bitbucket",
    "ghost.io": "Ghost", "helpscoutdocs.com": "Help Scout", "statuspage.io": "Statuspage", "zendesk.com": "Zendesk",
    "myshopify.com": "Shopify", "unbouncepages.com": "Unbounce", "fastly.net": "Fastly", "cloudfront.net": "CloudFront",
}
BRUTE_WORDS = """www mail remote blog webmail server ns1 ns2 smtp secure vpn m shop ftp mail2 test portal ns dev
admin api staging stage app apps beta cdn static assets img images media web email mx pop pop3 imap autodiscover
autoconfig cpanel whm git gitlab jenkins ci jira wiki docs help support status monitor grafana kibana elastic
db mysql sql postgres redis mongo backup old new demo sandbox uat qa preprod prod internal intranet extra
login sso auth id accounts account my dashboard panel manage console crm erp hr pay payments billing store
download downloads files upload cloud s3 storage proxy gateway gw lb node1 node2 web1 web2 mobile ios android
ws wss socket chat forum community news events careers jobs video stream live tv radio music partners vendor
office exchange owa lync meet zoom calendar cal ntp dns dns1 dns2 router fw firewall vpn2 ssh rdp bastion""".split()


def _src_crtsh(base):
    data = http_json("https://crt.sh/?q=%25." + base + "&output=json", timeout=max(CFG["timeout"], 30),
                     max_bytes=40_000_000)
    names = set()
    for row in data:
        for n in str(row.get("name_value", "")).splitlines():
            names.add(re.sub(r"^\*\.", "", n.strip().lower()))
    return names


def _src_hackertarget(base):
    r = http_fetch("https://api.hackertarget.com/hostsearch/?q=" + base, redirects=True, max_bytes=2_000_000)
    text = r["body"].decode("utf-8", "replace")
    if "API count exceeded" in text or text.lower().startswith("error"):
        raise FetchError(text.strip()[:80])
    return {ln.split(",")[0].strip().lower() for ln in text.splitlines() if "," in ln}


def _src_otx(base):
    d = http_json("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns" % base)
    return {str(x.get("hostname", "")).strip().lower() for x in d.get("passive_dns", [])}


def takeover_hint(cname):
    c = (cname or "").lower()
    return next((v for k, v in TAKEOVER.items() if k in c), None)


def resolve_host(h):
    try:
        canon, _aliases, ips = socket.gethostbyname_ex(h)
        return {"host": h, "ips": ips, "cname": canon if canon.lower() != h else None, "resolves": True}
    except (socket.gaierror, UnicodeError, OSError):
        pass
    v6 = dns_values(h, "AAAA")
    cname = (dns_values(h, "CNAME") or [None])[0]
    res = {"host": h, "ips": v6, "cname": cname, "resolves": bool(v6)}
    if not v6 and cname:
        res["takeover_hint"] = takeover_hint(cname)
    return res


def mod_subs(t, opts):
    if t.is_ip:
        return {"skipped": "IP target"}
    base = t.registrable
    found, status = {}, {}
    sources = {"crt.sh": _src_crtsh, "hackertarget": _src_hackertarget, "alienvault-otx": _src_otx}
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
    workers = getattr(opts, "threads", 30)
    if getattr(opts, "brute", False):
        words = BRUTE_WORDS
        if getattr(opts, "wordlist", None):
            with open(opts.wordlist, encoding="utf-8", errors="ignore") as f:
                words = [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]
        cand = ["%s.%s" % (w, base) for w in uniq(words)]
        with cf.ThreadPoolExecutor(workers) as ex:
            for r in ex.map(resolve_host, cand):
                if r["resolves"] and not (wild_ips and set(r["ips"]) <= wild_ips):
                    found.setdefault(r["host"], set()).add("brute")
        status["brute"] = "%d words tried" % len(cand)
    limit = getattr(opts, "max_resolve", 300)
    names = sorted(found)
    with cf.ThreadPoolExecutor(workers) as ex:
        resolved = list(ex.map(resolve_host, names[:limit]))
    for r in resolved:
        r["sources"] = sorted(found[r["host"]])
    return {
        "base": base, "total": len(names), "resolved_checked": len(resolved), "sources": status,
        "wildcard_dns": bool(wild_ips), "subdomains": resolved,
        "unchecked": names[limit:], "dangling_candidates": [r for r in resolved if r.get("takeover_hint")],
    }


# ----------------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------------
SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}


def analyze(rep):
    F = []
    add = lambda sev, mod, msg: F.append({"severity": sev, "module": mod, "message": msg})
    m = rep["modules"]
    w, d, s, h, e, ip, sub = (m.get(k) or {} for k in ("whois", "dns", "ssl", "http", "email", "ip", "subs"))
    # whois
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
    st = [x.lower().replace(" ", "") for x in w.get("status", [])]
    if st and not any("transferprohibited" in x for x in st):
        add("low", "whois", "No registrar transfer lock in status flags")
    # dns
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
    # tls
    if s and not s.get("skipped"):
        if s.get("error") and "tls_version" not in s:
            add("info", "ssl", s["error"])
        else:
            if s.get("expired"):
                add("high", "ssl", "Certificate has expired")
            elif s.get("days_left") is not None and s["days_left"] < 14:
                add("high", "ssl", "Certificate expires in %d days" % s["days_left"])
            elif s.get("days_left") is not None and s["days_left"] < 30:
                add("medium", "ssl", "Certificate expires in %d days" % s["days_left"])
            if not s.get("verified"):
                add("high", "ssl", "Certificate failed verification: %s" % s.get("verify_error"))
            if s.get("hostname_match") is False:
                add("high", "ssl", "Certificate does not cover this hostname")
            if s.get("self_signed"):
                add("medium", "ssl", "Self-signed certificate")
            pr = s.get("protocols", {})
            for v in ("TLSv1.0", "TLSv1.1"):
                if pr.get(v) == "accepted":
                    add("medium", "ssl", "Legacy protocol %s is accepted" % v)
            if pr.get("TLSv1.3") == "rejected":
                add("low", "ssl", "TLS 1.3 not supported")
    # http
    if h and not h.get("skipped"):
        hs = h.get("https", {})
        if hs.get("error"):
            add("medium" if not h.get("http", {}).get("error") else "info", "http", "HTTPS unreachable: %s" % hs["error"])
        else:
            if hs.get("insecure_tls_used"):
                add("medium", "http", "HTTPS only reachable with certificate validation disabled")
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
            bad = [c["name"] for c in hs.get("cookies", []) if not c["secure"] or not c["httponly"]]
            if bad:
                add("low", "http", "Cookies missing Secure/HttpOnly: %s" % ", ".join(bad[:6]))
        if h.get("http_redirects_to_https") is False and not hs.get("error"):
            add("medium", "http", "Plain HTTP does not redirect to HTTPS")
    # email
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
        if has_mx and not e.get("mta_sts", {}).get("dns"):
            add("info", "email", "MTA-STS not configured")
    # ip
    for a in ip.get("addresses", []):
        if a.get("private"):
            add("medium", "ip", "Public DNS points to a non-public address: %s" % a["ip"])
    # subs
    for r in sub.get("dangling_candidates", []):
        add("medium", "subs", "Possible dangling CNAME: %s -> %s (%s) - verify manually" % (r["host"], r["cname"], r["takeover_hint"]))
    F.sort(key=lambda x: SEV[x["severity"]])
    return F


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------
def section(title):
    print("\n" + bold(cyan("== %s %s" % (title, "=" * max(3, 66 - len(title))))))


def kv(k, v, indent=2, width=16):
    if v is None or v == "" or v == []:
        return
    print("%s%s %s" % (" " * indent, dim(k.ljust(width)), v))


def yn(v, good=None):
    if v is None:
        return dim("unknown")
    txt = "yes" if v else "no"
    if good is None:
        return txt
    return green(txt) if bool(v) == good else red(txt)


def trunc(s, n=150):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "..."


def r_dns(d):
    section("DNS")
    if d.get("skipped"):
        return print("  " + dim(d["skipped"]))
    if d.get("error"):
        return print("  " + red(d["error"]))
    if not d.get("exists", True):
        print("  " + red("NXDOMAIN - the domain does not exist"))
    kv("resolver", d.get("backend"))
    for ty in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        for r in d["records"].get(ty, []):
            print("  %s %s %s" % (bold(ty.ljust(6)), trunc(r["value"]), dim("ttl %s" % r["ttl"])))
    for ty, recs in (d.get("zone") or {}).items():
        for r in recs:
            print("  %s %s %s" % (bold((ty + "*").ljust(6)), r["value"], dim("(zone apex)")))
    if d.get("ns_addresses"):
        print("  " + dim("nameserver addresses"))
        for n, ips in d["ns_addresses"].items():
            print("    %s -> %s" % (n, ", ".join(ips) or dim("unresolved")))
    sg = d["dnssec"]
    kv("DNSSEC", green("signed (DS present, %d DNSKEY)" % sg["dnskey"]) if sg["signed"] else yellow("not signed"))
    kv("wildcard DNS", yellow("yes") if d.get("wildcard") else "no")


def r_whois(w):
    section("WHOIS / RDAP")
    if w.get("skipped"):
        return print("  " + dim(w["skipped"]))
    if w.get("error"):
        return print("  " + red(w["error"]))
    kv("source", "%s (%s)" % (w["source"], w.get("whois_server") or w["queried"]))
    if w.get("registered") is False:
        print("  " + yellow("Domain appears to be unregistered"))
    reg = w.get("registrar")
    if isinstance(reg, dict):
        kv("registrar", "%s%s" % (reg.get("name") or "-", " (IANA %s)" % reg["iana_id"] if reg.get("iana_id") else ""))
    else:
        kv("registrar", w.get("registrar"))
    kv("created", w.get("created_iso") and "%s  (%s days old)" % (w["created_iso"], w.get("age_days")))
    kv("updated", w.get("updated_iso"))
    dte = w.get("days_to_expiry")
    exp = w.get("expires_iso") and "%s  (%s days left)" % (w["expires_iso"], dte)
    kv("expires", (red(exp) if dte is not None and dte < 30 else exp))
    kv("status", ", ".join(w.get("status", [])))
    kv("nameservers", ", ".join(w.get("nameservers", [])))
    if w.get("dnssec_signed") is not None:
        kv("DNSSEC", "signed" if w["dnssec_signed"] else "unsigned")
    for role in ("registrant", "admin", "technical", "abuse"):
        c = w.get(role)
        if isinstance(c, dict) and (c.get("name") or c.get("email")):
            kv(role, " | ".join(x for x in (c.get("name"), c.get("email"), c.get("phone")) if x))
    kv("registrant", w.get("registrant") if isinstance(w.get("registrant"), str) else None)
    kv("abuse e-mail", w.get("abuse_email"))
    if w.get("raw"):
        print("\n" + dim(w["raw"].strip()))


def r_ssl(s):
    section("TLS / SSL")
    if s.get("skipped"):
        return print("  " + dim(s["skipped"]))
    if s.get("error") and "tls_version" not in s:
        return print("  " + yellow(s["error"]))
    ok = s.get("verified")
    kv("trusted", green("yes (chain + hostname verified)") if ok else red("NO - %s" % s.get("verify_error")))
    kv("subject", s.get("subject_cn"))
    kv("issuer", "%s%s" % (s.get("issuer_cn") or "-", " / %s" % s["issuer_org"] if s.get("issuer_org") else ""))
    if s.get("valid_to"):
        dl = s["days_left"]
        txt = "%s -> %s  (%d days left)" % (s["valid_from"], s["valid_to"], dl)
        kv("validity", red(txt) if dl < 14 else yellow(txt) if dl < 30 else txt)
        kv("lifetime", "%d days" % s["lifetime_days"])
    kv("hostname match", None if s.get("hostname_match") is None else yn(s["hostname_match"], True))
    kv("self-signed", yellow("yes") if s.get("self_signed") else "no")
    kv("serial", s.get("serial"))
    if s.get("sans"):
        sans = s["sans"]
        kv("SANs (%d)" % len(sans), trunc(", ".join(sans[:25]) + (" ..." if len(sans) > 25 else ""), 220))
    kv("wildcard", yn(s.get("wildcard")) if s.get("wildcard") is not None else None)
    kv("TLS / cipher", "%s / %s (%s bits)" % (s.get("tls_version"), s["cipher"]["name"], s["cipher"]["bits"]))
    kv("ALPN", s.get("alpn"))
    kv("OCSP", ", ".join(s.get("ocsp", [])))
    kv("CA issuers", ", ".join(s.get("ca_issuers", [])))
    kv("SHA-256", s.get("sha256"))
    pr = s.get("protocols")
    if pr:
        paint = {"accepted": green, "rejected": dim, "untestable": dim, "error": yellow}
        legacy = {"TLSv1.0", "TLSv1.1"}
        parts = []
        for v, r in pr.items():
            txt = "%s:%s" % (v, r)
            parts.append(red(txt) if (v in legacy and r == "accepted") else paint[r](txt))
        kv("protocols", "  ".join(parts))


def r_http(h):
    section("HTTP")
    if h.get("skipped"):
        return print("  " + dim(h["skipped"]))
    for scheme in ("https", "http"):
        p = h[scheme]
        print("  " + bold(scheme.upper()))
        for i, c in enumerate(p["chain"]):
            if "error" in c:
                print("    %s %s" % (red("x"), "%s - %s" % (c["url"], c["error"])))
            else:
                print("    %s %s %s%s" % (str(c["status"]), c["url"], dim("%sms" % c["ms"]),
                                         "  -> " + c["location"] if c.get("location") else ""))
        if p.get("error"):
            continue
        kv("title", p.get("title"), 4, 14)
        kv("server", p["headers"].get("server"), 4, 14)
        kv("content-type", p["headers"].get("content-type"), 4, 14)
        kv("tech / CDN", ", ".join(p.get("tech", [])), 4, 14)
        if p.get("insecure_tls_used"):
            print("    " + yellow("! certificate validation had to be disabled to connect"))
        if scheme == "https":
            sec = p["security"]
            kv("sec. headers", "%d/%d present" % (sec["present"], sec["total"]), 4, 14)
            for k, v in sec["headers"].items():
                print("      %s %s %s" % (green("+") if v else red("-"), k.ljust(30), dim(trunc(v, 70)) if v else ""))
            for c in p.get("cookies", []):
                fl = "%s%s samesite=%s" % ("Secure " if c["secure"] else red("!Secure "), "HttpOnly" if c["httponly"] else red("!HttpOnly"), c["samesite"])
                print("      cookie %s  %s" % (c["name"], fl))
    kv("http -> https", yn(h.get("http_redirects_to_https"), True))
    f = h.get("files") or {}
    if f:
        kv("robots.txt", yn(f.get("robots_txt")) + ("  (%s Disallow rules)" % f["robots_disallow"] if f.get("robots_disallow") is not None else ""))
        kv("sitemaps", ", ".join(f.get("sitemaps", [])))
        kv("security.txt", yn(f.get("security_txt")) + (" " + ", ".join(f.get("security_txt_contact", [])) if f.get("security_txt") else ""))


def r_ip(d):
    section("IP INTELLIGENCE")
    if not d.get("addresses"):
        return print("  " + dim(d.get("note", "none")))
    for a in d["addresses"]:
        print("  " + bold(a["ip"]) + (yellow("  (non-public address)") if not a.get("global") else ""))
        if not a.get("global"):
            continue
        kv("reverse DNS", ", ".join(a.get("ptr") or []) or dim("none"), 4, 14)
        asn = a.get("asn") or {}
        kv("ASN", "%s  %s" % (" ".join(asn.get("asn", [])), asn.get("name") or "") if asn else None, 4, 14)
        kv("prefix", asn.get("prefix") and "%s  (%s, %s)" % (asn["prefix"], asn.get("registry"), asn.get("allocated")), 4, 14)
        g = a.get("geo") or {}
        if g.get("error"):
            kv("geo", dim(g["error"]), 4, 14)
        else:
            kv("location", ", ".join(x for x in (g.get("city"), g.get("region"), g.get("country")) if x), 4, 14)
            kv("coordinates", g.get("lat") is not None and "%s, %s" % (g["lat"], g["lon"]), 4, 14)
            kv("org / ISP", " / ".join(x for x in (g.get("org"), g.get("isp")) if x), 4, 14)
            kv("timezone", g.get("timezone"), 4, 14)
        kv("hosting hint", a.get("hosting_hint"), 4, 14)


def r_email(e):
    section("E-MAIL SECURITY")
    if e.get("skipped"):
        return print("  " + dim(e["skipped"]))
    kv("MX", "  |  ".join(e["mx"]) if e["mx"] else yellow("none"))
    kv("MX provider", ", ".join(e["mx_provider"] or []))
    sp = e["spf"]
    if sp["present"]:
        pol = sp.get("policy") or "none"
        col = green if pol == "-all" else yellow if pol == "~all" else red
        kv("SPF", "%s  policy=%s  lookups=%s/10" % (trunc(sp["records"][0], 110), col(pol), red(sp["lookups"]) if sp["lookups_exceeded"] else sp["lookups"]))
    else:
        kv("SPF", red("missing"))
    dm = e["dmarc"]
    if dm["present"]:
        pol = dm.get("policy") or "?"
        col = green if pol in ("reject", "quarantine") else yellow
        kv("DMARC", "p=%s  sp=%s  pct=%s  rua=%s" % (col(pol), dm.get("subdomain_policy") or "-", dm["pct"], dm.get("rua") or "-"))
    else:
        kv("DMARC", red("missing"))
    kv("DKIM", ", ".join(e["dkim_selectors_found"]) if e["dkim_selectors_found"] else dim("none found (%s)" % e["dkim_note"]))
    sts = e["mta_sts"]
    kv("MTA-STS", ("mode=%s max_age=%s" % (sts.get("mode"), sts.get("max_age"))) if sts.get("dns") else dim("not configured"))
    kv("TLS-RPT", ", ".join(e["tls_rpt"]) or dim("not configured"))
    kv("BIMI", ", ".join(e["bimi"]) or dim("not configured"))


def r_subs(d):
    section("SUBDOMAINS")
    if d.get("skipped"):
        return print("  " + dim(d["skipped"]))
    kv("base domain", d["base"])
    kv("sources", ", ".join("%s=%s" % (k, v) for k, v in d["sources"].items()))
    kv("total found", "%d  (%d resolved/checked)" % (d["total"], d["resolved_checked"]))
    kv("wildcard DNS", yellow("yes - brute-force results filtered") if d["wildcard_dns"] else "no")
    for r in d["subdomains"]:
        ips = ", ".join(r["ips"][:3]) + (" ..." if len(r["ips"]) > 3 else "")
        line = "  %s %s" % (green("+") if r["resolves"] else dim("-"), r["host"].ljust(38))
        line += ips if ips else dim("no address")
        if r.get("cname"):
            line += dim("  CNAME " + r["cname"])
        if r.get("takeover_hint"):
            line += yellow("  <- possible dangling %s" % r["takeover_hint"])
        print(line)
    if d["unchecked"]:
        print("  " + dim("... %d more not resolved (raise --max-resolve; all are in the JSON output)" % len(d["unchecked"])))


def r_findings(F):
    section("FINDINGS")
    if not F:
        return print("  " + green("nothing notable"))
    col = {"high": red, "medium": yellow, "low": cyan, "info": dim}
    for f in F:
        print("  %s %s %s" % (col[f["severity"]](f["severity"].upper().ljust(6)), dim(f["module"].ljust(6)), f["message"]))


RENDER = {"dns": r_dns, "whois": r_whois, "ssl": r_ssl, "http": r_http, "ip": r_ip, "email": r_email, "subs": r_subs}


def render(rep):
    print("\n" + bold("%s" % rep["unicode"]) + (dim("  [%s]" % rep["domain"]) if rep["unicode"] != rep["domain"] else "")
          + dim("  registrable: %s" % rep["registrable"] if rep["type"] == "domain" and rep["registrable"] != rep["domain"] else ""))
    for name in ALL_MODULES:
        if name in rep["modules"]:
            data = rep["modules"][name]
            if data.get("error") and name not in ("dns", "whois", "ssl"):
                section(name.upper())
                print("  " + red(data["error"]))
            else:
                RENDER[name](data)
    r_findings(rep["findings"])
    print("\n" + dim("done in %.1fs  |  dns backend: %s" % (rep["elapsed_s"], "dnspython" if HAVE_DNSPYTHON and not CFG["doh"] else "DNS-over-HTTPS")))


# ----------------------------------------------------------------------------
# Orchestration / CLI
# ----------------------------------------------------------------------------
MODULES = {"dns": mod_dns, "whois": mod_whois, "ssl": mod_ssl, "http": mod_http, "ip": mod_ip, "email": mod_email, "subs": mod_subs}


def lookup(t, modules, opts):
    t0 = time.perf_counter()
    if t.is_ip:
        modules = [m for m in modules if m in ("ip", "ssl", "http")] or ["ip"]
    rep = {"input": t.raw, "domain": t.host, "unicode": t.unicode, "registrable": t.registrable,
           "type": "ip" if t.is_ip else "domain", "timestamp": iso(now_utc()), "modules": {}, "timing_ms": {}}

    def run(name):
        s = time.perf_counter()
        try:
            data = MODULES[name](t, opts)
        except Exception as ex:  # a module must never take the whole run down
            data = {"error": "%s: %s" % (type(ex).__name__, short_err(ex))}
        return name, data, round((time.perf_counter() - s) * 1000)

    with cf.ThreadPoolExecutor(max_workers=len(modules)) as ex:
        for name, data, ms in ex.map(run, modules):
            rep["modules"][name], rep["timing_ms"][name] = data, ms
    rep["findings"] = analyze(rep)
    rep["elapsed_s"] = round(time.perf_counter() - t0, 2)
    return rep


def build_parser():
    ap = argparse.ArgumentParser(description="All-in-one domain lookup (DNS, WHOIS/RDAP, TLS, HTTP, IP, e-mail security, subdomains).",
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="modules: %s" % ", ".join(ALL_MODULES))
    ap.add_argument("targets", nargs="*", help="domain, URL, e-mail address or IP (several allowed)")
    ap.add_argument("-l", "--list", metavar="FILE", help="file with one target per line")
    ap.add_argument("-m", "--modules", default="all", help="comma-separated modules (default: all)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the formatted report")
    ap.add_argument("-o", "--output", metavar="FILE", help="also save the full results as JSON")
    ap.add_argument("--timeout", type=float, default=8.0, help="network timeout in seconds (default 8)")
    ap.add_argument("--resolver", metavar="IP", help="use this DNS server (needs dnspython)")
    ap.add_argument("--doh", action="store_true", help="force DNS-over-HTTPS even if dnspython is installed")
    ap.add_argument("--tls-port", type=int, default=443, help="port for the TLS check (default 443)")
    ap.add_argument("--raw-whois", action="store_true", help="include raw WHOIS text")
    ap.add_argument("--brute", action="store_true", help="subdomain DNS brute force (one query per word)")
    ap.add_argument("--wordlist", metavar="FILE", help="custom wordlist for --brute")
    ap.add_argument("--max-resolve", type=int, default=300, help="max passive subdomains to resolve (default 300)")
    ap.add_argument("--max-ips", type=int, default=8, help="max IPs to profile (default 8)")
    ap.add_argument("--threads", type=int, default=30, help="threads for subdomain resolution (default 30)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version="domain_lookup %s" % __version__)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if os.name == "nt":
        os.system("")  # enable ANSI escapes on Windows 10+
    Style.on = sys.stdout.isatty() and not args.no_color and not args.json and not os.environ.get("NO_COLOR")
    CFG.update(timeout=args.timeout, resolver=args.resolver, doh=args.doh)
    if args.resolver and not HAVE_DNSPYTHON:
        print("[!] --resolver needs dnspython (pip install dnspython); using DNS-over-HTTPS instead", file=sys.stderr)

    mods = ALL_MODULES if args.modules.strip().lower() == "all" else [x.strip().lower() for x in args.modules.split(",") if x.strip()]
    bad = [m for m in mods if m not in MODULES]
    if bad:
        print("[!] unknown module(s): %s (choose from %s)" % (", ".join(bad), ", ".join(ALL_MODULES)), file=sys.stderr)
        return 2

    raw = list(args.targets)
    if args.list:
        with open(args.list, encoding="utf-8", errors="ignore") as f:
            raw += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not raw and sys.stdin.isatty():
        try:
            raw = [input("Domain to look up: ").strip()]
        except (EOFError, KeyboardInterrupt):
            return 130
    if not raw:
        build_parser().print_usage(sys.stderr)
        return 2

    reports, rc = [], 0
    for r in uniq(raw):
        try:
            t = parse_target(r)
        except ValueError as e:
            print("[!] %s" % e, file=sys.stderr)
            rc = 2
            continue
        if not args.json:
            print(dim("[*] looking up %s ..." % t.unicode), file=sys.stderr)
        try:
            rep = lookup(t, mods, args)
        except KeyboardInterrupt:
            print("\n[!] interrupted", file=sys.stderr)
            return 130
        reports.append(rep)
        if not args.json:
            render(rep)
    payload = reports[0] if len(reports) == 1 else reports
    if args.json:
        print(json.dumps(payload, indent=2, default=str, ensure_ascii=False))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
        print("[+] saved %s" % args.output, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
