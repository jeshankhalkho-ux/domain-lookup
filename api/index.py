"""
Domain Intelligence API - passive domain reconnaissance.

Sources (all free, no API key required):
  RDAP      https://rdap.org/domain/<domain>   registration data
  DNS       https://dns.google/resolve          A/AAAA/MX/NS/TXT/CNAME/SOA
  crt.sh    https://crt.sh/?q=%.<domain>        certificate transparency subdomains
  TLS       direct socket handshake             certificate chain details
  HTTP      direct request                     headers, redirect chain, tech fingerprint
  Geo       https://ipwho.is/<ip>               IP geolocation / ASN

Endpoints:
  GET /api/domain/info?domain=example.com   everything
  GET /api/domain/whois?domain=example.com   registration only
  GET /api/domain/dns?domain=example.com     DNS records only
  GET /api/domain/subdomains?domain=...      crt.sh subdomains only
  GET /api/domain/ssl?domain=example.com     TLS certificate only
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone

import requests as rq
from flask import Flask, jsonify, request

# ── Config ────────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "20"))
UA = os.getenv(
    "UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
)
MONITOR_URL = os.getenv("MONITOR_URL", "")
CORS_ALLOW = os.getenv("CORS_ALLOW", "*")

app = Flask(__name__)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)

CREATED_CAVEAT = (
    "This field is the registry's first registration date for the current "
    "registration. If a domain was allowed to lapse, deleted and re-registered, "
    "the original date is not published anywhere and cannot be recovered."
)

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


# ── Helpers ───────────────────────────────────────────────────────────────────
@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = CORS_ALLOW
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Api-Key"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


def clean_domain(raw: str) -> str:
    """Normalise user input to a bare hostname (strips scheme/path/port)."""
    d = (raw or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    d = d.split("/")[0].split("?")[0]
    d = d.split(":")[0]
    return d.strip(".")


def validate(domain: str):
    if not domain:
        return "domain is required"
    if len(domain) > 253:
        return "domain too long"
    if not DOMAIN_RE.match(domain):
        return "invalid domain format"
    return None


def is_public_ip(ip: str) -> bool:
    """Block private/loopback/link-local so this can't be used to probe internal nets."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        obj.is_private or obj.is_loopback or obj.is_link_local
        or obj.is_multicast or obj.is_reserved or obj.is_unspecified
    )


def resolve_ips(domain: str):
    ips = []
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            if ip not in ips and is_public_ip(ip):
                ips.append(ip)
    except socket.gaierror:
        pass
    return ips


def log_monitor(endpoint, status, elapsed, error=None):
    if not MONITOR_URL:
        return
    try:
        rq.post(f"{MONITOR_URL}/api/log", json={
            "api": "DomainIntel", "endpoint": endpoint,
            "status_code": status, "response_time": elapsed, "error": error,
        }, timeout=4)
    except Exception:
        pass


def ok(pd):
    return jsonify({"rs": "S", "rc": "OK", "rd": "Success", "pd": pd}), 200


def err(rc, rd, status=400):
    return jsonify({"rs": "E", "rc": rc, "rd": rd, "pd": None}), status


# ── RDAP (replaces WHOIS, structured + no rate-limit pain) ────────────────────
def rdap_lookup(domain: str):
    out = {"ok": False}
    try:
        r = rq.get(f"https://rdap.org/domain/{domain}",
                   headers={"User-Agent": UA, "Accept": "application/rdap+json"},
                   timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            out["error"] = f"rdap http {r.status_code}"
            return out
        d = r.json()
    except Exception as e:
        out["error"] = str(e)[:200]
        return out

    def events(kind):
        res = []
        for e in d.get("events") or []:
            if e.get("eventAction") == kind and e.get("eventDate"):
                res.append(e["eventDate"])
        return res

    registrar = ""
    for ent in d.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            vc = ent.get("vcardArray") or [[], []]
            for row in (vc[1] if len(vc) > 1 else []):
                if row and row[0] == "fn":
                    registrar = row[3]
                    break
        if registrar:
            break

    ns = []
    for nsd in d.get("nameservers") or []:
        if nsd.get("ldhName"):
            ns.append(nsd["ldhName"].lower().rstrip("."))

    all_events = [
        {"action": e.get("eventAction"), "date": e.get("eventDate")}
        for e in (d.get("events") or []) if e.get("eventDate")
    ]

    return {
        "ok": True,
        "source": "rdap",
        "handle": d.get("handle"),
        "ldhName": d.get("ldhName"),
        "unicodeName": d.get("unicodeName"),
        "registrar": registrar,
        "status": d.get("status") or [],
        "nameservers": ns,
        "secure_dns": bool(d.get("secureDNS")),
        "created": (events("registration") or [None])[0],
        "updated": (events("last changed") or [None])[0],
        "expires": (events("expiration") or [None])[0],
        "port43": d.get("port43"),
    }


def _whois_port43(domain, host="whois.iana.org", depth=0):
    """Raw WHOIS over TCP 43, following the IANA referral. Covers ccTLDs with no RDAP."""
    try:
        with socket.create_connection((host, 43), timeout=12) as s:
            s.settimeout(12)
            s.sendall(f"{domain}\r\n".encode())
            buf = b""
            while len(buf) < 200000:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
        text = buf.decode("utf-8", "replace")
    except Exception:
        return None, host

    if depth == 0:
        m = re.search(r"(?i)^\s*refer:\s*(\S+)", text, re.M)
        if m:
            return _whois_port43(domain, m.group(1).strip(), depth + 1)
    return text, host


_WHOIS_FIELDS = {
    "created": [
        r"(?i)^\s*(?:creation date|created on|created|registered on|"
        r"registration time|domain registration date|registered)\s*[:\-]?\s*"
        r"([^\r\n]{6,40})",
    ],
    "updated": [
        r"(?i)^\s*(?:updated date|last updated|last-update|modified)\s*[:\-]?\s*"
        r"([^\r\n]{6,40})",
    ],
    "expires": [
        r"(?i)^\s*(?:registry expiry date|expiry date|expires on|expires|"
        r"expiration date|payable by)\s*[:\-]?\s*([^\r\n]{6,40})",
    ],
    "registrar": [
        r"(?i)^\s*(?:registrar|sponsoring registrar|registrar name)\s*[:\-]\s*"
        r"([^\r\n]{3,80})",
    ],
}


def _norm_date(raw):
    """Normalise the many WHOIS date layouts to ISO where possible."""
    if not raw:
        return None
    s = raw.strip().split("T")[0].strip()
    s = s.replace("/", "-").replace(".", "-").rstrip("Z")
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return "%s-%s-%s" % m.groups()
    m = re.match(r"^(\d{2})-(\d{2})-(\d{4})$", s)
    if m:
        return "%s-%s-%s" % (m.group(3), m.group(2), m.group(1))
    return s or None


def whois_lookup(domain: str):
    text, host = _whois_port43(domain)
    out = {"ok": False, "server": host}
    if not text:
        out["error"] = f"whois unreachable ({host})"
        return out
    if re.search(r"(?i)no match|not found|no entries found|no data found", text):
        out["error"] = "domain not found in whois"
        return out

    data = {}
    for field, patterns in _WHOIS_FIELDS.items():
        for pat in patterns:
            m = re.search(pat, text, re.M)
            if m:
                data[field] = _norm_date(m.group(1))
                break
    ns = sorted(set(
        re.findall(r"(?i)^\s*(?:nserver|name server|nameserver)\s*[:\-]\s*([a-z0-9.\-]+\.[a-z]{2,})",
                   text, re.M)))
    status = sorted(set(
        re.findall(r"(?i)\b(clienthold|clienttransferprohibited|clientupdateprohibited|"
                   r"clientdeleteprohibited|serverhold|servertransferprohibited|"
                   r"serverupdateprohibited|serverdeleteprohibited|ok|active)\b",
                   text)))
    data["nameservers"] = ns[:20]
    data["status"] = status
    out.update({"ok": True, **data})
    return out


def _same_day(a, b):
    """Compare two ISO-ish timestamps by calendar day only."""
    if not a or not b:
        return None
    return str(a)[:10] == str(b)[:10]


def registration_lookup(domain: str, cross_check=True):
    """Resolve registration data, preferring RDAP and falling back to WHOIS.

    RDAP is registry-authoritative and agrees with WHOIS where both exist, but
    many ccTLDs (.io, .in, ...) publish no RDAP at all - those need the
    port-43 WHOIS fallback.
    """
    r = rdap_lookup(domain)
    w = whois_lookup(domain) if (cross_check or not r.get("ok")) else {"ok": False}

    if r.get("ok"):
        if w.get("ok") and w.get("created"):
            if _same_day(r.get("created"), w["created"]) is False:
                r["created_discrepancy"] = {
                    "rdap": r.get("created"), "whois": w.get("created"),
                    "note": "sources disagree; RDAP is registry-authoritative",
                }
        r["created_verified"] = bool(w.get("ok"))
        r["created_source"] = "rdap"
        r["whois"] = {k: v for k, v in w.items()
                      if k in ("ok", "server", "error", "status", "nameservers")}
        return r

    if w.get("ok"):
        w["created_source"] = "whois"
        w["created_verified"] = True
        w["note"] = "no RDAP for this TLD; taken from port-43 WHOIS"
        return w

    return {"ok": False, "error": r.get("error") or w.get("error") or "no data",
            "rdap_error": r.get("error"), "whois_error": w.get("error")}


# ── DNS over HTTPS ────────────────────────────────────────────────────────────
def dns_lookup(domain: str, types=None):
    records = {}
    for t in types or DNS_TYPES:
        try:
            r = rq.get("https://dns.google/resolve",
                       params={"name": domain, "type": t},
                       headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT)
            data = r.json()
        except Exception:
            continue
        answers = []
        for a in data.get("Answer") or []:
            val = str(a.get("data", "")).strip('"')
            if val:
                answers.append(val)
        if answers:
            records[t] = answers
    return records


def extract_emails(records):
    out = []
    for txt in records.get("TXT", []):
        for addr in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", txt):
            out.append(addr.lower())
    return sorted(set(out))


# ── crt.sh subdomains ─────────────────────────────────────────────────────────
def crt_subdomains(domain: str):
    out = {"ok": False}
    # crt.sh is frequently flaky (502/503); retry a couple of times
    rows, last_err = None, None
    for attempt in range(3):
        try:
            r = rq.get(f"https://crt.sh/?q=%.{domain}&output=json",
                       headers={"User-Agent": UA}, timeout=REQUEST_TIMEOUT + 15)
            if r.status_code == 200:
                rows = r.json()
                break
            last_err = f"crt.sh http {r.status_code}"
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:120]}"
        time.sleep(1.5 * (attempt + 1))

    if rows is None:
        out["error"] = last_err
        return out

    names = set()
    for row in rows:
        for n in (row.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and n != domain:
                names.add(n)
    return {"ok": True, "count": len(names), "subdomains": sorted(names)}


# ── TLS certificate ───────────────────────────────────────────────────────────
def _flatten_rdns(rdns):
    """ssl cert issuer/subject are tuples of RDNs, each a tuple of (k, v)."""
    out = {}
    for rdn in rdns or ():
        try:
            for pair in rdn:
                out[pair[0]] = pair[1]
        except (TypeError, IndexError):
            continue
    return out


def tls_info(domain: str):
    out = {"ok": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
                der = ss.getpeercert(binary_form=True)
                cipher = ss.cipher()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:160]}"
        return out

    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
        except Exception:
            pass

    sans = [v for typ, v in (cert.get("subjectAltName") or ()) if typ == "DNS"]

    return {
        "ok": True,
        "subject": _flatten_rdns(cert.get("subject")),
        "issuer": _flatten_rdns(cert.get("issuer")),
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "days_until_expiry": days_left,
        "expired": (days_left is not None and days_left < 0),
        "serial": cert.get("serialNumber"),
        "sha1_fingerprint": hashlib.sha1(der).hexdigest(),
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
        "version": cert.get("version"),
        "san_count": len(sans),
        "san": sorted(set(sans))[:100],
        "cipher": cipher[0] if cipher else None,
        "protocol": cipher[1] if cipher else None,
    }


# ── HTTP probe ────────────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]

TECH_HINTS = {
    "cloudflare": ("server", "cf-ray"),
    "akamai": ("server", "x-akamai"),
    "amazon cloudfront": ("server", "via"),
    "vercel": ("server", "x-vercel"),
    "netlify": ("server", "x-nf"),
    "apache": ("server",),
    "nginx": ("server",),
    "iis": ("server",),
    "shopify": ("x-shopify-stage", "x-shopid"),
    "wordpress": ("x-powered-by", "link"),
    "react": ("x-powered-by",),
}


def http_probe(domain: str):
    out = {"ok": False}
    chain = []
    try:
        r = rq.get(f"https://{domain}/", headers={"User-Agent": UA},
                   timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:160]}"
        return out

    try:
        hist = rq.get(f"https://{domain}/", headers={"User-Agent": UA},
                      timeout=REQUEST_TIMEOUT, allow_redirects=False,
                      stream=True)
        chain = [f"{hist.status_code} {domain}"]
        hist.close()
    except Exception:
        pass

    hdrs = {k.lower(): v for k, v in r.headers.items()}
    server = hdrs.get("server", "")
    powered = hdrs.get("x-powered-by", "")

    detected = []
    haystack = " ".join([server, powered, str(hdrs)]).lower()
    for tech, keys in TECH_HINTS.items():
        for k in keys:
            if k in haystack:
                detected.append(tech)
                break

    missing = [h for h in SECURITY_HEADERS if h not in hdrs]
    insecure = "https" in hdrs.get("strict-transport-security", "")

    return {
        "ok": True,
        "status": r.status_code,
        "final_url": r.url,
        "redirects": chain,
        "title": (re.search(r"<title[^>]*>(.*?)</title>", r.text[:200000],
                             re.I | re.S).group(1).strip()
                  if re.search(r"<title[^>]*>(.*?)</title>", r.text[:200000], re.I | re.S)
                  else ""),
        "server": server,
        "x_powered_by": powered,
        "technologies": sorted(set(detected)),
        "content_type": hdrs.get("content-type", ""),
        "hsts": bool(insecure),
        "security_headers_present": [h for h in SECURITY_HEADERS if h in hdrs],
        "security_headers_missing": missing,
        "security_score": round(
            (len(SECURITY_HEADERS) - len(missing)) / len(SECURITY_HEADERS) * 100),
        "headers": {k: v for k, v in hdrs.items()
                    if k in ("server", "x-powered-by", "via", "cf-ray",
                             "x-vercel-id", "x-amz-cf-id", "content-type",
                             "strict-transport-security")},
    }


def geo_lookup(ips):
    res = []
    for ip in ips[:3]:
        if not is_public_ip(ip):
            continue
        try:
            r = rq.get(f"https://ipwho.is/{ip}", timeout=8)
            d = r.json()
            res.append({
                "ip": ip,
                "success": d.get("success"),
                "country": d.get("country"),
                "region": d.get("region"),
                "city": d.get("city"),
                "asn": d.get("connection", {}).get("asn"),
                "org": d.get("connection", {}).get("org"),
                "isp": d.get("connection", {}).get("isp"),
            })
        except Exception:
            res.append({"ip": ip, "error": "geo lookup failed"})
    return res


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "OPTIONS"])
def index():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "service": "Domain Intelligence API",
        "version": "1.0.0",
        "endpoints": {
            "info": "GET /api/domain/info?domain=<domain>",
            "whois": "GET /api/domain/whois?domain=<domain>",
            "dns": "GET /api/domain/dns?domain=<domain>",
            "subdomains": "GET /api/domain/subdomains?domain=<domain>",
            "ssl": "GET /api/domain/ssl?domain=<domain>",
            "health": "GET /api/health",
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


def _domain_arg():
    raw = request.args.get("domain") or request.args.get("q") or ""
    return clean_domain(raw)


@app.route("/api/domain/whois", methods=["GET", "OPTIONS"])
def r_whois():
    if request.method == "OPTIONS":
        return "", 204
    d = _domain_arg()
    if err_msg := validate(d):
        return err("INVALID_DOMAIN", err_msg)
    cross = request.args.get("cross_check", "1") not in ("0", "false", "no")
    reg = registration_lookup(d, cross_check=cross)
    if not reg.get("ok"):
        return err("REGISTRY_UNAVAILABLE",
                   reg.get("error") or "no registration data", 502)
    reg["created_caveat"] = CREATED_CAVEAT
    return ok(reg)


@app.route("/api/domain/dns", methods=["GET", "OPTIONS"])
def r_dns():
    if request.method == "OPTIONS":
        return "", 204
    d = _domain_arg()
    if err_msg := validate(d):
        return err("INVALID_DOMAIN", err_msg)
    recs = dns_lookup(d)
    if not recs:
        return err("NO_RECORDS", "No DNS records resolved", 404)
    return ok({
        "domain": d,
        "records": recs,
        "emails_found": extract_emails(recs),
        "ips": [v for v in recs.get("A", []) if is_public_ip(v)],
    })


@app.route("/api/domain/subdomains", methods=["GET", "OPTIONS"])
def r_sub():
    if request.method == "OPTIONS":
        return "", 204
    d = _domain_arg()
    if err_msg := validate(d):
        return err("INVALID_DOMAIN", err_msg)
    return ok({"domain": d, **crt_subdomains(d)})


@app.route("/api/domain/ssl", methods=["GET", "OPTIONS"])
def r_ssl():
    if request.method == "OPTIONS":
        return "", 204
    d = _domain_arg()
    if err_msg := validate(d):
        return err("INVALID_DOMAIN", err_msg)
    return ok({"domain": d, **tls_info(d)})


@app.route("/api/domain/info", methods=["GET", "OPTIONS"])
def r_info():
    t0 = time.time()
    if request.method == "OPTIONS":
        return "", 204
    d = _domain_arg()
    if err_msg := validate(d):
        log_monitor("/api/domain/info", 400, time.time() - t0, err_msg)
        return err("INVALID_DOMAIN", err_msg)

    ips = resolve_ips(d)
    pd = {
        "domain": d,
        "resolved_ips": ips,
        "ip_count": len(ips),
        "registration": registration_lookup(
            d, cross_check=request.args.get("cross_check", "1") not in ("0", "false", "no")),
    }
    pd["registration"]["created_caveat"] = CREATED_CAVEAT
    pd["dns"] = dns_lookup(d)
    pd["emails_found"] = extract_emails(pd["dns"])
    pd["subdomains"] = crt_subdomains(d)
    pd["tls"] = tls_info(d)
    pd["http"] = http_probe(d)
    pd["geo"] = geo_lookup(ips)

    elapsed = round((time.time() - t0) * 1000)
    log_monitor("/api/domain/info", 200, elapsed)
    resp = jsonify({"rs": "S", "rc": "OK", "rd": "Success", "pd": pd})
    resp.headers["X-Elapsed-Ms"] = str(elapsed)
    return resp, 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5060")), debug=False)