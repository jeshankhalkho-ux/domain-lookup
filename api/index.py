"""
HTTP wrapper around domain_lookup.py - exposes the CLI as a JSON/text API.

This file contains no lookup logic. Every piece of analysis comes from
domain_lookup.py at the repository root; this only translates query parameters
into the options object that script expects, calls its lookup(), and serves the
result.

Endpoints
  GET /api/domain/lookup?domain=example.com[&modules=...&format=json]
  GET /api/domain/report?domain=example.com          formatted text report
  GET /api/health
"""

import argparse
import io
import os
import sys
import time
import contextlib

from flask import Flask, Response, jsonify, request

# make the sibling CLI importable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import domain_lookup as dl  # noqa: E402

app = Flask(__name__)

MAX_DURATION = int(os.getenv("MAX_DURATION", "55"))
CORS_ALLOW = os.getenv("CORS_ALLOW", "*")


@app.after_request
def cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = CORS_ALLOW
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


def ok(pd):
    return jsonify({"rs": "S", "rc": "OK", "rd": "Success", "pd": pd}), 200


def err(rc, rd, status=400):
    return jsonify({"rs": "E", "rc": rc, "rd": rd, "pd": None}), status


def build_opts():
    """Map query parameters onto the argparse namespace domain_lookup expects."""
    a = request.args
    def num(name, default, cast, lo=None, hi=None):
        try:
            v = cast(a.get(name, default))
        except (TypeError, ValueError):
            return default
        if lo is not None and v < lo:
            return default
        if hi is not None and v > hi:
            return default
        return v

    opts = argparse.Namespace(
        timeout=num("timeout", 8.0, float, 1.0, 30.0),
        resolver=None,
        doh=a.get("doh", "").lower() in ("1", "true", "yes"),
        tls_port=num("tls_port", 443, int, 1, 65535),
        raw_whois=a.get("raw_whois", "").lower() in ("1", "true", "yes"),
        brute=False,
        wordlist=None,
        max_resolve=num("max_resolve", 300, int, 1, 1000),
        max_ips=num("max_ips", 8, int, 1, 20),
        threads=num("threads", 30, int, 1, 100),
        modules="all",
    )

    # keep the script's own global config in step with the request
    dl.CFG.update(timeout=opts.timeout, resolver=opts.resolver, doh=opts.doh)

    # brute force is intentionally not exposed: it is an active scan
    if a.get("brute", "").lower() in ("1", "true", "yes"):
        return None, "brute force is disabled on this endpoint"
    return opts, None


def pick_modules():
    """Always returns (list | None, message)."""
    raw = (request.args.get("modules") or "all").strip().lower()
    if raw == "all":
        return list(dl.ALL_MODULES), None
    mods = [m.strip() for m in raw.split(",") if m.strip()]
    bad = [m for m in mods if m not in dl.ALL_MODULES]
    if bad:
        return None, "unknown module(s): %s (valid: %s)" % (
            ", ".join(bad), ", ".join(dl.ALL_MODULES))
    return mods, None


def run_lookup(force_modules=None):
    """Returns (report_dict, error_tuple)."""
    raw = request.args.get("domain") or request.args.get("q") or ""
    if not raw.strip():
        return None, ("MISSING_DOMAIN", "domain parameter is required", 400)
    try:
        target = dl.parse_target(raw)
    except Exception as e:
        return None, ("INVALID_DOMAIN", str(e), 400)

    if force_modules:
        mods = [m for m in force_modules if m in dl.ALL_MODULES] or ["dns"]
    else:
        mods, msg = pick_modules()
        if mods is None:
            return None, ("INVALID_MODULE", msg, 400)
    opts, msg = build_opts()
    if opts is None:
        return None, ("DISABLED", msg, 400)

    try:
        rep = dl.lookup(target, mods, opts)
    except Exception as e:
        return None, ("LOOKUP_FAILED", "%s: %s" % (type(e).__name__, e), 502)
    return rep, None


def strip_non_json(obj):
    """Make a report safe for jsonify (regex/bytes/sets do occur in raw output)."""
    if isinstance(obj, dict):
        return {str(k): strip_non_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [strip_non_json(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (set, frozenset)):
        return sorted(str(v) for v in obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    return str(obj)


@app.route("/", methods=["GET", "OPTIONS"])
def index():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({
        "service": "Domain Lookup API",
        "implementation": "domain_lookup.py (unmodified)",
        "modules": dl.ALL_MODULES,
        "endpoints": {
            "lookup": "GET /api/domain/lookup?domain=<target>",
            "report": "GET /api/domain/report?domain=<target>  (formatted text)",
            "health": "GET /api/health",
            "aliases": "GET /api/domain/<module>?domain=<target> "
                       "(whois, dns, ssl, http, ip, email, subs, info, findings)",
        },
        "example": "/api/domain/lookup?domain=github.com&modules=whois,ssl",
        "parameters": {
            "domain": "domain, URL, e-mail address or IP",
            "modules": "comma-separated subset, default all",
            "view": "summary (default) | full  - full returns the complete raw report",
            "format": "json | text (lookup), text | json (report)",
            "subs_limit": "how many subdomains to list in the summary, default 10",
            "timeout": "network timeout seconds, 1-30, default 8",
            "tls_port": "TLS port, default 443",
            "max_ips": "IPs profiled per target, default 8",
            "max_resolve": "subdomains resolved, default 300",
            "threads": "concurrency, default 30",
            "raw_whois": "include raw WHOIS text",
            "doh": "force DNS-over-HTTPS",
        },
        "notes": "Passive only. DNS brute force is not exposed on this endpoint.",
    }), 200


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "domain-lookup",
        "version": getattr(dl, "__version__", "?"),
        "dnspython": dl.HAVE_DNSPYTHON,
        "tldextract": dl.HAVE_TLDEXTRACT,
    }), 200


@app.route("/<path:_p>", methods=["GET", "POST", "OPTIONS"])
def fallback(_p):
    if request.method == "OPTIONS":
        return "", 204
    return err("NOT_FOUND",
               "Endpoint not found. Valid: /api/domain/lookup, /api/domain/report, "
               "/api/health (needs ?domain=<target>)", 404)


def _subs_limit():
    try:
        v = int(request.args.get("subs_limit", "10"))
    except (TypeError, ValueError):
        return 10
    return max(0, min(200, v))


def _view():
    return (request.args.get("view") or "summary").strip().lower()


def _finish(rep, t0):
    """Shared response tail for every endpoint."""
    elapsed = round((time.time() - t0) * 1000)
    if _view() == "full":
        rep["http_elapsed_ms"] = elapsed
        rep["budget_ms"] = MAX_DURATION * 1000
        return rep
    out = summarize(rep, subs_limit=_subs_limit())
    out["http_elapsed_ms"] = elapsed
    return out


@app.route("/api/domain/lookup", methods=["GET", "OPTIONS"])
def r_lookup():
    if request.method == "OPTIONS":
        return "", 204
    t0 = time.time()
    rep, e = run_lookup()
    if e:
        return err(e[0], e[1], e[2])
    rep = strip_non_json(rep)
    payload = _finish(rep, t0)
    if request.args.get("format", "json").lower() == "text":
        return Response(text_report(rep), mimetype="text/plain; charset=utf-8")
    return ok(payload)


def text_report(rep):
    """Re-use the script's own renderer, capturing stdout."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            dl.render(rep)
        out = buf.getvalue()
    except Exception as e:
        out = "report rendering failed: %s\n\n%s" % (e, _fallback_text(rep))
    return ascii_safe(out)


def _fallback_text(rep):
    L = ["=" * 66, "  DOMAIN LOOKUP: %s" % rep.get("domain"), "=" * 66, ""]
    w = (rep.get("modules") or {}).get("whois") or {}
    if w.get("created_iso"):
        L.append("  created      %s (%s days old)" % (w["created_iso"], w.get("age_days")))
    if w.get("registrar"):
        reg = w["registrar"]
        L.append("  registrar    %s" % (reg.get("name") if isinstance(reg, dict) else reg))
    if w.get("expires_iso"):
        L.append("  expires      %s (%s days)" % (w["expires_iso"], w.get("days_to_expiry")))
    s = (rep.get("modules") or {}).get("ssl") or {}
    if s.get("issuer_org") or s.get("issuer_cn"):
        L.append("  tls issuer   %s" % (s.get("issuer_org") or s.get("issuer_cn")))
    L.append("")
    L.append("-- FINDINGS " + "-" * 52)
    fs = rep.get("findings") or []
    if fs:
        for f in fs:
            L.append("  [%-6s] %-7s %s" % (f["severity"].upper(), f["module"], f["message"]))
    else:
        L.append("  nothing notable")
    L.append("")
    return "\n".join(L)


def ascii_safe(s):
    out = []
    for ch in s:
        if ch == "\n" or ch == "\t":
            out.append(ch)
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append("-")
    return "".join(out)


# ── Compact view ─────────────────────────────────────────────────────────────
def _first(d, *keys, default=None):
    for k in keys:
        v = d.get(k)
        if v not in (None, "", [], {}):
            return v
    return default


def _reg_name(w):
    r = w.get("registrar")
    return (r.get("name") if isinstance(r, dict) else r) or None


def summarize(rep, subs_limit=10):
    """Small, readable payload. Full raw data stays available via &view=full."""
    m = rep.get("modules") or {}

    dns = m.get("dns") or {}
    recs = dns.get("records") or {}
    ip = m.get("ip") or {}
    addrs = ip.get("addresses") or []
    first = addrs[0] if addrs else {}
    asn = first.get("asn") or {}
    geo = first.get("geo") or {}

    sub = m.get("subs") or {}
    subs = (sub.get("subdomains") or [])
    kept = subs[:subs_limit]

    out = {
        "domain": rep.get("domain"),
        "registrable": rep.get("registrable"),
        "type": rep.get("type"),
        "elapsed_s": rep.get("elapsed_s"),
        "module_timings_ms": rep.get("timing_ms"),
        "dns_backend": "dnspython" if dl.HAVE_DNSPYTHON and not dl.CFG["doh"]
                       else "DNS-over-HTTPS",
    }

    w = m.get("whois")
    if w and not w.get("skipped"):
        out["registration"] = {
            "source": w.get("source"),
            "registrar": _reg_name(w),
            "created": w.get("created_iso"),
            "age_days": w.get("age_days"),
            "expires": w.get("expires_iso"),
            "days_to_expiry": w.get("days_to_expiry"),
            "status": w.get("status") or [],
            "nameservers": (w.get("nameservers") or [])[:4],
            "nameservers_more": max(0, len(w.get("nameservers") or []) - 4),
            "abuse": (w.get("abuse") or {}).get("email") if isinstance(w.get("abuse"), dict) else None,
            "dnssec": w.get("dnssec_signed"),
        }

    if dns and not dns.get("skipped"):
        out["dns"] = {
            "a": [r["value"] for r in (recs.get("A") or [])][:4],
            "aaaa_count": len(recs.get("AAAA") or []),
            "mx": [r["value"] for r in (recs.get("MX") or [])][:5],
            "ns_count": len(recs.get("NS") or []),
            "txt_count": len(recs.get("TXT") or []),
            "caa": [r["value"] for r in (recs.get("CAA") or [])][:3],
            "dnssec": (dns.get("dnssec") or {}).get("signed"),
            "wildcard": dns.get("wildcard"),
            "exists": dns.get("exists"),
        }

    s = m.get("ssl")
    if s and not s.get("skipped"):
        out["tls"] = {
            "issuer": s.get("issuer_org") or s.get("issuer_cn"),
            "subject": s.get("subject_cn"),
            "valid_to": s.get("valid_to"),
            "days_left": s.get("days_left"),
            "protocol": s.get("tls_version"),
            "cipher": (s.get("cipher") or {}).get("name") if isinstance(s.get("cipher"), dict)
                      else s.get("cipher"),
            "alpn": s.get("alpn"),
            "trusted": s.get("verified"),
            "self_signed": s.get("self_signed"),
            "wildcard_cert": s.get("wildcard"),
            "san_count": s.get("san_count") or len(s.get("sans") or []),
            "protocol_support": s.get("protocols"),
        }

    h = m.get("http")
    if h and not h.get("skipped"):
        https = h.get("https") or {}
        sec = https.get("security") or {}
        out["web"] = {
            "status": https.get("status"),
            "title": https.get("title"),
            "server": https.get("server"),
            "tech": (https.get("tech") or [])[:6],
            "security_present": "%s/%s" % (sec.get("present"), sec.get("total")),
            "security_issues": (sec.get("issues") or [])[:6],
            "http_redirects_to_https": h.get("http_redirects_to_https"),
            "robots_txt": (h.get("files") or {}).get("robots_txt"),
            "security_txt": (h.get("files") or {}).get("security_txt"),
        }

    if ip and not ip.get("skipped"):
        out["network"] = {
            "ips": [a.get("ip") for a in addrs][:4],
            "asn": " ".join(asn.get("asn") or []) if asn else None,
            "asn_name": asn.get("name"),
            "prefix": asn.get("prefix"),
            "org": geo.get("org"),
            "location": ", ".join(x for x in [geo.get("city"), geo.get("country")] if x) or None,
            "hosting_hint": first.get("hosting_hint"),
        }

    e = m.get("email")
    if e and not e.get("skipped"):
        spf = e.get("spf") or {}
        dm = e.get("dmarc") or {}
        out["email_security"] = {
            "mx_count": len(e.get("mx") or []),
            "mx_provider": e.get("mx_provider"),
            "spf": spf.get("policy") if spf.get("present") else None,
            "spf_lookups": spf.get("lookups"),
            "dmarc": dm.get("policy") if dm.get("present") else None,
            "dkim_selectors": len(e.get("dkim_selectors_found") or []),
            "mta_sts": bool((e.get("mta_sts") or {}).get("dns")),
            "bimi": bool(e.get("bimi")),
        }

    if sub and not sub.get("skipped"):
        out["subdomains"] = {
            "base": sub.get("base"),
            "total": sub.get("total"),
            "resolved_checked": sub.get("resolved_checked"),
            "sources": sub.get("sources"),
            "wildcard_dns": sub.get("wildcard"),
            "dangling_cname": len(sub.get("dangling_candidates") or []),
            "sample": [{"host": x.get("host"), "ips": (x.get("ips") or [])[:2]}
                       for x in kept],
            "shown": len(kept),
            "omitted": max(0, len(subs) - len(kept)),
            "note": "pass &subs_limit=N to change how many are listed",
        }

    counts = {}
    for f in (rep.get("findings") or []):
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    out["findings"] = rep.get("findings") or []
    out["finding_counts"] = counts
    out["errors"] = {k: v.get("error") for k, v in m.items()
                     if isinstance(v, dict) and v.get("error")}
    out["_full"] = "append &view=full for the complete raw report"
    return out


@app.route("/api/domain/report", methods=["GET", "OPTIONS"])
def r_report():
    if request.method == "OPTIONS":
        return "", 204
    t0 = time.time()
    rep, e = run_lookup()
    if e:
        return err(e[0], e[1], e[2])
    rep = strip_non_json(rep)
    if request.args.get("format", "text").lower() == "json":
        return ok(_finish(rep, t0))
    return Response(text_report(rep), mimetype="text/plain; charset=utf-8")


# ── Backwards-compatible aliases ──────────────────────────────────────────────
# The earlier HTTP version of this repo exposed /api/domain/<name> for each
# module plus /api/domain/info. Map those onto lookup() so old URLs keep working.
ALIASES = {"info": None, "whois": "whois", "dns": "dns", "ssl": "ssl",
           "subs": "subs", "email": "email", "ip": "ip", "http": "http",
           "findings": None}


def _alias_view(module):
    def view():
        if request.method == "OPTIONS":
            return "", 204
        rep, e = run_lookup(force_modules=[module] if module else None)
        if e:
            return err(e[0], e[1], e[2])
        rep = strip_non_json(rep)
        if request.args.get("format", "json").lower() == "text":
            return Response(text_report(rep), mimetype="text/plain; charset=utf-8")
        return ok(_finish(rep, time.time()))
    return view


for _name, _mod in ALIASES.items():
    app.add_url_rule("/api/domain/" + _name, "alias_" + _name,
                     _alias_view(_mod), methods=["GET", "OPTIONS"])

# tolerate the /lookup suffix and the bare /api/domain path too
app.add_url_rule("/api/lookup", "alias_lookup", r_lookup, methods=["GET", "OPTIONS"])
app.add_url_rule("/api/domain", "alias_domain", r_lookup, methods=["GET", "OPTIONS"])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5060")), debug=False)