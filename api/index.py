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


def run_lookup():
    """Returns (report_dict, error_tuple)."""
    raw = request.args.get("domain") or request.args.get("q") or ""
    if not raw.strip():
        return None, ("MISSING_DOMAIN", "domain parameter is required", 400)
    try:
        target = dl.parse_target(raw)
    except Exception as e:
        return None, ("INVALID_DOMAIN", str(e), 400)

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
            "report": "GET /api/domain/report?domain=<target>",
            "health": "GET /api/health",
        },
        "parameters": {
            "domain": "domain, URL, e-mail address or IP",
            "modules": "comma-separated subset, default all",
            "format": "json | text (lookup), text | json (report)",
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
    return err("NOT_FOUND", "Endpoint not found", 404)


@app.route("/api/domain/lookup", methods=["GET", "OPTIONS"])
def r_lookup():
    if request.method == "OPTIONS":
        return "", 204
    t0 = time.time()
    rep, e = run_lookup()
    if e:
        return err(e[0], e[1], e[2])
    rep = strip_non_json(rep)
    rep["http_elapsed_ms"] = round((time.time() - t0) * 1000)
    rep["budget_ms"] = MAX_DURATION * 1000
    if request.args.get("format", "json").lower() == "text":
        return Response(text_report(rep), mimetype="text/plain; charset=utf-8")
    return ok(rep)


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


@app.route("/api/domain/report", methods=["GET", "OPTIONS"])
def r_report():
    if request.method == "OPTIONS":
        return "", 204
    rep, e = run_lookup()
    if e:
        return err(e[0], e[1], e[2])
    rep = strip_non_json(rep)
    if request.args.get("format", "text").lower() == "json":
        return ok(rep)
    return Response(text_report(rep), mimetype="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5060")), debug=False)