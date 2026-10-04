"""
Vercel entrypoint: Flask API around url_analyzer.py (the UI is static: public/index.html).

Endpoints
  GET  /api/health
  GET  /api/analyze?url=...&mode=full|passive|offline
  POST /api/analyze   {"url": "...", "mode": "full"}

Environment variables (Vercel -> Project -> Settings -> Environment Variables)
  API_KEY            required unless ALLOW_PUBLIC=1; sent as header  x-api-key  (or Authorization: Bearer ...)
  ALLOW_PUBLIC       "1" = run without a key (not recommended: anyone can make your function fetch URLs)
  ALLOWED_ORIGIN     optional CORS origin, e.g. https://my-frontend.vercel.app (default: same-origin only)
  RATE_LIMIT_PER_MIN per-IP limit, best effort per instance (default 20)
  TIME_BUDGET_S      wall-clock budget per analysis (default 45; keep below maxDuration in vercel.json)
  VT_API_KEY, GSB_API_KEY, URLHAUS_AUTH_KEY   optional threat-intel keys
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import threading
import time
from collections import defaultdict, deque

from flask import Flask, Response, request, send_from_directory

import url_analyzer as ua

# Hardened server-side settings (never taken from the request)
ua.CFG.update(timeout=8.0, max_bytes=800_000, allow_private=False, verify=True, allowed_ports={80, 443})


def _env_num(name, default, cast=float):
    try:
        return cast(os.environ.get(name, "") or default)
    except ValueError:
        return cast(default)


# Open by default — no API key required.
# Set API_KEY env var to enable authentication.
API_KEY = os.environ.get("API_KEY", "").strip()
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "").strip().rstrip("/")
RATE_PER_MIN = _env_num("RATE_LIMIT_PER_MIN", 20, int)
BUDGET_S = _env_num("TIME_BUDGET_S", 45, float)

MODES = {
    "full": [],                                                                 # contacts the target
    "passive": ["fetch", "favicon"],                                            # never contacts the target
    "offline": ["fetch", "favicon", "dns", "whois", "intel", "history"],        # static analysis only
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8192
_hits, _lock = defaultdict(deque), threading.Lock()


def _json(obj, status=200):
    return Response(json.dumps(obj, default=str, ensure_ascii=False), status=status, mimetype="application/json")


def _err(status, msg):
    return _json({"error": msg}, status)


def _client_ip():
    return (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or request.headers.get("x-real-ip") or request.remote_addr or "?")


def _rate_wait(ip):
    """Seconds to wait if over the limit, else 0. Per-instance memory: pair with a Vercel Firewall rate-limit rule."""
    now = time.monotonic()
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_PER_MIN:
            return int(60 - (now - q[0])) + 1
        q.append(now)
        if len(_hits) > 5000:
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > 60]:
                _hits.pop(k, None)
    return 0


def _auth_error():
    # No authentication required - open by default
    return None


@app.after_request
def _headers(resp):
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        origin = request.headers.get("Origin")
        if ALLOWED_ORIGIN and origin == ALLOWED_ORIGIN:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Headers"] = "content-type, x-api-key, authorization"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            resp.headers["Vary"] = "Origin"
    return resp


@app.route("/api/health")
def health():
    return _json({"ok": True, "version": ua.__version__,
                  "configured": True, "auth_required": bool(API_KEY),
                  "intel_keys": {"virustotal": bool(os.environ.get("VT_API_KEY")),
                                 "safe_browsing": bool(os.environ.get("GSB_API_KEY")),
                                 "urlhaus": bool(os.environ.get("URLHAUS_AUTH_KEY"))}})


@app.route("/api/analyze", methods=["GET", "POST"])
def analyze():
    wait = _rate_wait(_client_ip())
    if wait:
        r = _err(429, "Rate limit exceeded. Try again in %ds." % wait)
        r.headers["Retry-After"] = str(wait)
        return r
    bad = _auth_error()
    if bad:
        return bad
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        url, mode = data.get("url"), data.get("mode", "full")
    else:
        url, mode = request.args.get("url"), request.args.get("mode", "full")
    if not isinstance(url, str) or not url.strip():
        return _err(400, "Provide a 'url'.")
    url = url.strip()
    if len(url) > 2048:
        return _err(400, "URL too long (max 2048 characters).")
    if mode not in MODES:
        return _err(400, "mode must be one of: %s" % ", ".join(MODES))
    opts = argparse.Namespace(skip=MODES[mode], max_redirects=8, default_scheme="https", budget=BUDGET_S)
    try:
        report = ua.analyze(url, opts)
    except ValueError as e:
        return _err(400, str(e))
    except Exception:
        app.logger.exception("analysis failed")
        return _err(500, "Internal error while analysing the URL.")
    report["mode"] = mode
    return _json(report)


@app.route("/")
def index():  # on Vercel the CDN serves public/index.html first; this is for local runs
    return send_from_directory(os.path.join(os.path.dirname(os.path.abspath(__file__)), "public"), "index.html")


if __name__ == "__main__":
    app.run(port=int(os.environ.get("PORT", "5000")), debug=False)
