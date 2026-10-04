#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
url_analyzer.py - URL analyzer for phishing / malware triage and OSINT

What it does
  parse      full URL breakdown, IDN/punycode, obfuscated-IP decoding, tracking-param stripping,
             refang (hxxp / [.]) on input and defang on output
  lexical    phishing heuristics: brand impersonation, typosquats, homoglyphs, suspicious TLDs,
             shorteners, '@' tricks, open-redirect params, risky extensions, DGA-like names ...
  redirects  hop-by-hop trace (HTTP, meta-refresh, JS stubs) with per-hop IP / TLS / cross-domain info;
             the destination URL is re-analysed too (so shorteners can't hide anything)
  network    IPs, CNAME/NS, reverse DNS, ASN + prefix (Team Cymru), geolocation, free-hosting / tunnel hints
  whois      RDAP via IANA bootstrap: domain age, registrar, expiry, status
  tls        certificate details from the real connection: issuer, validity, SANs, hostname match
  http       status, headers, security-header audit (hygiene), cookies, technology / CDN hints
  content    forms (credential / card fields, cross-domain posts), deceptive links, hidden iframes,
             JS obfuscation signals, brand-vs-domain mismatch, file sniffing, IOC extraction (emails,
             crypto addresses, Telegram / WhatsApp, tracker IDs), favicon hash (Shodan-compatible mmh3)
  intel      VirusTotal, Google Safe Browsing, URLhaus (need API keys in env), OpenPhish community feed
  history    first Wayback Machine capture of the host
  verdict    0-100 heuristic suspicion score with an itemised, explainable breakdown

Safety notes
  * Nothing from the page is ever executed - HTML is parsed, not rendered. Body size is capped.
  * The target SEES your IP and user-agent when it is fetched. For suspicious links use a VM / VPN, or run
    with --passive (never contacts the target) or --offline (no network at all).
  * Private / loopback / link-local destinations are blocked by default (SSRF guard); --allow-private overrides.
  * The score is a triage aid, not proof. Brand and keyword heuristics produce false positives.

Install: standard library only (no dependencies).

API keys (optional, via environment variables - the URL is sent to that service when a key is set):
  VT_API_KEY, GSB_API_KEY, URLHAUS_AUTH_KEY

Examples
  python url_analyzer.py https://bit.ly/abc123
  python url_analyzer.py "hxxps://paypa1-secure[.]com/login" --passive
  python url_analyzer.py -l urls.txt --json -o results.json
  python url_analyzer.py https://example.com --offline          # static analysis only
  python url_analyzer.py https://example.com --fail-on high     # exit code 3 for CI / scripts
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import hashlib
import html as htmllib
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import warnings
import zlib
from collections import Counter
from functools import lru_cache
from html.parser import HTMLParser

__version__ = "1.0.0"

CFG = {
    "timeout": 10.0,
    "max_bytes": 1_500_000,
    "allow_private": False,
    "verify": True,
    "allowed_ports": None,   # e.g. {80, 443} for a public deployment (stops port-scanning via the tool)
    "cli": False,
    "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
}
REDIRECT_CODES = (301, 302, 303, 307, 308)
_LOCAL = threading.local()   # per-request deadline (set by analyze() when opts.budget is given)


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
magenta = lambda s: Style.c("35", s)


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%d %H:%M:%SZ") if d else None


def parse_dt(s):
    if not s:
        return None
    s = str(s).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        d = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y%m%d%H%M%S"):
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


def uniq(seq):
    return list(dict.fromkeys(seq))


def short_err(e):
    s = str(getattr(e, "reason", e) or e).strip()
    return s.splitlines()[0][:200] if s else type(e).__name__


def trunc(s, n=120):
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "..."


def sev_of(w):
    return "critical" if w >= 60 else "high" if w >= 25 else "medium" if w >= 10 else "low" if w >= 3 else "info"


class Findings:
    def __init__(self):
        self.items = []

    def add(self, module, weight, msg, **extra):
        d = {"module": module, "weight": weight, "severity": sev_of(weight), "message": msg}
        d.update(extra)
        self.items.append(d)


class FetchError(Exception):
    def __init__(self, msg, cert_error=False):
        super().__init__(msg)
        self.cert_error = cert_error


# ----------------------------------------------------------------------------
# Reference data
# ----------------------------------------------------------------------------
MULTI_SUFFIXES = set("""
co.uk org.uk me.uk ltd.uk plc.uk ac.uk gov.uk net.uk sch.uk com.au net.au org.au edu.au gov.au co.nz org.nz
co.za org.za com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn com.hk com.sg com.my com.tw com.tr com.mx
com.ar com.co com.pk com.bd com.np com.lk com.ng com.eg com.sa com.ua co.jp ne.jp or.jp ac.jp co.kr or.kr co.id
or.id co.th in.th co.il org.il co.ke co.in net.in org.in firm.in gen.in ind.in ac.in edu.in res.in gov.in nic.in mil.in
""".split())

BRANDS = {
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "windows.com", "bing.com", "msn.com", "skype.com", "xbox.com", "azure.com", "office365.com", "onedrive.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "goo.gl", "google.co.in", "googleusercontent.com", "withgoogle.com", "youtu.be"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.ca", "amazonaws.com", "amzn.to", "amzn.com", "a.co"],
    "facebook": ["facebook.com", "fb.com", "fb.me", "messenger.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "telegram": ["telegram.org", "t.me", "telegram.me"],
    "twitter": ["twitter.com", "x.com", "t.co"],
    "linkedin": ["linkedin.com", "lnkd.in"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "ebay": ["ebay.com", "ebay.in", "ebay.co.uk"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
    "adobe": ["adobe.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
    "spotify": ["spotify.com"],
    "snapchat": ["snapchat.com"],
    "dhl": ["dhl.com"], "fedex": ["fedex.com"], "ups": ["ups.com"], "usps": ["usps.com"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"], "hsbc": ["hsbc.com", "hsbc.co.in"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfclife.com"],
    "hdfcbank": ["hdfcbank.com"],
    "icici": ["icicibank.com", "icicidirect.com", "iciciprulife.com"],
    "icicibank": ["icicibank.com"],
    "axisbank": ["axisbank.com"], "kotak": ["kotak.com"],
    "paytm": ["paytm.com", "paytmbank.com"], "phonepe": ["phonepe.com"], "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"], "uidai": ["uidai.gov.in"], "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"], "digilocker": ["digilocker.gov.in"], "npci": ["npci.org.in"],
    "jio": ["jio.com"], "airtel": ["airtel.in"], "myntra": ["myntra.com"], "zomato": ["zomato.com"],
    "swiggy": ["swiggy.com"], "razorpay": ["razorpay.com"],
}
KEYWORDS = ["login", "signin", "verify", "verification", "secure", "security", "account",
            "update", "confirm", "banking", "wallet", "password", "passwd", "credential", "authenticate", "billing",
            "invoice", "payment", "suspend", "unlock", "recover", "recovery", "support", "helpdesk", "alert",
            "urgent", "limited", "reward", "prize", "giveaway", "claim", "bonus", "refund", "kyc", "otp",
            "bank", "free", "crypto", "airdrop", "webmail", "docusign", "validate", "restore", "reactivate"]
SUS_TLDS = set("""tk ml ga cf gq xyz top icu cyou click link zip mov rest fit buzz cam monster sbs bond work support
country kim loan men party review science stream trade win date download racing accountant cricket faith bid gdn
vip pw su cc ws lol quest cfd""".split())
SHORTENERS = set("""bit.ly tinyurl.com t.co goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at tiny.cc rb.gy bl.ink
t.ly v.gd s.id shorte.st adf.ly bitly.com qr.ae soo.gd clck.ru ift.tt amzn.to lnkd.in fb.me trib.al
rotf.lt zpr.io 1url.com tr.ee tny.im urlz.fr hyperurl.co""".split())
DANGEROUS_EXT = {"exe", "scr", "bat", "cmd", "com", "msi", "ps1", "vbs", "vbe", "js", "jse", "jar", "apk", "dmg", "pkg",
                 "iso", "img", "lnk", "hta", "dll", "docm", "xlsm", "pptm", "wsf", "reg", "cpl", "msix", "appx"}
ARCHIVE_EXT = {"zip", "rar", "7z", "cab", "gz", "tar", "z", "ace"}
FREE_HOSTS = ("000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com", "github.io", "gitlab.io", "netlify.app",
              "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "herokuapp.com", "glitch.me",
              "repl.co", "replit.app", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org", "no-ip.org",
              "no-ip.com", "hopto.org", "zapto.org", "serveo.net", "onrender.com", "fly.dev", "surge.sh",
              "webflow.io", "carrd.co", "godaddysites.com", "square.site", "mystrikingly.com", "bubbleapps.io",
              "framer.website", "lovable.app", "sites.google.com", "r2.dev")
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirect_url", "redir", "next", "return", "returnto", "return_to",
                   "goto", "dest", "destination", "continue", "link", "target", "forward", "u", "r", "out", "callback"}
TRACKING_PARAMS = {"fbclid", "gclid", "dclid", "msclkid", "mc_eid", "mc_cid", "igshid", "yclid", "_hsenc", "_hsmi",
                   "ref_src", "ref_url", "spm", "gbraid", "wbraid", "ttclid", "twclid", "li_fat_id", "vero_id",
                   "mkt_tok", "oly_enc_id", "oly_anon_id", "_ga", "s_cid", "cmpid", "igshid", "si"}
COMMON_TLD_LABELS = {"com", "net", "org", "gov", "edu", "co", "in", "io"}
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ɡ": "g", "ο": "o", "ν": "v", "ι": "i", "α": "a", "ρ": "p", "ӏ": "l", "һ": "h", "ԛ": "q", "ɑ": "a", "ǝ": "e",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "ᴅ": "d", "ℓ": "l", "０": "0", "１": "1",
}


# ----------------------------------------------------------------------------
# URL parsing
# ----------------------------------------------------------------------------
_IPV4_ODD = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)


def refang(s):
    s = (s or "").strip().strip("<>\"'`")
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[://]", "://"),
                 ("[:]", ":"), ("[@]", "@"), ("[/]", "/")):
        s = s.replace(a, b)
    return re.sub(r"^hxxp(s?)(?=:)", r"http\1", s, flags=re.I)


def defang(url):
    p = urllib.parse.urlsplit(url)
    host = (p.netloc or "").replace(".", "[.]")
    scheme = {"http": "hxxp", "https": "hxxps"}.get(p.scheme, p.scheme)
    return "%s://%s%s%s" % (scheme, host, p.path, ("?" + p.query) if p.query else "")


def classify_host(host):
    try:
        ip = ipaddress.ip_address(host)
        return ("ipv6" if ip.version == 6 else "ipv4", str(ip))
    except ValueError:
        pass
    if _IPV4_ODD.match(host):
        try:
            return ("ipv4-obfuscated", socket.inet_ntoa(socket.inet_aton(host)))
        except OSError:
            pass
    return (None, None)


def registrable_of(host):
    if not host:
        return host
    if classify_host(host)[0]:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _blank():
    return {"input": None, "scheme": None, "fetchable": False, "url": None, "fetch_url": None, "host": None,
            "unicode_host": None, "port": None, "path": "", "query": "", "fragment": "", "username": None,
            "has_userinfo": False, "host_kind": None, "ip_normalized": None, "registrable": None, "suffix": None,
            "sld": None, "subdomain": "", "subdomain_count": 0, "is_idn": False, "params": [], "clean_url": None,
            "defanged": None, "length": 0, "pct_encoded": 0, "double_encoded": False, "ext": None, "notes": [],
            "backslash": False}


def parse_url(raw, default_scheme="https"):
    s = refang(raw)
    if not s:
        raise ValueError("empty input")
    U = _blank()
    U["input"], U["length"] = raw, len(s)
    if s.startswith("//"):
        s = default_scheme + ":" + s
        U["notes"].append("protocol-relative URL, assumed %s" % default_scheme)
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", s) or re.match(r"^[A-Za-z0-9.-]+:\d+(?:[/?#]|$)", s):
        s = default_scheme + "://" + s
        U["notes"].append("no scheme given, assumed %s" % default_scheme)
    try:
        p = urllib.parse.urlsplit(s)
    except ValueError as e:
        raise ValueError("unparseable URL: %s" % e)
    U["scheme"] = p.scheme.lower()
    if U["scheme"] not in ("http", "https"):
        U["url"] = s
        U["defanged"] = s.replace(".", "[.]")
        return U
    try:
        port = p.port
    except ValueError:
        raise ValueError("invalid port in URL")
    host = (p.hostname or "").rstrip(".")
    if not host:
        raise ValueError("URL has no host")
    try:
        ascii_host = host.encode("idna").decode("ascii") if not host.isascii() or "xn--" in host else host
        uni = ascii_host.encode("ascii").decode("idna") if "xn--" in ascii_host else host
    except UnicodeError:
        raise ValueError("invalid internationalised host name")
    U["backslash"] = "\\" in p.netloc
    U["has_userinfo"] = "@" in p.netloc
    U["username"] = urllib.parse.unquote(p.username or "") + (":" + urllib.parse.unquote(p.password) if p.password else "")
    kind, ipn = classify_host(ascii_host)
    reg = registrable_of(ascii_host)
    labels = reg.split(".") if not kind else [reg]
    sub = ascii_host[: -len(reg) - 1] if (not kind and ascii_host != reg) else ""
    qs = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    clean_q = [(k, v) for k, v in qs if not (k.lower().startswith("utm_") or k.lower() in TRACKING_PARAMS)]
    hostpart = "[%s]" % ascii_host if kind == "ipv6" else ascii_host
    netloc = hostpart + (":%d" % port if port else "")
    path = urllib.parse.quote(p.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = urllib.parse.quote(p.query, safe="/%:@!$&'()*+,;=-._~?")
    last = path.rsplit("/", 1)[-1]
    U.update(
        url=urllib.parse.urlunsplit((U["scheme"], netloc, path, query, "")), fetchable=True,
        host=ascii_host, unicode_host=uni, port=port, path=p.path or "/", query=p.query, fragment=p.fragment,
        host_kind=kind, ip_normalized=ipn, registrable=reg, suffix=(".".join(labels[1:]) if not kind else None),
        sld=(labels[0] if not kind else None), subdomain=sub, subdomain_count=len(sub.split(".")) if sub else 0,
        is_idn=(uni != ascii_host) or any(l.startswith("xn--") for l in ascii_host.split(".")),
        params=qs, ext=(last.rsplit(".", 1)[-1].lower() if "." in last else None),
        pct_encoded=len(re.findall(r"%[0-9a-fA-F]{2}", p.path + p.query)),
        double_encoded=bool(re.search(r"%25[0-9a-fA-F]{2}", p.path + p.query)),
    )
    U["fetch_url"] = U["url"]
    U["clean_url"] = urllib.parse.urlunsplit((U["scheme"], netloc, path, urllib.parse.urlencode(clean_q), ""))
    U["defanged"] = defang(U["url"])
    return U


# ----------------------------------------------------------------------------
# Lexical / heuristic analysis
# ----------------------------------------------------------------------------
def shannon(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def levenshtein(a, b, cap=3):
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def scripts_in(label):
    out = set()
    for ch in label:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                pass
    return out


def skeletons(token):
    t = "".join(CONFUSABLES.get(ch, ch) for ch in unicodedata.normalize("NFKC", token))
    t = t.replace("rn", "m").replace("vv", "w")
    base = t.translate(str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"}))
    return {base.replace("1", "l"), base.replace("1", "i"), t}


def is_legit(reg, legit):
    return reg in legit


def brand_findings(U, F, label):
    reg, sub, sld = U["registrable"], U["subdomain"], U["sld"] or ""
    host_wo_suffix = (sub + "." if sub else "") + sld
    host_tokens = [t for t in re.split(r"[^a-z0-9\u0080-\uffff]+", U["unicode_host"].lower().replace(U["suffix"] or "\0", "")) if t]
    path_blob = urllib.parse.unquote(U["path"] + " " + U["query"]).lower()
    path_tokens = [t for t in re.split(r"[^a-z0-9]+", path_blob) if t]
    seen = set()
    for brand, legit in BRANDS.items():
        if is_legit(reg, legit) or legit[0] in seen:
            continue
        in_host = brand in host_tokens or (len(brand) >= 5 and any(t.startswith(brand) for t in host_tokens))
        in_path = brand in path_tokens or (len(brand) >= 5 and any(t.startswith(brand) for t in path_tokens))
        homoglyph = any(brand in skeletons(t) and t != brand for t in host_tokens if len(brand) >= 4)
        typo = len(brand) >= 5 and any(0 < levenshtein(t, brand, 2) <= (2 if len(brand) >= 8 else 1)
                                       for t in host_tokens if len(t) >= 4)
        if homoglyph:
            F.add("url", 35, "%sHomoglyph / leet-speak imitation of '%s' in the host name" % (label, brand), brand=brand)
        elif typo:
            F.add("url", 30, "%sHost looks like a typo-squat of '%s' (official: %s)" % (label, brand, legit[0]), brand=brand)
        elif in_host:
            F.add("url", 25, "%sBrand '%s' used in the host name but the domain is %s (official: %s)" % (label, brand, reg, legit[0]), brand=brand)
        elif in_path:
            F.add("url", 10, "%sBrand '%s' appears in the URL path of an unrelated domain (%s)" % (label, brand, reg), brand=brand)
        else:
            continue
        seen.add(legit[0])
        if len(seen) >= 3:
            break


def lexical(U, F, label=""):
    L = lambda w, m, **k: F.add("url", w, label + m, **k)
    sch = U["scheme"]
    if sch in ("data", "javascript", "vbscript", "file"):
        return L(50, "Dangerous URL scheme '%s:'" % sch)
    if not U["fetchable"]:
        return L(0, "Non-web scheme '%s:' - not analysed further" % sch)
    host, reg, kind = U["host"], U["registrable"], U["host_kind"]
    if kind == "ipv4-obfuscated":
        L(30, "Obfuscated IP address in host (%s = %s)" % (host, U["ip_normalized"]))
    elif kind:
        L(15, "IP address used instead of a domain name (%s)" % host)
    if U["has_userinfo"]:
        if re.search(r"[a-z0-9-]+\.[a-z]{2,}", U["username"].lower()):
            L(35, "'user@host' trick: the text before '@' looks like a domain but the real host is %s" % host)
        else:
            L(10, "URL contains credentials / userinfo before the host")
    if U["backslash"]:
        L(30, "Backslash in the authority part (browsers may route to a different host than parsers)")
    if U["is_idn"]:
        mixed = [l for l in U["unicode_host"].split(".") if len(scripts_in(l)) > 1]
        if mixed:
            L(30, "Mixed-script label(s) in host (homograph attack): %s" % ", ".join(mixed))
        else:
            L(10, "Internationalised domain (punycode): %s" % U["host"])
    if U["suffix"] and U["suffix"].rsplit(".", 1)[-1] in SUS_TLDS:
        L(8, "TLD .%s is heavily abused for throw-away domains" % U["suffix"].rsplit(".", 1)[-1])
    if reg in SHORTENERS:
        L(5, "URL shortener (%s) - destination is hidden until the redirect is followed" % reg)
    fh = next((f for f in FREE_HOSTS if host == f or host.endswith("." + f)), None)
    if fh:
        L(5, "Hosted on a free / shared / tunnelling platform (%s) - often abused, not malicious by itself" % fh)
    if not kind:
        brand_findings(U, F, label)
        sld = U["sld"] or ""
        tokens = [t for t in re.split(r"[^a-z0-9]+", (U["unicode_host"] + " " + urllib.parse.unquote(U["path"])).lower()) if t]
        blob = " ".join(tokens)
        hits = uniq(k for k in KEYWORDS if (k in blob.replace("-", "") if len(k) >= 5 else k in tokens))
        if len(hits) >= 3:
            L(15, "Several credential / urgency keywords: %s" % ", ".join(hits[:6]))
        elif hits:
            L(3, "Sensitive keyword(s): %s" % ", ".join(hits))
        if U["subdomain_count"] >= 4:
            L(8, "Very deep subdomain chain (%d labels)" % U["subdomain_count"])
        elif U["subdomain_count"] == 3:
            L(3, "Deep subdomain chain (3 labels)")
        if U["subdomain"]:
            sl = U["subdomain"].split(".")
            if any(l in COMMON_TLD_LABELS for l in sl[1:]) or (len(sl) >= 2 and sl[-1] in COMMON_TLD_LABELS):
                L(20, "A domain name is embedded in the subdomain (%s) to mimic another site; real domain is %s" % (U["subdomain"], reg))
        hy = U["unicode_host"].count("-")
        if hy >= 3:
            L(5, "Many hyphens in host name (%d)" % hy)
        if len(sld) >= 10 and shannon(sld) >= 3.6 and (sum(ch.isdigit() for ch in sld) >= 3 or
                                                      sum(ch in "aeiou" for ch in sld) / len(sld) < 0.25):
            L(8, "Random-looking domain label '%s' (possible generated name)" % sld)
    if U["port"] and U["port"] not in (80, 443):
        L(8, "Non-standard port %d" % U["port"])
    if U["length"] >= 200:
        L(8, "Very long URL (%d characters)" % U["length"])
    elif U["length"] >= 100:
        L(3, "Long URL (%d characters)" % U["length"])
    if U["pct_encoded"] >= 10 or U["double_encoded"]:
        L(5, "Heavy or double percent-encoding (%d sequences)" % U["pct_encoded"])
    path_q = urllib.parse.unquote(U["path"] + "?" + U["query"])
    if re.search(r"https?://", U["path"] + U["query"], re.I) or re.search(r"https?://", path_q, re.I):
        for k, v in U["params"]:
            if re.match(r"(?:https?:)?//", urllib.parse.unquote(v), re.I):
                L(8, "Open-redirect style parameter '%s' carries a URL: %s" % (k, trunc(urllib.parse.unquote(v), 80)))
                break
        else:
            L(10, "Another URL is embedded in the path / query")
    elif any(k.lower() in REDIRECT_PARAMS and re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", urllib.parse.unquote(v), re.I) for k, v in U["params"]):
        L(5, "Redirect-style parameter pointing at a domain name")
    if re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", path_q):
        L(5, "E-mail address inside the URL (typical of per-victim phishing links)")
    if any(len(v) >= 60 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", v) for _, v in U["params"]):
        L(3, "Long encoded token in a query parameter")
    if U["ext"] in DANGEROUS_EXT:
        L(20, "URL points at an executable / script file type (.%s)" % U["ext"])
    elif U["ext"] in ARCHIVE_EXT:
        L(8, "URL points at an archive (.%s)" % U["ext"])
    if U["scheme"] == "http":
        L(5, "Plain HTTP URL (no transport encryption)")


# ----------------------------------------------------------------------------
# HTTP client with SSRF guard (stdlib sockets; one connection per hop)
# ----------------------------------------------------------------------------
def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _ip_public(ip_str):
    ip = ipaddress.ip_address(ip_str.split("%")[0])
    if ip.version == 6:
        inner = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if inner is not None:
            ip = inner
    return ip.is_global and not ip.is_multicast


def _resolve(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FetchError("DNS resolution failed: %s" % (e.strerror or e))
    except UnicodeError:
        raise FetchError("invalid host name")
    ips = uniq(i[4][0] for i in infos)
    if not CFG["allow_private"]:
        bad = [ip for ip in ips if not _ip_public(ip)]
        if bad:
            raise FetchError("blocked by SSRF guard: %s resolves to non-public address %s%s" %
                             (host, bad[0], " (use --allow-private to override)" if CFG.get("cli") else ""))
    return ips


def _decode_body(body, enc):
    enc = (enc or "").lower()
    cap = CFG["max_bytes"]
    try:
        if "gzip" in enc:
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, cap)
        if "deflate" in enc:
            try:
                return zlib.decompressobj().decompress(body, cap)
            except zlib.error:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body, cap)
    except zlib.error:
        pass
    return body


def fetch_once(url, verify=True, max_bytes=None, accept="text/html,application/xhtml+xml,*/*;q=0.8"):
    max_bytes = CFG["max_bytes"] if max_bytes is None else max_bytes
    p = urllib.parse.urlsplit(url)
    scheme, host = p.scheme.lower(), p.hostname
    if scheme not in ("http", "https") or not host:
        raise FetchError("unsupported URL")
    try:
        port = p.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise FetchError("invalid port")
    if CFG.get("allowed_ports") and port not in CFG["allowed_ports"]:
        raise FetchError("blocked: port %d is not allowed on this deployment" % port)
    timeout, dl = CFG["timeout"], getattr(_LOCAL, "deadline", None)
    if dl is not None:
        rem = dl - time.monotonic()
        if rem < 1.0:
            raise FetchError("time budget exhausted")
        timeout = min(timeout, rem)
    ips = _resolve(host, port)
    t0 = time.perf_counter()
    sock, ip, last = None, None, None
    for cand in ips[:4]:
        try:
            sock, ip = socket.create_connection((cand, port), timeout=timeout), cand
            break
        except OSError as e:
            last = e
    if sock is None:
        raise FetchError("connection failed: %s" % short_err(last))
    tls = None
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=None if _is_ip(host) else host)
            except ssl.SSLCertVerificationError as e:
                raise FetchError(getattr(e, "verify_message", None) or short_err(e), cert_error=True) from None
            except (ssl.SSLError, OSError) as e:
                raise FetchError("TLS error: %s" % short_err(e)) from None
            c = sock.cipher() or (None, None, None)
            tls = {"version": sock.version(), "cipher": c[0], "bits": c[2], "verified": verify, "verify_error": None,
                   "der": sock.getpeercert(binary_form=True), "cert": sock.getpeercert() or None}
        conn = (http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection)(host, port, timeout=timeout)
        conn.sock = sock
        target = (p.path or "/") + ("?" + p.query if p.query else "")
        conn.request("GET", target, headers={"User-Agent": CFG["ua"], "Accept": accept,
                                             "Accept-Language": "en-US,en;q=0.9", "Connection": "close"})
        resp = conn.getresponse()
        status, headers = resp.status, resp.getheaders()
        ms = round((time.perf_counter() - t0) * 1000)
        body, trunc_flag = b"", False
        if status not in REDIRECT_CODES and status not in (204, 304):
            chunks, got, hard = [], 0, time.monotonic() + timeout * 2   # total cap stops slow-drip servers
            try:
                while got <= max_bytes and time.monotonic() < hard:
                    c = resp.read1(min(65536, max_bytes + 1 - got))
                    if not c:
                        break
                    chunks.append(c)
                    got += len(c)
            except http.client.IncompleteRead as e:
                chunks.append(e.partial)
            except (OSError, http.client.HTTPException):
                pass
            body = b"".join(chunks)
            if len(body) > max_bytes:
                body, trunc_flag = body[:max_bytes], True
        hd = {}
        for k, v in headers:
            hd.setdefault(k.lower(), v)
        body = _decode_body(body, hd.get("content-encoding"))
        return {"url": url, "status": status, "reason": resp.reason, "headers": headers, "hdr": hd, "body": body,
                "truncated": trunc_flag, "ms": ms, "ip": ip, "tls": tls, "http_version": "1.%d" % (resp.version - 10)}
    except FetchError:
        raise
    except (OSError, http.client.HTTPException) as e:
        raise FetchError(short_err(e)) from None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fetch_hop(url, **kw):
    try:
        return fetch_once(url, verify=CFG["verify"], **kw)
    except FetchError as e:
        if e.cert_error and CFG["verify"]:
            r = fetch_once(url, verify=False, **kw)
            if r["tls"]:
                r["tls"]["verified"], r["tls"]["verify_error"] = False, str(e)
            return r
        raise


def api_json(url, method="GET", headers=None, json_body=None, form=None, timeout=None, max_bytes=8_000_000):
    data, hdrs = None, {"User-Agent": "url-analyzer/%s" % __version__, "Accept": "application/json"}
    if json_body is not None:
        data, hdrs["Content-Type"] = json.dumps(json_body).encode(), "application/json"
    elif form is not None:
        data, hdrs["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        try:
            resp = urllib.request.urlopen(req, timeout=timeout or CFG["timeout"])
            status, body = resp.status, resp.read(max_bytes)
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read(1_000_000)
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError) as e:
        raise FetchError(short_err(e)) from None
    text = body.decode("utf-8", "replace")
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


# ----------------------------------------------------------------------------
# DNS over HTTPS, ASN, geo, RDAP
# ----------------------------------------------------------------------------
RTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}


@lru_cache(maxsize=1024)
def doh(name, rtype):
    for ep in ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"):
        try:
            st, d = api_json("%s?%s" % (ep, urllib.parse.urlencode({"name": name, "type": rtype})),
                             headers={"Accept": "application/dns-json"})
        except FetchError:
            continue
        if not isinstance(d, dict):
            continue
        vals = []
        for a in d.get("Answer") or []:
            if a.get("type") == RTYPE_NUM[rtype]:
                v = a.get("data", "")
                if rtype == "TXT":
                    v = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', v)) or v.strip('"')
                elif rtype in ("NS", "CNAME", "PTR", "MX"):
                    v = v.rstrip(".")
                vals.append(v)
        return vals
    return []


def asn_lookup(ip):
    a = ipaddress.ip_address(ip)
    rp = a.reverse_pointer
    q = (rp[:-len(".in-addr.arpa")] + ".origin.asn.cymru.com") if a.version == 4 else \
        (rp[:-len(".ip6.arpa")] + ".origin6.asn.cymru.com")
    vals = doh(q, "TXT")
    if not vals:
        return None
    p = [x.strip() for x in vals[0].split("|")]
    asns = p[0].split()
    out = {"asn": ["AS" + x for x in asns], "prefix": p[1] if len(p) > 1 else None,
           "country": p[2] if len(p) > 2 else None, "registry": p[3] if len(p) > 3 else None, "name": None}
    if asns:
        nm = doh("AS%s.asn.cymru.com" % asns[0], "TXT")
        if nm:
            q2 = [x.strip() for x in nm[0].split("|")]
            out["name"] = q2[4] if len(q2) > 4 else None
    return out


def geo_lookup(ip):
    try:
        st, d = api_json("https://ipwho.is/%s" % ip)
    except FetchError as e:
        return {"error": str(e)}
    if not isinstance(d, dict) or d.get("success") is False:
        return {"error": (d or {}).get("message", "lookup failed") if isinstance(d, dict) else "lookup failed"}
    conn = d.get("connection") or {}
    return {"country": d.get("country"), "region": d.get("region"), "city": d.get("city"),
            "timezone": (d.get("timezone") or {}).get("id"), "isp": conn.get("isp"), "org": conn.get("org")}


def ip_profile(ip):
    a = ipaddress.ip_address(ip)
    prof = {"ip": ip, "global": a.is_global}
    if not a.is_global:
        return prof
    with cf.ThreadPoolExecutor(3) as ex:
        f1, f2, f3 = ex.submit(doh, a.reverse_pointer, "PTR"), ex.submit(asn_lookup, ip), ex.submit(geo_lookup, ip)
        prof["ptr"], prof["asn"], prof["geo"] = f1.result(), f2.result(), f3.result()
    return prof


def mod_network(U, host, F, extra_ips=()):
    out = {"host": host, "ips": [], "cname": [], "ns": [], "addresses": []}
    kind, ipn = classify_host(host)
    if kind:
        ips = [ipn]
    else:
        try:
            ips = uniq(i[4][0] for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM))
        except socket.gaierror as e:
            out["error"] = "does not resolve (%s)" % (e.strerror or e)
            F.add("network", 3, "Host %s does not resolve (taken down, mistyped or not yet live)" % host)
            return out
    ips = uniq(list(ips) + [x for x in extra_ips if x])[:6]
    out["ips"] = ips
    if not kind:
        with cf.ThreadPoolExecutor(2) as ex:
            f1, f2 = ex.submit(doh, host, "CNAME"), ex.submit(doh, registrable_of(host), "NS")
            out["cname"], out["ns"] = f1.result(), f2.result()
    with cf.ThreadPoolExecutor(3) as ex:
        out["addresses"] = list(ex.map(ip_profile, ips))
    for a in out["addresses"]:
        if not a["global"]:
            F.add("network", 10, "%s resolves to a non-public address (%s)" % (host, a["ip"]))
    return out


@lru_cache(maxsize=1)
def _rdap_bootstrap():
    st, d = api_json("https://data.iana.org/rdap/dns.json")
    return d.get("services", []) if isinstance(d, dict) else []


def mod_whois(reg, F):
    if _is_ip(reg) or "." not in reg:
        return {"skipped": "not a registrable domain"}
    tld, base = reg.rsplit(".", 1)[-1], "https://rdap.org/"
    try:
        for tlds, urls in _rdap_bootstrap():
            if tld in tlds and urls:
                base = sorted(urls, key=lambda u: not u.startswith("https"))[0].rstrip("/") + "/"
                break
    except FetchError:
        pass
    try:
        st, d = api_json(base + "domain/" + reg, headers={"Accept": "application/rdap+json"})
    except FetchError as e:
        return {"error": "RDAP failed: %s" % e}
    if st >= 400 or not isinstance(d, dict):
        return {"error": "RDAP returned HTTP %s" % st}
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) or []}
    registrar = None
    redacted = False
    for ent in d.get("entities", []) or []:
        card = {i[0]: i[3] for i in (ent.get("vcardArray") or [None, []])[1] if len(i) >= 4}
        if "registrar" in ent.get("roles", []):
            registrar = card.get("fn")
        if any("redact" in str(v).lower() or "privacy" in str(v).lower() for v in card.values()):
            redacted = True
    created, expires = parse_dt(ev.get("registration")), parse_dt(ev.get("expiration"))
    now = now_utc()
    out = {"domain": d.get("ldhName"), "registrar": registrar, "status": d.get("status", []),
           "created": iso(created), "updated": iso(parse_dt(ev.get("last changed"))), "expires": iso(expires),
           "age_days": (now - created).days if created else None,
           "days_to_expiry": (expires - now).days if expires else None, "privacy_redacted": redacted,
           "nameservers": sorted({(n.get("ldhName") or "").lower() for n in d.get("nameservers", []) or []})}
    age = out["age_days"]
    if age is not None:
        if age < 7:
            F.add("whois", 35, "Domain registered only %d day(s) ago" % age)
        elif age < 30:
            F.add("whois", 25, "Domain registered %d days ago (very new)" % age)
        elif age < 90:
            F.add("whois", 10, "Domain registered %d days ago (new)" % age)
        elif age < 365:
            F.add("whois", 3, "Domain is under a year old (%d days)" % age)
    if out["days_to_expiry"] is not None and out["days_to_expiry"] < 0:
        F.add("whois", 5, "Domain registration has expired")
    return out


# ----------------------------------------------------------------------------
# TLS certificate (from the same connection used for the request)
# ----------------------------------------------------------------------------
def _decode_cert_der(der):
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
    return any(n.lower() == host or (n.lower().startswith("*.") and "." in host and host.split(".", 1)[1] == n.lower()[2:])
               for n in names)


def mod_tls(tls, host, F):
    if not tls:
        return None
    der = tls["der"]
    cert = tls["cert"] or _decode_cert_der(der)
    out = {"version": tls["version"], "cipher": tls["cipher"], "bits": tls["bits"], "verified": tls["verified"],
           "verify_error": tls["verify_error"], "sha256": ":".join("%02X" % b for b in hashlib.sha256(der).digest()) if der else None}
    if tls["verify_error"]:
        F.add("tls", 20, "Certificate failed validation: %s" % tls["verify_error"])
    if not cert:
        return out
    subj, iss = _rdn(cert.get("subject")), _rdn(cert.get("issuer"))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    nb = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), dt.timezone.utc)
    na = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    names = sans or ([subj["commonName"]] if "commonName" in subj else [])
    match = True if tls["verified"] else (None if _is_ip(host) else _host_matches(host, names))
    now = now_utc()
    out.update(subject_cn=subj.get("commonName"), issuer_cn=iss.get("commonName"), issuer_org=iss.get("organizationName"),
               valid_from=iso(nb), valid_to=iso(na), days_left=(na - now).days, age_days=(now - nb).days,
               sans=sans, wildcard=any(s.startswith("*.") for s in sans), hostname_match=match,
               self_signed=bool(subj) and subj == iss, serial=cert.get("serialNumber"))
    if out["self_signed"]:
        F.add("tls", 15, "Self-signed certificate")
    if match is False:
        F.add("tls", 25, "Certificate does not cover host %s (covers: %s)" % (host, ", ".join(names[:4]) or "-"))
    if na < now:
        F.add("tls", 15, "Certificate expired %d days ago" % -out["days_left"])
    elif out["days_left"] < 7:
        F.add("tls", 3, "Certificate expires in %d days" % out["days_left"])
    if out["age_days"] < 3:
        F.add("tls", 5, "Certificate was issued only %d day(s) ago" % out["age_days"])
    return out


# ----------------------------------------------------------------------------
# Redirect trace
# ----------------------------------------------------------------------------
META_REFRESH = re.compile(r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*(\d+)\s*[;,]\s*(?:url\s*=\s*)?['"]?([^'">\s]+)""", re.I)
JS_REDIRECT = re.compile(r"""(?:(?:window|document|top|self|parent)\.)?location(?:\.href)?\s*=\s*['"]([^'"]{4,400})['"]|location\.(?:replace|assign)\(\s*['"]([^'"]{4,400})['"]\s*\)""", re.I)


def client_redirect(r, base):
    ctype = r["hdr"].get("content-type", "").lower()
    if r["status"] >= 400 or ("html" not in ctype and r["body"][:200].lstrip().lower().startswith(b"<") is False):
        return None, None
    text = r["body"][:200_000].decode("utf-8", "replace")
    m = META_REFRESH.search(text)
    if m and int(m.group(1)) <= 10:
        return urllib.parse.urljoin(base, htmllib.unescape(m.group(2))), "meta-refresh"
    visible = re.sub(r"(?is)<(script|style).*?</\1>|<[^>]+>", " ", text)
    if len(r["body"]) < 6000 and len(visible.split()) < 40:
        m = JS_REDIRECT.search(text)
        if m:
            return urllib.parse.urljoin(base, m.group(1) or m.group(2)), "javascript"
    return None, None


def trace(U, max_redirects):
    hops, seen, client, final, url, notes = [], set(), 0, None, U["fetch_url"], []
    while True:
        if len([h for h in hops if "error" not in h]) > max_redirects:
            notes.append("redirect limit (%d) reached" % max_redirects)
            break
        if url in seen:
            notes.append("redirect loop detected")
            break
        seen.add(url)
        try:
            r = fetch_hop(url)
        except FetchError as e:
            hops.append({"url": url, "error": str(e)})
            break
        hop = {"n": len(hops) + 1, "url": url, "type": "http", "status": r["status"], "ip": r["ip"], "ms": r["ms"],
               "server": r["hdr"].get("server"), "content_type": r["hdr"].get("content-type"),
               "tls_version": (r["tls"] or {}).get("version"), "cert_verified": (r["tls"] or {}).get("verified"),
               "set_cookies": sum(1 for k, _ in r["headers"] if k.lower() == "set-cookie"), "location": None}
        hops.append(hop)
        loc = r["hdr"].get("location")
        if r["status"] in REDIRECT_CODES and loc:
            nxt = urllib.parse.urljoin(url, loc.strip())
            sch = urllib.parse.urlsplit(nxt).scheme.lower()
            hop["location"] = nxt
            if sch not in ("http", "https"):
                notes.append("redirects to non-web scheme %s:" % sch)
                final = r
                break
            url = nxt
            continue
        final = r
        if client < 3:
            nxt, kind = client_redirect(r, url)
            if nxt and urllib.parse.urlsplit(nxt).scheme.lower() in ("http", "https"):
                hop["type"], hop["location"] = kind, nxt
                client += 1
                url = nxt
                continue
        break
    return {"hops": hops, "final": final, "final_url": hops[-1]["url"] if hops and "error" not in hops[-1] else None,
            "notes": notes, "client_redirects": client}


def trace_findings(U, tr, F):
    hops = [h for h in tr["hops"] if "error" not in h]
    if len(hops) > 4:
        F.add("redirects", 5, "Long redirect chain (%d hops)" % len(hops))
    regs = [registrable_of(urllib.parse.urlsplit(h["url"]).hostname) for h in hops]
    changes = sum(1 for a, b in zip(regs, regs[1:]) if a != b)
    if changes >= 2:
        F.add("redirects", 8, "Redirect chain crosses %d different domains: %s" % (changes + 1, " -> ".join(uniq(regs))))
    elif changes == 1:
        F.add("redirects", 3, "Ends on a different domain than the one in the link: %s" % regs[-1])
    for a, b in zip(hops, hops[1:]):
        if a["url"].startswith("https://") and b["url"].startswith("http://"):
            F.add("redirects", 10, "HTTPS -> HTTP downgrade in the redirect chain (%s)" % b["url"])
    if tr["client_redirects"]:
        F.add("redirects", 5, "Uses client-side redirect(s) (meta-refresh / JavaScript), common in cloaking and phishing kits")
    for n in tr["notes"]:
        F.add("redirects", 3, n.capitalize())
    if tr["hops"] and "error" in tr["hops"][-1]:
        F.add("redirects", 0, "Fetch failed: %s" % tr["hops"][-1]["error"])


# ----------------------------------------------------------------------------
# HTTP summary: headers, cookies, tech
# ----------------------------------------------------------------------------
HEADER_TECH = [("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-vercel-id", "Vercel"),
               ("x-nf-request-id", "Netlify"), ("x-github-request-id", "GitHub Pages"), ("fly-request-id", "Fly.io"),
               ("x-azure-ref", "Azure Front Door"), ("x-sucuri-id", "Sucuri"), ("x-wix-request-id", "Wix"),
               ("x-shopify-stage", "Shopify"), ("x-drupal-cache", "Drupal"), ("x-served-by", "Fastly/Varnish"),
               ("x-render-origin-server", "Render"), ("x-railway-edge", "Railway")]
BODY_TECH = [("wp-content", "WordPress"), ("wp-includes", "WordPress"), ("/_next/", "Next.js"), ("__NEXT_DATA__", "Next.js"),
             ("/_nuxt/", "Nuxt"), ("cdn.shopify.com", "Shopify"), ("Drupal.settings", "Drupal"), ("content=\"Joomla", "Joomla"),
             ("static.wixstatic.com", "Wix"), ("squarespace.com", "Squarespace"), ("data-reactroot", "React"),
             ("ng-version", "Angular"), ("cloudflareinsights.com", "Cloudflare Web Analytics"),
             ("recaptcha", "reCAPTCHA"), ("hcaptcha.com", "hCaptcha"), ("challenges.cloudflare.com", "Cloudflare Turnstile")]
SEC_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options",
               "referrer-policy", "permissions-policy"]


def detect_tech(h, body):
    tech = [name for k, name in HEADER_TECH if k in h]
    if re.search(r"cloudflare", h.get("server", ""), re.I):
        tech.append("Cloudflare")
    for k in ("x-powered-by", "x-generator", "x-aspnet-version"):
        if h.get(k):
            tech.append("%s: %s" % (k, h[k]))
    if h.get("server"):
        tech.append("server: %s" % h["server"])
    tech += [name for needle, name in BODY_TECH if needle in body]
    m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)", body, re.I)
    if m:
        tech.append("generator: %s" % m.group(1)[:80])
    return uniq(tech)


def parse_cookies(headers):
    out = []
    for k, v in headers:
        if k.lower() != "set-cookie":
            continue
        parts = [x.strip() for x in v.split(";")]
        flags = {x.split("=")[0].lower(): (x.split("=", 1)[1] if "=" in x else True) for x in parts[1:]}
        out.append({"name": parts[0].split("=", 1)[0], "secure": "secure" in flags, "httponly": "httponly" in flags,
                    "samesite": flags.get("samesite")})
    return out


def mod_http(final, scheme, F):
    h = final["hdr"]
    sec = {k: h.get(k) for k in SEC_HEADERS}
    out = {"status": final["status"], "reason": final["reason"], "http_version": final["http_version"],
           "response_ms": final["ms"], "content_type": h.get("content-type"), "content_length": h.get("content-length"),
           "server": h.get("server"), "security_headers": sec, "cookies": parse_cookies(final["headers"]),
           "redirect_chain_headers": None}
    if scheme == "https":
        if not sec["strict-transport-security"]:
            F.add("http", 0, "HSTS header missing (hygiene)")
        if not sec["content-security-policy"]:
            F.add("http", 0, "Content-Security-Policy missing (hygiene)")
    return out


# ----------------------------------------------------------------------------
# Content analysis
# ----------------------------------------------------------------------------
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title = "", False
        self.metas, self.links, self.forms, self.scripts, self.iframes, self.icons = [], [], [], [], [], []
        self._a, self._form, self._script, self._skip = None, None, None, 0
        self.base, self.imgs, self.inputs, self.events = None, 0, [], Counter()
        self.text = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for k in a:
            if k in ("oncontextmenu", "onpaste", "oncopy", "onselectstart", "ondragstart"):
                self.events[k] += 1
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "a" and "href" in a:
            if self._a:
                self.links.append(self._a)
            self._a = {"href": a["href"].strip(), "text": ""}
        elif tag == "form":
            self._form = {"action": a.get("action", "").strip(), "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select"):
            i = {"type": (a.get("type") or ("text" if tag == "input" else tag)).lower(), "name": a.get("name", ""),
                 "id": a.get("id", ""), "autocomplete": a.get("autocomplete", ""), "placeholder": a.get("placeholder", "")}
            self.inputs.append(i)
            if self._form is not None:
                self._form["inputs"].append(i)
        elif tag == "script":
            if a.get("src"):
                self.scripts.append({"src": a["src"].strip()})
            else:
                self._script = []
            self._skip += 1
        elif tag == "style":
            self._skip += 1
        elif tag == "iframe":
            st = a.get("style", "").lower().replace(" ", "")
            hidden = (a.get("width") in ("0", "1") or a.get("height") in ("0", "1") or "display:none" in st or
                      "visibility:hidden" in st or "width:0" in st or "height:0" in st or "left:-" in st)
            self.iframes.append({"src": a.get("src", "").strip(), "hidden": hidden})
        elif tag == "link" and "icon" in a.get("rel", "").lower() and a.get("href"):
            self.icons.append(a["href"].strip())
        elif tag == "base" and a.get("href"):
            self.base = a["href"].strip()
        elif tag == "img":
            self.imgs += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "a" and self._a:
            self.links.append(self._a)
            self._a = None
        elif tag == "form":
            self._form = None
        elif tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
            if tag == "script" and self._script is not None:
                self.scripts.append({"inline": "".join(self._script)})
                self._script = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._script is not None:
            self._script.append(data)
        elif not self._skip:
            if self._a is not None:
                self._a["text"] += data
            if len(self.text) < 4000:
                self.text.append(data)


MAGIC = [(b"MZ", "Windows executable (PE)"), (b"\x7fELF", "ELF executable"), (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
         (b"\xcf\xfa\xed\xfe", "Mach-O executable"), (b"PK\x03\x04", "ZIP container (zip/apk/jar/docx/xlsx)"),
         (b"%PDF", "PDF document"), (b"Rar!", "RAR archive"), (b"7z\xbc\xaf", "7-Zip archive"),
         (b"\xd0\xcf\x11\xe0", "legacy MS Office (OLE)"), (b"\x1f\x8b", "gzip"), (b"#!", "shell script"),
         (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"), (b"MSCF", "Microsoft CAB"),
         (b"L\x00\x00\x00\x01\x14\x02", "Windows shortcut (LNK)")]
EXEC_KINDS = ("PE", "ELF", "Mach-O", "CAB", "LNK", "shell script")
OBF = {"eval()": r"\beval\s*\(", "atob()": r"\batob\s*\(", "unescape()": r"\bunescape\s*\(",
       "fromCharCode": r"fromCharCode", "document.write()": r"document\.write\s*\(",
       "hex-escape blob": r"(?:\\x[0-9a-fA-F]{2}){20,}", "unicode-escape blob": r"(?:\\u[0-9a-fA-F]{4}){20,}",
       "long base64 blob": r"[A-Za-z0-9+/=]{300,}"}
SENSITIVE_FIELD = re.compile(r"card|cc-?num|cvv|cvc|expir|iban|routing|ssn|aadhaar|aadhar|\bpan\b|otp|pin\b|passcode|"
                             r"seed|mnemonic|recovery.?phrase|private.?key|upi", re.I)
IOC_RE = {
    "emails": r"\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "btc": r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{26,34})\b",
    "eth": r"\b0x[a-fA-F0-9]{40}\b",
    "telegram": r"(?:t\.me|telegram\.me)/([A-Za-z0-9_+]{4,})",
    "whatsapp": r"wa\.me/(\d{8,15})",
    "ga_ids": r"\b(?:UA-\d{4,10}-\d{1,3}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,8}|AW-\d{8,12})\b",
    "fb_pixel": r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{8,20})['\"]",
}


def sniff(body):
    for sig, name in MAGIC:
        if body.startswith(sig):
            return name
    return None


def mmh3_32(data, seed=0):
    c1, c2, h, n = 0xCC9E2D51, 0x1B873593, seed, len(data)
    rounded = n & ~3
    for i in range(0, rounded, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail, k = data[rounded:], 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_info(page_url, icons, skip_fetch):
    out = {}
    for href in (icons[:1] or []) + ["/favicon.ico"]:
        u = urllib.parse.urljoin(page_url, href)
        if urllib.parse.urlsplit(u).scheme not in ("http", "https"):
            continue
        try:
            r = fetch_hop(u, max_bytes=262_144, accept="image/*,*/*;q=0.8")
        except FetchError:
            continue
        if r["status"] == 200 and r["body"] and b"<html" not in r["body"][:300].lower():
            out = {"url": u, "bytes": len(r["body"]), "sha256": hashlib.sha256(r["body"]).hexdigest(),
                   "mmh3": mmh3_32(base64.encodebytes(r["body"]))}
            break
    return out


def mod_content(final_url, final, F, favicon=True):
    body, h = final["body"], final["hdr"]
    ctype = h.get("content-type", "").lower()
    out = {"size": len(body), "truncated": final["truncated"], "sha256": hashlib.sha256(body).hexdigest() if body else None}
    kind = sniff(body)
    out["file_type"] = kind
    disp = h.get("content-disposition", "")
    if "attachment" in disp.lower():
        out["download"] = (re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', disp, re.I) or [None, None])[1] or True
        fn = str(out["download"]).lower()
        if fn.rsplit(".", 1)[-1] in DANGEROUS_EXT:
            F.add("content", 20, "Server forces download of an executable / script file (%s)" % out["download"])
    if kind and any(k in kind for k in EXEC_KINDS):
        mismatch = "html" in ctype or ctype.startswith(("text/", "image/"))
        F.add("content", 35 if mismatch else 25, "Response body is a %s%s" % (kind, " but Content-Type claims %s" % ctype.split(";")[0] if mismatch else ""))
    elif kind and "ZIP" in kind and urllib.parse.urlsplit(final_url).path.lower().endswith((".apk", ".jar")):
        F.add("content", 15, "Response is an Android/Java package")
    is_html = "html" in ctype or body[:600].lstrip().lower().startswith((b"<!doctype html", b"<html", b"<head", b"<body"))
    if not body or not is_html:
        out["html"] = False
        return out
    out["html"] = True
    m = re.search(r"charset=([\w-]+)", ctype) or re.search(rb"<meta[^>]+charset=[\"']?([\w-]+)", body[:4096], re.I)
    enc = (m.group(1) if isinstance(m.group(1), str) else m.group(1).decode()) if m else "utf-8"
    try:
        text = body.decode(enc, "replace")
    except LookupError:
        text = body.decode("utf-8", "replace")
    P = PageParser()
    try:
        P.feed(text)
        P.close()
    except Exception as e:  # malformed markup must never break the run
        out["parse_warning"] = short_err(e)
    base = urllib.parse.urljoin(final_url, P.base) if P.base else final_url
    page_reg = registrable_of(urllib.parse.urlsplit(final_url).hostname)
    title = re.sub(r"\s+", " ", P.title).strip()
    out["title"] = title[:200] or None
    meta = {}
    for mt in P.metas:
        k = (mt.get("name") or mt.get("property") or mt.get("http-equiv") or "").lower()
        if k and mt.get("content"):
            meta.setdefault(k, mt["content"][:200])
    out["meta"] = {k: meta[k] for k in ("description", "generator", "og:title", "og:site_name", "robots", "viewport") if k in meta}
    if re.search(r"noindex", meta.get("robots", ""), re.I):
        F.add("content", 2, "Page asks search engines not to index it (noindex)")
    out["tech"] = detect_tech(h, text)

    # forms
    forms = []
    for f in P.forms:
        action = urllib.parse.urljoin(base, f["action"]) if f["action"] else final_url
        asplit = urllib.parse.urlsplit(action)
        areg = registrable_of(asplit.hostname) if asplit.hostname else None
        fields = [i for i in f["inputs"] if i["type"] not in ("hidden", "submit", "button", "image", "reset")]
        pw = any(i["type"] == "password" for i in f["inputs"])
        sens = uniq(i["name"] or i["id"] or i["type"] for i in f["inputs"]
                    if SENSITIVE_FIELD.search(" ".join((i["name"], i["id"], i["autocomplete"], i["placeholder"]))))
        d = {"action": action, "method": f["method"], "fields": len(fields), "password": pw, "sensitive_fields": sens,
             "cross_domain": bool(areg and areg != page_reg), "insecure": asplit.scheme == "http", "mailto": asplit.scheme == "mailto"}
        forms.append(d)
        if pw or sens:
            what = "password" if pw else "sensitive (%s)" % ", ".join(sens[:3])
            if d["cross_domain"]:
                F.add("content", 35, "Form collecting %s data posts to a DIFFERENT domain: %s" % (what, areg))
            elif d["insecure"]:
                F.add("content", 25, "Form collecting %s data submits over plain HTTP" % what)
            elif pw:
                F.add("content", 2, "Page contains a login / password form")
            elif sens:
                F.add("content", 6, "Page collects sensitive data fields: %s" % ", ".join(sens[:4]))
        if d["mailto"]:
            F.add("content", 15, "Form submits data to an e-mail address (mailto:)")
    out["forms"] = forms
    out["password_fields"] = sum(1 for i in P.inputs if i["type"] == "password")
    if not P.forms and out["password_fields"]:
        F.add("content", 4, "Password field outside any <form> (script-driven credential capture is common in phishing kits)")

    # links
    ext_domains, deceptive, nulls, total = Counter(), [], 0, 0
    for l in P.links:
        href = l["href"]
        if not href or href.startswith(("mailto:", "tel:", "sms:")):
            continue
        total += 1
        if href == "#" or href.lower().startswith("javascript:"):
            nulls += 1
            continue
        u = urllib.parse.urlsplit(urllib.parse.urljoin(base, href))
        r = registrable_of(u.hostname) if u.hostname else None
        if r and r != page_reg:
            ext_domains[r] += 1
            m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", l["text"].lower())
            if m and registrable_of(m.group(1)) != r:
                deceptive.append({"text": trunc(l["text"].strip(), 60), "href": trunc(href, 80)})
    out["links"] = {"total": total, "external": sum(ext_domains.values()), "null_links": nulls,
                    "top_external_domains": ext_domains.most_common(8)}
    if deceptive:
        F.add("content", 15, "%d link(s) display one domain but point to another (e.g. '%s' -> %s)" %
              (len(deceptive), deceptive[0]["text"], deceptive[0]["href"]))
    out["deceptive_links"] = deceptive[:5]
    if total >= 5 and nulls / total > 0.6:
        F.add("content", 5, "Most links are dead (# / javascript:) - typical of a cloned page")

    # scripts / iframes
    sdoms, inline_text = Counter(), ""
    for s in P.scripts:
        if "src" in s:
            u = urllib.parse.urlsplit(urllib.parse.urljoin(base, s["src"]))
            if u.hostname and registrable_of(u.hostname) != page_reg:
                sdoms[registrable_of(u.hostname)] += 1
        else:
            inline_text += s["inline"][:200_000] + "\n"
    out["scripts"] = {"total": len(P.scripts), "external_domains": sdoms.most_common(8), "inline_bytes": len(inline_text)}
    hits = [n for n, rx in OBF.items() if re.search(rx, inline_text)]
    out["obfuscation_signals"] = hits
    if len(hits) >= 3:
        F.add("content", 15, "Heavily obfuscated inline JavaScript (%s)" % ", ".join(hits))
    elif len(hits) == 2:
        F.add("content", 6, "Some obfuscation patterns in inline JavaScript (%s)" % ", ".join(hits))
    if P.events or re.search(r"contextmenu[^;]{0,60}(preventDefault|return\s*false)|keyCode\s*={2,3}\s*123", inline_text):
        F.add("content", 5, "Page tries to block right-click / dev-tools (anti-analysis)")
    ifr = []
    for fr in P.iframes:
        u = urllib.parse.urlsplit(urllib.parse.urljoin(base, fr["src"])) if fr["src"] else None
        cross = bool(u and u.hostname and registrable_of(u.hostname) != page_reg)
        ifr.append({"src": trunc(fr["src"], 100), "hidden": fr["hidden"], "cross_domain": cross})
    out["iframes"] = ifr
    hid = [i for i in ifr if i["hidden"] and (i["cross_domain"] or not i["src"])]
    if hid:
        F.add("content", 15, "%d hidden iframe(s)%s" % (len(hid), " loading %s" % hid[0]["src"] if hid[0]["src"] else ""))
    if P.base and registrable_of(urllib.parse.urlsplit(base).hostname) != page_reg:
        F.add("content", 10, "<base href> points to another domain (%s)" % P.base)

    # brand in title / site name vs actual domain
    label_src = " ".join(filter(None, [title, meta.get("og:site_name", ""), meta.get("og:title", "")])).lower()
    toks = set(re.split(r"[^a-z0-9]+", label_src))
    has_cred = bool(out["password_fields"]) or any(f["sensitive_fields"] for f in forms)
    for brand, legit in BRANDS.items():
        if registrable_of(urllib.parse.urlsplit(final_url).hostname) in legit:
            continue
        if brand in toks or (len(brand) >= 6 and brand in label_src):
            F.add("content", 25 + (10 if has_cred else 0),
                  "Page presents itself as '%s' (title: %s) but is hosted on %s%s" %
                  (brand, trunc(title, 50), page_reg, " and asks for credentials" if has_cred else ""))
            break

    # IOCs
    ioc = {}
    for k, rx in IOC_RE.items():
        found = uniq(m if isinstance(m, str) else m[0] for m in re.findall(rx, text[:1_000_000]))
        if k == "emails":
            found = [e for e in found if not re.search(r"\.(png|jpg|gif|svg|webp|css|js)$", e, re.I) and "example" not in e.lower()]
        if found:
            ioc[k] = found[:10]
    out["iocs"] = ioc
    if ioc.get("btc") or ioc.get("eth"):
        F.add("content", 4, "Crypto wallet address(es) on the page: %s" % ", ".join((ioc.get("btc", []) + ioc.get("eth", []))[:2]))
    if favicon:
        out["favicon"] = favicon_info(final_url, [urllib.parse.urljoin(base, i) for i in P.icons], False)
    return out


# ----------------------------------------------------------------------------
# Threat intelligence + history
# ----------------------------------------------------------------------------
def _openphish():
    path = os.path.join(tempfile.gettempdir(), "url_analyzer_openphish.txt")
    try:
        if os.path.exists(path) and time.time() - os.path.getmtime(path) < 3600:
            return open(path, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        pass
    req = urllib.request.Request("https://openphish.com/feed.txt", headers={"User-Agent": "url-analyzer/%s" % __version__})
    try:
        data = urllib.request.urlopen(req, timeout=CFG["timeout"]).read(8_000_000).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        raise FetchError(short_err(e)) from None
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
    except OSError:
        pass
    return data.splitlines()


def intel_one(url, host, F, tag=""):
    res = {}
    vt, gsb, uh = os.environ.get("VT_API_KEY"), os.environ.get("GSB_API_KEY"), os.environ.get("URLHAUS_AUTH_KEY")
    suffix = " (%s)" % tag if tag else ""
    if vt:
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            st, d = api_json("https://www.virustotal.com/api/v3/urls/" + uid, headers={"x-apikey": vt})
            if st == 404:
                res["virustotal"] = {"found": False}
            elif st == 200 and isinstance(d, dict):
                a = d["data"]["attributes"]
                s = a.get("last_analysis_stats", {})
                res["virustotal"] = {"found": True, "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
                                     "harmless": s.get("harmless", 0), "undetected": s.get("undetected", 0),
                                     "reputation": a.get("reputation"), "categories": a.get("categories"),
                                     "last_analysis": iso(parse_dt(dt.datetime.fromtimestamp(a["last_analysis_date"], dt.timezone.utc).isoformat())) if a.get("last_analysis_date") else None,
                                     "link": "https://www.virustotal.com/gui/url/" + uid}
                m_, s_ = s.get("malicious", 0), s.get("suspicious", 0)
                if m_ >= 3:
                    F.add("intel", 70, "VirusTotal: %d engines flag this URL as malicious%s" % (m_, suffix))
                elif m_ >= 1:
                    F.add("intel", 30, "VirusTotal: %d engine(s) flag this URL as malicious%s" % (m_, suffix))
                elif s_ >= 1:
                    F.add("intel", 10, "VirusTotal: %d engine(s) mark this URL suspicious%s" % (s_, suffix))
            else:
                res["virustotal"] = {"error": "HTTP %s" % st}
        except (FetchError, KeyError, TypeError) as e:
            res["virustotal"] = {"error": short_err(e)}
    if gsb:
        body = {"client": {"clientId": "url-analyzer", "clientVersion": __version__},
                "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                               "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
        try:
            st, d = api_json("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + urllib.parse.quote(gsb),
                             method="POST", json_body=body)
            if st == 200 and isinstance(d, dict):
                types = uniq(m.get("threatType") for m in d.get("matches", []))
                res["safe_browsing"] = {"matches": types}
                if types:
                    F.add("intel", 80, "Google Safe Browsing lists this URL: %s%s" % (", ".join(types), suffix))
            else:
                res["safe_browsing"] = {"error": "HTTP %s" % st}
        except FetchError as e:
            res["safe_browsing"] = {"error": str(e)}
    if uh:
        try:
            st, d = api_json("https://urlhaus-api.abuse.ch/v1/url/", method="POST", form={"url": url}, headers={"Auth-Key": uh})
            if isinstance(d, dict) and d.get("query_status") == "ok":
                res["urlhaus"] = {"listed": True, "status": d.get("url_status"), "threat": d.get("threat"), "tags": d.get("tags"),
                                  "link": d.get("urlhaus_reference")}
                F.add("intel", 85 if d.get("url_status") == "online" else 50,
                      "URLhaus: listed as %s (%s)%s" % (d.get("threat") or "malware distribution", d.get("url_status"), suffix))
            elif isinstance(d, dict):
                res["urlhaus"] = {"listed": False, "query_status": d.get("query_status")}
            else:
                res["urlhaus"] = {"error": "HTTP %s" % st}
        except FetchError as e:
            res["urlhaus"] = {"error": str(e)}
    try:
        feed = _openphish()
        norm = url.rstrip("/").lower()
        exact = any(x.strip().rstrip("/").lower() == norm for x in feed)
        on_host = (not exact) and any(urllib.parse.urlsplit(x.strip()).hostname == host for x in feed)
        res["openphish"] = {"listed": exact, "host_listed": on_host, "feed_size": len(feed)}
        if exact:
            F.add("intel", 80, "OpenPhish community feed lists this exact URL%s" % suffix)
        elif on_host:
            F.add("intel", 40, "OpenPhish community feed lists other URLs on host %s%s" % (host, suffix))
    except FetchError as e:
        res["openphish"] = {"error": str(e)}
    return res


def mod_intel(urls, F):
    out = {"checked": {}, "services_with_keys": [k for k, e in (("virustotal", "VT_API_KEY"), ("safe_browsing", "GSB_API_KEY"),
                                                                ("urlhaus", "URLHAUS_AUTH_KEY")) if os.environ.get(e)]}
    for i, (u, tag) in enumerate(urls):
        out["checked"][u] = intel_one(u, urllib.parse.urlsplit(u).hostname, F, tag)
    return out


def mod_history(host, F):
    if _is_ip(host):
        return {"skipped": "IP host"}
    try:
        st, d = api_json("https://web.archive.org/cdx/search/cdx?" + urllib.parse.urlencode(
            {"url": host, "matchType": "host", "limit": "1", "output": "json", "fl": "timestamp,original"}), timeout=20)
    except FetchError as e:
        return {"error": str(e)}
    if not isinstance(d, list) or len(d) < 2:
        return {"first_capture": None}
    first = parse_dt(d[1][0])
    age = (now_utc() - first).days if first else None
    return {"first_capture": iso(first), "age_days": age, "sample": d[1][1]}


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
VERDICTS = [(60, "CRITICAL"), (35, "HIGH"), (15, "MODERATE"), (0, "LOW")]


def verdict(findings):
    s = min(100, sum(f["weight"] for f in findings))
    return s, next(v for t, v in VERDICTS if s >= t)


def analyze(raw, opts):
    """Analyse one URL. opts needs: skip, max_redirects, default_scheme; optional: budget (seconds)."""
    budget = getattr(opts, "budget", None)
    _LOCAL.deadline = (time.monotonic() + budget) if budget else None
    try:
        return _analyze(raw, opts)
    finally:
        _LOCAL.deadline = None


def _analyze(raw, opts):
    t0 = time.perf_counter()
    skip = set(opts.skip)
    U = parse_url(raw, opts.default_scheme)
    F = Findings()
    rep = {"input": raw, "analyzed_at": iso(now_utc()), "url": {k: v for k, v in U.items() if k not in ("params",)},
           "params": [{"name": k, "value": v} for k, v in U["params"]], "modules": {}, "skipped": sorted(skip)}
    lexical(U, F)
    if not U["fetchable"]:
        return finish(rep, F, t0)
    final_url, final, tr = U["fetch_url"], None, None
    # 1) contact the target (redirects, TLS, HTTP, content)
    if "fetch" not in skip:
        tr = trace(U, opts.max_redirects)
        rep["modules"]["redirects"] = {"hops": tr["hops"], "notes": tr["notes"], "final_url": tr["final_url"]}
        trace_findings(U, tr, F)
        final = tr["final"]
        if tr["final_url"]:
            final_url = tr["final_url"]
    D = parse_url(final_url, opts.default_scheme) if final_url != U["fetch_url"] else U
    if D is not U:
        rep["modules"]["destination"] = {"url": D["url"], "defanged": D["defanged"], "host": D["host"], "registrable": D["registrable"]}
        if D["registrable"] != U["registrable"]:
            lexical(D, F, "[destination] ")
    if final:
        scheme = D["scheme"]
        rep["modules"]["http"] = mod_http(final, scheme, F)
        rep["modules"]["tls"] = mod_tls(final["tls"], D["host"], F) if final["tls"] else None
        rep["modules"]["content"] = mod_content(final_url, final, F, favicon="favicon" not in skip)
        if rep["modules"]["content"].get("password_fields") and scheme == "http":
            F.add("content", 25, "Login form served over unencrypted HTTP")
    # 2) third-party lookups run in parallel
    jobs = {}
    with cf.ThreadPoolExecutor(4) as ex:
        if "dns" not in skip:
            jobs["network"] = ex.submit(mod_network, D, D["host"], F, [final["ip"]] if final else [])
        if "whois" not in skip:
            jobs["whois"] = ex.submit(mod_whois, D["registrable"], F)
        if "history" not in skip:
            jobs["history"] = ex.submit(mod_history, D["host"], F)
        if "intel" not in skip:
            urls = [(U["url"], "input URL")] + ([(D["url"], "destination")] if D["url"] != U["url"] else [])
            jobs["intel"] = ex.submit(mod_intel, urls, F)
        for k, fu in jobs.items():
            try:
                rep["modules"][k] = fu.result()
            except Exception as e:
                rep["modules"][k] = {"error": "%s: %s" % (type(e).__name__, short_err(e))}
    h = rep["modules"].get("history") or {}
    w = rep["modules"].get("whois") or {}
    if "first_capture" in h and h["first_capture"] is None and (w.get("age_days") or 9999) < 180:
        F.add("history", 5, "No Wayback Machine history for a recently registered domain")
    return finish(rep, F, t0)


def finish(rep, F, t0):
    F.items.sort(key=lambda f: (-f["weight"], f["module"]))
    rep["findings"] = F.items
    rep["score"], rep["verdict"] = verdict(F.items)
    rep["elapsed_s"] = round(time.perf_counter() - t0, 2)
    return rep


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------
def section(title):
    print("\n" + bold(cyan("== %s %s" % (title, "=" * max(3, 66 - len(title))))))


def kv(k, v, indent=2, width=15):
    if v is None or v == "" or v == [] or v is False:
        return
    print("%s%s %s" % (" " * indent, dim(k.ljust(width)), v))


SEV_COL = {"critical": lambda s: bold(red(s)), "high": red, "medium": yellow, "low": cyan, "info": dim}
VERDICT_COL = {"CRITICAL": lambda s: bold(red(s)), "HIGH": red, "MODERATE": yellow, "LOW": green}


def render(rep):
    U = rep["url"]
    print("\n" + bold(trunc(U["url"] or U["input"], 150)))
    kv("defanged", U["defanged"])
    bar = "#" * (rep["score"] // 5) + "." * (20 - rep["score"] // 5)
    print("\n  %s  %s  %s" % (bold("VERDICT"), VERDICT_COL[rep["verdict"]](rep["verdict"].ljust(8)),
                             "%s %d/100  %s" % (VERDICT_COL[rep["verdict"]]("[" + bar + "]"), rep["score"], dim("(heuristic suspicion score, not proof)"))))
    section("FINDINGS")
    shown = [f for f in rep["findings"] if f["weight"] > 0] or []
    if not shown:
        print("  " + green("no suspicious indicators found"))
    for f in rep["findings"]:
        print("  %s %s %s %s" % (SEV_COL[f["severity"]](f["severity"].upper().ljust(8)), dim("+%-3d" % f["weight"]),
                                 dim(f["module"].ljust(9)), f["message"]))
    section("URL BREAKDOWN")
    kv("scheme", U["scheme"])
    kv("host", U["host"] and (U["host"] + ("  (%s)" % U["unicode_host"] if U["unicode_host"] != U["host"] else "")))
    kv("host type", U["host_kind"] and "%s -> %s" % (U["host_kind"], U["ip_normalized"]))
    kv("registrable", U["registrable"])
    kv("subdomain", U["subdomain"] and "%s  (%d label%s)" % (U["subdomain"], U["subdomain_count"], "s" if U["subdomain_count"] > 1 else ""))
    kv("port", U["port"])
    kv("path", trunc(U["path"], 120) if U["path"] not in ("", "/") else None)
    kv("fragment", U["fragment"])
    kv("userinfo", U["username"] if U["has_userinfo"] else None)
    for p in rep["params"][:12]:
        kv("param", "%s = %s" % (p["name"], trunc(p["value"], 90)))
    kv("clean URL", U["clean_url"] if U["clean_url"] and U["clean_url"] != U["url"] else None)
    kv("length", U["length"])
    for n in U["notes"]:
        kv("note", n)
    m = rep["modules"]
    if m.get("redirects"):
        section("REDIRECT TRACE")
        for h in m["redirects"]["hops"]:
            if "error" in h:
                print("  %s %s  %s" % (red("x"), trunc(h["url"], 90), red(h["error"])))
                continue
            col = green if h["status"] < 300 else yellow if h["status"] < 400 else red
            tag = "" if h["type"] == "http" else magenta("[%s] " % h["type"])
            print("  %s %s %s %s%s" % (str(h["n"]).rjust(2), col(str(h["status"])), trunc(h["url"], 90), dim("%s %sms" % (h["ip"], h["ms"])),
                                       ("\n       " + tag + "-> " + trunc(h["location"], 100)) if h.get("location") else ""))
        for n in m["redirects"]["notes"]:
            print("  " + yellow("! " + n))
    if m.get("destination"):
        kv("destination", "%s  (%s)" % (m["destination"]["host"], m["destination"]["defanged"]), 2)
    n = m.get("network")
    if n:
        section("NETWORK")
        if n.get("error"):
            print("  " + yellow(n["error"]))
        kv("host", n["host"])
        kv("CNAME", ", ".join(n["cname"]))
        kv("nameservers", ", ".join(n["ns"]))
        for a in n["addresses"]:
            if not a["global"]:
                print("  %s %s" % (a["ip"], yellow("(non-public)")))
                continue
            asn = a.get("asn") or {}
            g = a.get("geo") or {}
            print("  %s" % bold(a["ip"]))
            kv("reverse DNS", ", ".join(a.get("ptr") or []), 4, 13)
            kv("ASN", asn and "%s %s" % (" ".join(asn.get("asn", [])), asn.get("name") or ""), 4, 13)
            kv("prefix", asn.get("prefix"), 4, 13)
            kv("location", ", ".join(x for x in (g.get("city"), g.get("region"), g.get("country")) if x), 4, 13)
            kv("org / ISP", " / ".join(x for x in (g.get("org"), g.get("isp")) if x), 4, 13)
    w = m.get("whois")
    if w:
        section("DOMAIN REGISTRATION (RDAP)")
        if w.get("error") or w.get("skipped"):
            print("  " + dim(w.get("error") or w.get("skipped")))
        else:
            kv("registrar", w.get("registrar"))
            age = w.get("age_days")
            kv("created", w.get("created") and "%s  (%s days old)" % (w["created"], age))
            kv("expires", w.get("expires") and "%s  (%s days left)" % (w["expires"], w["days_to_expiry"]))
            kv("status", ", ".join(w.get("status", [])))
            kv("nameservers", ", ".join(w.get("nameservers", [])))
            kv("privacy", "contact data redacted" if w.get("privacy_redacted") else None)
    t = m.get("tls")
    if t:
        section("TLS CERTIFICATE")
        kv("trusted", green("yes") if t["verified"] else red("NO - %s" % t.get("verify_error")))
        kv("subject", t.get("subject_cn"))
        kv("issuer", "%s / %s" % (t.get("issuer_cn"), t.get("issuer_org")) if t.get("issuer_cn") else None)
        kv("validity", t.get("valid_from") and "%s -> %s  (issued %sd ago, %sd left)" % (t["valid_from"], t["valid_to"], t["age_days"], t["days_left"]))
        kv("hostname match", None if t.get("hostname_match") is None else (green("yes") if t["hostname_match"] else red("NO")))
        kv("SANs", t.get("sans") and trunc(", ".join(t["sans"][:12]), 140))
        kv("protocol", "%s  %s (%s bits)" % (t["version"], t["cipher"], t["bits"]))
        kv("SHA-256", t.get("sha256"))
    h = m.get("http")
    if h:
        section("HTTP RESPONSE")
        kv("status", "%s %s  (HTTP/%s, %sms)" % (h["status"], h["reason"], h["http_version"], h["response_ms"]))
        kv("content-type", h["content_type"])
        kv("server", h["server"])
        sh = h["security_headers"]
        miss = [k for k, v in sh.items() if not v]
        kv("sec. headers", "%d/%d present%s" % (len(sh) - len(miss), len(sh), ("  missing: " + ", ".join(miss)) if miss else ""))
        for c in h["cookies"]:
            kv("cookie", "%s  %s %s samesite=%s" % (c["name"], "Secure" if c["secure"] else red("!Secure"), "HttpOnly" if c["httponly"] else red("!HttpOnly"), c["samesite"]))
    c = m.get("content")
    if c:
        section("PAGE CONTENT")
        kv("size", "%d bytes%s  sha256 %s" % (c["size"], " (truncated)" if c["truncated"] else "", (c["sha256"] or "")[:16] + "..."))
        kv("file type", c.get("file_type"))
        kv("download", c.get("download") if c.get("download") not in (None, True) else ("attachment" if c.get("download") else None))
        if c.get("html"):
            kv("title", c.get("title"))
            for k, v in (c.get("meta") or {}).items():
                kv("meta " + k, trunc(v, 100))
            kv("tech / CDN", ", ".join(c.get("tech", [])))
            for f in c["forms"]:
                flags = " ".join(x for x in (red("PASSWORD") if f["password"] else "", yellow("sensitive:" + ",".join(f["sensitive_fields"][:3])) if f["sensitive_fields"] else "",
                                             red("CROSS-DOMAIN") if f["cross_domain"] else "", red("HTTP") if f["insecure"] else "") if x)
                kv("form", "%s %s  (%d fields) %s" % (f["method"].upper(), trunc(f["action"], 70), f["fields"], flags))
            l = c["links"]
            kv("links", "%d total, %d external, %d dead  top ext: %s" % (l["total"], l["external"], l["null_links"], ", ".join("%s(%d)" % x for x in l["top_external_domains"][:4])))
            s = c["scripts"]
            kv("scripts", "%d (%d inline bytes)  ext: %s" % (s["total"], s["inline_bytes"], ", ".join("%s(%d)" % x for x in s["external_domains"][:4])))
            kv("obfuscation", ", ".join(c["obfuscation_signals"]))
            for i in c["iframes"][:4]:
                kv("iframe", "%s%s%s" % (i["src"] or "(no src)", red(" hidden") if i["hidden"] else "", yellow(" cross-domain") if i["cross_domain"] else ""))
            for d in c["deceptive_links"][:3]:
                kv("deceptive", "%s -> %s" % (d["text"], d["href"]))
            for k, v in (c.get("iocs") or {}).items():
                kv("IOC " + k, ", ".join(v[:6]))
            fv = c.get("favicon")
            if fv:
                kv("favicon", "mmh3 %s  sha256 %s...  (%s)" % (fv["mmh3"], fv["sha256"][:12], fv["url"]))
                kv("", dim("Shodan: http.favicon.hash:%s" % fv["mmh3"]), 2, 15)
    i = m.get("intel")
    if i:
        section("THREAT INTELLIGENCE")
        kv("API keys", ", ".join(i["services_with_keys"]) or dim("none set (VT_API_KEY / GSB_API_KEY / URLHAUS_AUTH_KEY)"))
        for u, res in i["checked"].items():
            print("  " + dim(trunc(u, 100)))
            for svc, r in res.items():
                if r.get("error"):
                    line = yellow("error: %s" % r["error"])
                elif svc == "virustotal":
                    line = "not in VT database" if not r.get("found") else "malicious=%s suspicious=%s harmless=%s  %s" % (r["malicious"], r["suspicious"], r["harmless"], r["link"])
                elif svc == "safe_browsing":
                    line = red("MATCH: " + ", ".join(r["matches"])) if r["matches"] else green("clean")
                elif svc == "urlhaus":
                    line = red("LISTED (%s, %s)" % (r["threat"], r["status"])) if r.get("listed") else green("not listed")
                else:
                    line = red("LISTED") if r["listed"] else (yellow("host has other listed URLs") if r["host_listed"] else green("not listed")) + dim("  (%d URLs in feed)" % r["feed_size"])
                kv(svc, line, 4, 14)
    hs = m.get("history")
    if hs:
        section("HISTORY (WAYBACK MACHINE)")
        if hs.get("error") or hs.get("skipped"):
            print("  " + dim(hs.get("error") or hs.get("skipped")))
        elif hs.get("first_capture"):
            kv("first capture", "%s  (%s days ago)" % (hs["first_capture"], hs["age_days"]))
        else:
            print("  " + yellow("no archived captures for this host"))
    print("\n" + dim("done in %.1fs  |  skipped: %s" % (rep["elapsed_s"], ", ".join(rep["skipped"]) or "nothing")))


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser():
    ap = argparse.ArgumentParser(
        description="URL analyzer: phishing heuristics, redirect tracing, TLS, RDAP, content analysis, threat intel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="--skip values: fetch, favicon, dns, whois, intel, history\n"
               "API keys (env): VT_API_KEY, GSB_API_KEY, URLHAUS_AUTH_KEY")
    ap.add_argument("urls", nargs="*", help="URL(s); defanged input (hxxp, [.]) is accepted")
    ap.add_argument("-l", "--list", metavar="FILE", help="file with one URL per line")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the formatted report")
    ap.add_argument("-o", "--output", metavar="FILE", help="also save full results as JSON")
    ap.add_argument("--passive", action="store_true", help="never contact the target (no fetch / TLS / favicon)")
    ap.add_argument("--offline", action="store_true", help="no network at all - static URL analysis only")
    ap.add_argument("--skip", default="", help="comma-separated modules to skip")
    ap.add_argument("--max-redirects", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-bytes", type=int, default=1_500_000, help="max response body to read (default 1.5 MB)")
    ap.add_argument("--ua", help="custom User-Agent")
    ap.add_argument("--insecure", action="store_true", help="don't validate TLS certificates")
    ap.add_argument("--allow-private", action="store_true", help="allow private / loopback destinations (disables SSRF guard)")
    ap.add_argument("--default-scheme", choices=["http", "https"], default="https")
    ap.add_argument("--fail-on", choices=["moderate", "high", "critical"], help="exit with code 3 at/above this verdict")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version="url_analyzer %s" % __version__)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if os.name == "nt":
        os.system("")
    Style.on = sys.stdout.isatty() and not args.no_color and not args.json and not os.environ.get("NO_COLOR")
    CFG.update(timeout=args.timeout, max_bytes=args.max_bytes, allow_private=args.allow_private, verify=not args.insecure, cli=True)
    if args.ua:
        CFG["ua"] = args.ua
    valid = {"fetch", "favicon", "dns", "whois", "intel", "history"}
    skip = {x.strip().lower() for x in args.skip.split(",") if x.strip()}
    if skip - valid:
        print("[!] unknown --skip value(s): %s (choose from %s)" % (", ".join(sorted(skip - valid)), ", ".join(sorted(valid))), file=sys.stderr)
        return 2
    if args.passive:
        skip |= {"fetch", "favicon"}
    if args.offline:
        skip |= valid
    args.skip = sorted(skip)
    raw = list(args.urls)
    if args.list:
        with open(args.list, encoding="utf-8", errors="ignore") as f:
            raw += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not raw and sys.stdin.isatty():
        try:
            raw = [input("URL to analyze: ").strip()]
        except (EOFError, KeyboardInterrupt):
            return 130
    if not raw:
        build_parser().print_usage(sys.stderr)
        return 2
    reports, rc = [], 0
    order = {"moderate": 1, "high": 2, "critical": 3}
    for r in uniq(raw):
        try:
            rep = analyze(r, args)
        except ValueError as e:
            print("[!] %s: %s" % (trunc(r, 60), e), file=sys.stderr)
            rc = 2
            continue
        except KeyboardInterrupt:
            print("\n[!] interrupted", file=sys.stderr)
            return 130
        reports.append(rep)
        if not args.json:
            render(rep)
        if args.fail_on and rc == 0 and order.get(rep["verdict"].lower(), 0) >= order[args.fail_on]:
            rc = 3
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
