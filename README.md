# Domain Intelligence API

Passive domain reconnaissance in one call. No API keys, no signup — every data
source is free and public.

## What it returns

| Section | Source | Data |
|---|---|---|
| `registration` | RDAP (`rdap.org`) | registrar, status, creation/expiry dates, nameservers, DNSSEC |
| `dns` | Google DoH | A, AAAA, MX, NS, TXT, CNAME, SOA + extracted emails |
| `subdomains` | crt.sh | certificate-transparency discovered subdomains |
| `tls` | direct handshake | issuer, subject, SANs, expiry, SHA-1/SHA-256 fingerprints, cipher |
| `http` | direct request | status, redirect chain, title, server, tech fingerprint, security headers |
| `geo` | ipwho.is | IP → country/city/ASN/ISP |

## Endpoints

```
GET /api/domain/info?domain=example.com     everything (composite)
GET /api/domain/whois?domain=example.com    registration only
GET /api/domain/dns?domain=example.com      DNS records only
GET /api/domain/subdomains?domain=...       crt.sh subdomains only
GET /api/domain/ssl?domain=example.com      TLS certificate only
GET /api/health
```

Input is normalised, so all of these work:
```
example.com
https://example.com/path?q=1
EXAMPLE.COM:443
```

## Run locally

```bash
pip install -r requirements.txt
python api/index.py          # http://127.0.0.1:5060
```

## Deploy

`vercel.json` is already configured for `@vercel/python`. Import the repo in
Vercel and pick the Python preset — no build settings needed.

## Example

```bash
curl "http://127.0.0.1:5060/api/domain/info?domain=github.com"
```

```json
{
  "rs": "S", "rc": "OK", "pd": {
    "domain": "github.com",
    "resolved_ips": ["20.207.73.82"],
    "registration": {
      "registrar": "MarkMonitor Inc.",
      "created": "2007-10-09T18:20:50Z",
      "expires": "2028-10-09T18:20:50Z",
      "nameservers": ["dns1.p08.nsone.net", "..."]
    },
    "subdomains": { "count": 118 },
    "tls": { "issuer": {"organizationName": "Sectigo Limited"}, "days_until_expiry": 57 },
    "http": { "status": 200, "security_score": 83 },
    "geo": [{ "ip": "20.207.73.82", "city": "Pune", "org": "Microsoft Corporation" }]
  }
}
```

## Notes

- `security_score` = percentage of the 6 checked headers present
  (`strict-transport-security`, `content-security-policy`, `x-frame-options`,
  `x-content-type-options`, `referrer-policy`, `permissions-policy`)
- Private/loopback/link-local IPs are filtered out, so the API can't be used to
  probe internal networks
- crt.sh is often rate-limited; that section retries 3× and reports
  `{"ok": false, "error": ...}` instead of failing the whole request
- Composite `/info` takes ~20s because it fans out to six upstreams