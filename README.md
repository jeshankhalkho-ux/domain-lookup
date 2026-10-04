# Domain Lookup

All-in-one domain intelligence lookup — passive reconnaissance with a
severity-rated findings engine.

`domain_lookup.py` is a standalone CLI. It runs on the **standard library
alone**; `dnspython` and `tldextract` are optional and only make it faster /
more precise.

## Modules

| Module | What it collects |
|---|---|
| `dns` | A/AAAA/CNAME/MX/NS/TXT/SOA/CAA, NS glue addresses, DNSSEC (DS/DNSKEY), wildcard-DNS test |
| `whois` | RDAP via the IANA bootstrap, raw WHOIS (port 43) fallback, domain age, days-to-expiry, registrar, status flags, abuse contact |
| `ssl` | TLS handshake, certificate details, SANs, expiry, hostname match, protocol support (TLS 1.0-1.3), cipher, ALPN (h2), SHA-256/SHA-1 fingerprints |
| `http` | http/https redirect chains, response headers, security-header audit, cookie flags, page title, technology/CDN hints, robots.txt, security.txt |
| `ip` | per-IP reverse DNS, ASN + prefix (Team Cymru over DNS), geolocation, hosting hint |
| `email` | MX provider, SPF (recursive lookup count), DMARC, DKIM (common selectors), MTA-STS, TLS-RPT, BIMI |
| `subs` | passive subdomains (crt.sh, HackerTarget, AlienVault OTX), resolution, dangling-CNAME hints, optional DNS brute force |

## Install

```bash
pip install -r requirements.txt   # optional accelerators
```

The script runs without them.

## Usage

```bash
python domain_lookup.py example.com
python domain_lookup.py https://www.example.co.uk/path -m dns,whois,ssl
python domain_lookup.py example.com --brute --wordlist words.txt
python domain_lookup.py -l domains.txt --json -o results.json
python domain_lookup.py 1.1.1.1                    # IP targets: rDNS, ASN, geo, TLS, HTTP
python domain_lookup.py example.com --no-color      # plain output for piping
```

### Options

```
-m, --modules      comma-separated modules (default: all)
-l, --list         file with one target per line
--json             print JSON instead of the formatted report
-o, --output       also save the full results as JSON
--timeout          network timeout in seconds (default 8)
--resolver IP      use a specific DNS server (needs dnspython)
--doh              force DNS-over-HTTPS
--tls-port PORT    TLS port to probe (default 443)
--raw-whois        include the raw WHOIS text
--brute            DNS brute force using the built-in wordlist
--wordlist FILE    custom wordlist for --brute
--max-resolve N    cap on subdomains resolved (default 300)
--max-ips N        cap on IPs profiled per target (default 8)
--threads N        concurrency for resolution/brute force (default 30)
--no-color         disable ANSI colour
```

## Findings

Every run produces severity-rated findings:

```
  [MEDIUM] http     Plain HTTP does not redirect to HTTPS
  [LOW   ] email    SPF ends in +all (anyone can send as this domain)
  [INFO  ] dns      No IPv6 (AAAA) records
```

Severities: `high`, `medium`, `low`, `info`.

## Notes

- Everything is passive or ordinary client traffic: DNS queries, public APIs,
  one TLS/HTTP connection per target. The optional `--brute` flag sends one DNS
  query per wordlist entry.
- The `created` date is the registry's first registration date for the *current*
  registration. If a domain lapsed, was deleted and re-registered, the original
  date is not published anywhere and cannot be recovered.
- Only run this against domains you own or are authorised to assess.
