# Bot Defense Research: CDN & WAF Detection Mechanisms

## Overview

Modern web platforms layer multiple independent detection signals. No single
evasion technique defeats all of them simultaneously. This document surveys the
principal mechanisms, explains the underlying signal each captures, and maps
the corresponding countermeasures implemented in this codebase.

---

## 1. TLS Fingerprinting (JA3 / JA3S)

### Mechanism
Every TLS client announces its capabilities in a ClientHello message: the TLS
version it prefers, an ordered list of supported cipher suites, TLS extensions,
supported elliptic curves, and elliptic curve point formats. John Althouse's
JA3 algorithm hashes these five fields into a 32-character MD5 fingerprint that
is stable per library version.

```
JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats)
```

A stock Python `requests` client produces `JA3=7dc2bc3fcda09e2c0f4...`, which
appears in threat-intelligence blocklists. Cloudflare, Akamai, and PerimeterX
block known-bad JA3 hashes at the TLS layer — before any HTTP header is read.

### Detection Signal
The cipher suite order is the highest-entropy field. Python's `ssl` module
sorts ciphers differently from Chrome or Firefox. A single JA3 hash appearing
across many source IPs is a strong automation signal.

### Countermeasure (`evasion/fingerprint.py`)
The `TLSFingerprintAdapter` class creates a custom `SSLContext` with ciphers
ordered to match the target browser profile. Four browser profiles are
implemented: `chrome_120`, `firefox_120`, `safari_17`, `chrome_mobile`. Each
profile also sets matching HTTP headers (`User-Agent`, `Accept`,
`Accept-Language`, `Accept-Encoding`, `Sec-Fetch-*`).

**Limitation**: Full JA3 parity requires controlling extension ordering and
elliptic-curve negotiation parameters, which the Python `ssl` module does not
expose. Complete parity requires `curl-impersonate` or a custom TLS stack.
The implementation defeats signature-based blocklists; it does not defeat
behavioral ML models that expect consistent extension ordering.

---

## 2. HTTP Header Fingerprinting

### Mechanism
Browsers emit a characteristic set of headers in a characteristic order.
Chrome 120 always sends `Sec-Fetch-Dest`, `Sec-Fetch-Mode`, `Sec-Fetch-Site`,
and `Sec-Fetch-User` on navigational requests. It sends `Accept-Language` on
every request. These headers are absent from `requests.get()` by default.

WAF rule engines check:
- Presence of `Accept-Language` (always sent by browsers)
- Presence of `Sec-Fetch-*` headers (sent since Chrome 76 / Firefox 90)
- `Accept: */*` without Sec-Fetch headers (library default)
- `User-Agent` strings matching known libraries (`python-requests/`, `urllib/`)

### Detection Signals Logged by `defender_server.py`
| Signal | Severity | Notes |
|--------|----------|-------|
| Missing `Accept-Language` | HIGH | Browsers always send this |
| `Accept: */*` + no Sec-Fetch | MEDIUM | Library-default combination |
| Empty `User-Agent` | CRITICAL | Trivially blocked by WAFs |
| Library string in UA | CRITICAL | `python-requests`, `urllib`, `curl` |

### Countermeasure
`fingerprint.py` `build_session()` sets all headers to match the profile's
browser fingerprint including the full `Sec-Fetch-*` set.

---

## 3. Behavioral / Timing Analysis

### Mechanism
Human inter-page timing follows a log-normal distribution with a coefficient
of variation (CV = σ/μ) typically between 0.5 and 1.5. A bot making requests
at a fixed 500ms interval has CV ≈ 0 — trivially detectable.

DistilNetworks (2019) and Cloudflare Bot Fight Mode both publish that timing
regularity is among the top-three signals used by their ML classifiers. Even
jittered bots that use `random.uniform(0.5, 2.0)` produce a flat distribution
with entropy much lower than human browsing.

### Entropy Formula
```
H(X) = -Σ p_i * log₂(p_i)
```

Applied to timing intervals binned into 0.5-second buckets:

| Entropy (bits) | Classification | Detection Risk |
|----------------|----------------|----------------|
| < 1.0 | BOT_LIKE | HIGH |
| 1.0 – 2.5 | SEMI_REGULAR | MEDIUM |
| 2.5 – 4.0 | HUMAN_LIKE | LOW |
| > 4.0 | CHAOTIC | VERY_LOW |

Human reading times also exhibit occasional long pauses (distraction, re-reading)
that skew the distribution rightward. A bot using only uniform jitter produces
no tail.

### Countermeasure (`evasion/behavioral.py`)
`JitterEngine` samples from a Gaussian distribution (μ=3s, σ=1.5s) with a 12%
probability of a "distraction pause" (μ=18s, σ=6s). This produces both the
right mean interval and the heavy right tail observed in human sessions.

`NavigationRandomizer` models skip (15%), revisit (8%), and early-abandon (5%)
behaviors from the DistilNetworks taxonomy.

---

## 4. Canary Tokens / Honeytokens

### Mechanism
A canary token is a value embedded in a page that has no legitimate purpose —
only a bot that processes content indiscriminately will extract and store it.
Types in common use:

| Token Type | Embedding Method | Detection Trigger |
|------------|-----------------|-------------------|
| Zero-width Unicode | Inserted between real words | Scraper stores/republishes text |
| CSS-hidden text | `display:none`, `visibility:hidden`, `position:absolute;left:-9999px` | Scraper extracts all text nodes |
| Honeypot anchor | `<a href="…" style="display:none">` | Scraper follows all links |
| 1×1 tracking pixel | `<img width="1" height="1">` | Real browser loads it; headless doesn't |
| Data-attribute canary | `data-canary-id="UNIQUE-VALUE"` | Scraper stores DOM attributes |
| Meta tag tracking ID | `<meta name="tracking-id" content="…">` | Scraper reads all meta tags |

### Zero-Width Character Watermarking
U+200B (Zero Width Space) and U+200C (Zero Width Non-Joiner) are invisible to
readers but survive copy-paste and HTML scraping. A publisher can embed a unique
bit pattern across multiple invisible characters, creating a per-session
fingerprint. When a scraped article appears elsewhere, the zero-width sequence
identifies the source scrape session.

### Countermeasure (`core/origin.py` → `scan_canary_tokens`)
Before processing content, `scan_canary_tokens()` checks for all known canary
types and returns a structured findings report with severity ratings. The
`canary-scan` subcommand surfaces this report interactively.

**Defensive Use**: Publishers can use `defender_server.py` to verify their own
canary deployments function correctly.

---

## 5. IP Reputation and ASN Profiling

### Mechanism
Data-center IP ranges (AWS, GCP, Azure, DigitalOcean, Hetzner) appear on
commercially maintained blocklists. A request from `AS14618 Amazon.com` is
statistically much more likely to be automated than one from a residential
ISP. Cloudflare's "Bot Score" heavily weights ASN.

Reverse DNS also leaks automation: `ec2-54-x-x-x.compute-1.amazonaws.com` is
an unambiguous signal.

### Countermeasure (`core/origin.py` → `asn_profile`)
`asn_profile()` uses `ipinfo.io` to classify the target server's ASN and flags
hosting providers. The `forensic` subcommand logs this in the chain-of-custody
report so the operator knows whether they are hitting a CDN edge node or a true
origin.

For operators running from data-center IPs: use a residential proxy. This
codebase does not implement proxy rotation — that is an operational concern
outside its scope.

---

## 6. Navigation Pattern Analysis

### Mechanism
A real user session on a news site typically:
- Lands on a homepage or search result
- Reads 3–5 articles over 10–20 minutes
- Occasionally navigates back
- Follows links non-sequentially

A scraper typically:
- Requests `/`, then `/page/1`, `/page/2`, `/page/3` … sequentially
- Makes no `Referer` header transitions that match navigation
- Never requests CSS/JS assets (headless mode without resource loading)

### Countermeasure
`NavigationRandomizer.generate_sequence()` introduces probabilistic skips,
revisits, and session abandonment. The `StealthRequestor.get_many()` wrapper
applies this pattern automatically to multi-URL fetches.

---

## 7. Defender Validation Lab

`evasion/defender_server.py` implements the blue-team view: a server that
embeds all six canary types and logs every request attribute used by real WAF
rule engines. Run it locally to validate evasion techniques before pointing
them at production targets.

```bash
# Terminal 1 — start defender
python evasion/defender_server.py --port 8888

# Terminal 2 — run forensic fetch against it
python tit-for-tat.py forensic --url http://localhost:8888 --stealth --entropy-score

# Terminal 2 — run canary scan
python tit-for-tat.py canary-scan --url http://localhost:8888

# Terminal 1 — Ctrl+C generates defender report
```

The defender report shows exactly which signals your client left behind,
allowing iterative improvement of evasion parameters.

---

## References

- John Althouse, "TLS Fingerprinting with JA3 and JA3S" (Salesforce Engineering, 2019)
- DistilNetworks, "2019 Bad Bot Report" — bot behavioral taxonomy
- Cloudflare, "How Bot Fight Mode works" — timing and header analysis
- "Bot or Not? Deciphering Browser Automation" — USENIX Security 2012
- OWASP Automated Threats to Web Applications (OAT-021: Credential Cracking, OAT-007: Credential Stuffing)
