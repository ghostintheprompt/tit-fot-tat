# Threat Model: Automated Scraping Against News Organizations

## Scope

This document models the threat landscape facing newsrooms from automated
scraping, and how the techniques in this tool relate to both offensive
(adversary TTPs) and defensive (publisher countermeasures) postures.

---

## Assets at Risk

| Asset | Sensitivity | Threat |
|-------|-------------|--------|
| Pre-publication drafts | CRITICAL | Competitive intelligence, source exposure |
| Source identity (bylines, contact metadata) | HIGH | Journalist/source targeting |
| Editorial calendar / story slugs | HIGH | Story tipping |
| Paywall content | MEDIUM | Revenue loss, CFAA exposure |
| Proprietary analytics data in HTML | LOW–MEDIUM | Competitive intelligence |

---

## Adversary Classes

### Class A — Aggregators (Opportunistic)
**Goal**: Build searchable content corpus for SEO arbitrage or LLM training.  
**Capability**: High volume, commodity tools (Scrapy, Puppeteer), no stealth.  
**Indicators**: High request rate, obvious library UAs, no session state.

### Class B — Competitive Intelligence (Targeted)
**Goal**: Monitor specific publications for story leads before publication.  
**Capability**: Moderate stealth, targeted URLs, scheduling around publish cycles.  
**Indicators**: Periodic polling of `/feed/`, `/wp-json/wp/v2/posts?status=draft`,
slug-prediction requests.

### Class C — Nation-State / Advanced (APT)
**Goal**: Source identification, journalist surveillance, operational security.  
**Capability**: Residential proxies, browser-like fingerprints, long dwell times.  
**Indicators**: Often indistinguishable from human traffic at network layer;
detected through behavioral ML or canary token triggers.

---

## Attack Surface

### 1. CDN Bypass → Origin Exposure
A WAF only protects the origin if all traffic routes through it. Direct origin
access bypasses rate limiting, IP blocking, and WAF rules entirely.

**Vector**: Certificate Transparency logs, historical DNS, MX record
correlation, subdomain enumeration (see `core/origin.py`).

**Severity**: CRITICAL — all other controls are neutralized.

**Mitigation**: Origin servers should reject requests not originating from
CDN IP ranges (Cloudflare publishes its IP list at
`https://www.cloudflare.com/ips/`). Rotate origin IP after exposure.

### 2. REST API Draft Exposure
WordPress's REST API (`/wp-json/wp/v2/posts?status=draft`) returns draft
content to unauthenticated clients when the `rest_is_request_to_rest_api`
filter is not gated on authentication.

**Vector**: Direct API enumeration (see `core/cms.py`).

**Severity**: CRITICAL — pre-publication content exposed.

**Mitigation**: Add `rest_authentication_errors` filter; restrict draft status
queries to authenticated users.

### 3. RSS Feed Metadata Leakage
RSS feeds generated during editorial workflow often include draft titles,
author email addresses, and scheduled timestamps in the feed description or
`<author>` element before formal publication.

**Vector**: RSS enumeration and pattern matching (see `core/rss.py`).

**Severity**: HIGH — can expose embargoed stories and source identities.

**Mitigation**: Generate RSS feeds from published content only; filter `<author>`
to display names rather than email addresses.

### 4. Image EXIF / Document Metadata
Photos uploaded by journalists or sources may contain GPS coordinates, camera
model, and creation timestamp in EXIF data. PDF documents submitted by sources
frequently contain author metadata from word processors.

**Vector**: Image/PDF metadata extraction (see `core/cms.py`
→ `check_metadata_persistence`).

**Severity**: HIGH — can geolocate sources or identify devices.

**Mitigation**: Strip metadata on upload (WordPress: install ExifCleaner or
Imsanity; nginx: use `image_filter` module). Educate journalists to scrub files
before submission.

### 5. Canary Token / Honeytoken Triggering
Publishers embed invisible tokens to detect and attribute automated access.
An unsophisticated scraper that follows all links, stores all text, or loads
all images will trigger multiple canary tokens, generating a forensic record
linking the scraper's IP, UA, and timing to a specific content request.

**Vector**: Zero-width characters, CSS-hidden text, honeypot anchors, 1×1
pixels (see `core/origin.py` → `scan_canary_tokens`).

**Severity** (to the scraper operator): HIGH — creates evidentiary record for
legal proceedings.

**Countermeasure**: Scan for canary tokens before extracting content; apply
stealth mode to avoid leaving attributable fingerprints.

---

## Detection Evasion — Stealth Techniques Implemented

| Technique | Module | Defeats |
|-----------|--------|---------|
| Browser cipher suite order | `evasion/fingerprint.py` | JA3 blocklists |
| Browser-matching HTTP headers | `evasion/fingerprint.py` | Header fingerprint rules |
| Profile rotation across sessions | `evasion/fingerprint.py` | Per-session JA3 correlation |
| Gaussian inter-request jitter | `evasion/behavioral.py` | Timing regularity detectors |
| Distraction pause simulation | `evasion/behavioral.py` | CV-based ML classifiers |
| Non-linear navigation | `evasion/behavioral.py` | Sequential traversal patterns |
| Canary token pre-scan | `core/origin.py` | Honeytoken attribution |
| ASN profiling | `core/origin.py` | Awareness of detection risk by IP class |

---

## Chain of Custody

The `forensic` subcommand produces a tamper-evident record for each fetch:

```json
{
  "schema_version": "1.0",
  "url": "https://example.com/article",
  "source_ip": "104.21.x.x",
  "content_length": 42831,
  "sha256": "a3f2…",
  "collected_at": "2026-04-17T14:32:01+00:00",
  "collector_host": "research-box",
  "asn_profile": {"asn": "AS13335", "org": "AS13335 Cloudflare, Inc.", "hosting": true},
  "hmac_sha256": "7c91…"
}
```

The HMAC (keyed by `TFT_HMAC_KEY`) proves the record was produced by an
authorized instance of this tool — not fabricated after the fact. This supports
editorial verification workflows where provenance of scraped evidence must be
established.

---

## Legal Context

This tool is designed for authorized security testing of news organization
infrastructure by journalists, security researchers, and defenders. All
techniques demonstrated here are:

- **Documented** as known adversary TTPs in academic literature
- **Defensible** in the context of responsible disclosure and journalism security
- **Logged** with chain-of-custody records that support legal review

Unauthorized use against systems you do not own or have explicit written
permission to test violates:
- Computer Fraud and Abuse Act (18 U.S.C. § 1030) — USA
- Computer Misuse Act 1990 — UK
- Equivalent statutes in most jurisdictions

The defender server (`evasion/defender_server.py`) exists to demonstrate the
blue-team perspective: every technique here leaves a traceable footprint when
the target operator is paying attention.
