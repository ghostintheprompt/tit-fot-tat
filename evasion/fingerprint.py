"""
TLS Fingerprint & Browser Profile Rotation
===========================================
Modern WAFs (Cloudflare, Akamai, AWS Shield) identify bots at the TLS handshake
layer before a single HTTP byte is read. The JA3 fingerprint hashes:

  TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePointFormats

A Python requests session using the default ssl context produces a consistent,
well-known bot JA3 that CDNs flag immediately. This module rotates cipher suite
ordering and header profiles to vary the fingerprint across requests.

References:
  - Salesforce JA3: https://github.com/salesforce/ja3
  - Cloudflare bot detection: https://blog.cloudflare.com/cloudflare-bot-management/
  - Akamai Bot Manager: https://www.akamai.com/products/bot-manager
"""

import random
import hashlib
import ssl
import requests
from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter

# ── Browser profiles with authentic header sets ───────────────────────────────

BROWSER_PROFILES = {
    "chrome_120": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.6099.130 Safari/537.36"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        # JA3 ≈ 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,...
        # Cipher suites in Chrome 120 preference order
        "ciphers": (
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:"
            "AES128-GCM-SHA256:"
            "AES256-GCM-SHA384:"
            "AES128-SHA:"
            "AES256-SHA"
        ),
        "ja3_note": "Chrome 120 signature — common, low suspicion",
    },

    "firefox_120": {
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
            "Gecko/20100101 Firefox/120.0"
        ),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.5",
        "accept_encoding": "gzip, deflate, br",
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        # JA3 ≈ 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-47-53,...
        "ciphers": (
            "TLS_AES_128_GCM_SHA256:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES256-SHA:"
            "ECDHE-RSA-AES256-SHA:"
            "ECDHE-ECDSA-AES128-SHA:"
            "ECDHE-RSA-AES128-SHA"
        ),
        "ja3_note": "Firefox 120 signature — common, low suspicion",
    },

    "safari_17": {
        "user_agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) "
            "Version/17.1 Safari/605.1.15"
        ),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        # Safari omits sec-ch-ua client hints
        "ciphers": (
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-SHA384:"
            "ECDHE-ECDSA-AES128-SHA256:"
            "ECDHE-RSA-AES256-SHA384:"
            "ECDHE-RSA-AES128-SHA256"
        ),
        "ja3_note": "Safari 17 on macOS Sonoma — distinct from Chrome/Firefox",
    },

    "chrome_mobile": {
        "user_agent": (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.6099.144 Mobile Safari/537.36"
        ),
        "accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec_ch_ua_mobile": "?1",
        "sec_ch_ua_platform": '"Android"',
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        "ciphers": (
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-CHACHA20-POLY1305"
        ),
        "ja3_note": "Chrome Mobile on Android — triggers mobile-specific WAF paths",
    },
}


# ── TLS Context Adapter ───────────────────────────────────────────────────────

class TLSFingerprintAdapter(HTTPAdapter):
    """
    HTTPAdapter that applies a custom SSL context with a specific cipher suite
    ordering to vary the JA3 fingerprint.

    Note on JA3 completeness:
    Python's ssl/urllib3 stack gives us cipher suite ordering (JA3 field 2) and
    TLS version (field 1), but extensions ordering and elliptic curve negotiation
    (fields 3-5) are partially controlled by OpenSSL internals. For research-grade
    full JA3 spoofing, use curl-impersonate or custom TLS stacks. This adapter
    provides meaningful cipher rotation that defeats simple JA3 blocklists.
    """

    def __init__(self, ciphers: str, **kwargs):
        self._ciphers = ciphers
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context(ciphers=self._ciphers)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        ctx = create_urllib3_context(ciphers=self._ciphers)
        proxy_kwargs["ssl_context"] = ctx
        return super().proxy_manager_for(proxy, **proxy_kwargs)


# ── Session Builder ───────────────────────────────────────────────────────────

def build_session(profile_name: str = None) -> tuple[requests.Session, dict]:
    """
    Create a requests.Session configured with a browser fingerprint profile.

    Returns (session, profile) so callers can log which profile was used.
    If profile_name is None, selects one at random.

    Usage:
        session, profile = build_session('chrome_120')
        resp = session.get('https://example.com')
    """
    if profile_name is None:
        profile_name = random.choice(list(BROWSER_PROFILES.keys()))
    elif profile_name not in BROWSER_PROFILES:
        raise ValueError(f"Unknown profile '{profile_name}'. Options: {list(BROWSER_PROFILES)}")

    profile = BROWSER_PROFILES[profile_name]
    session = requests.Session()

    # Mount TLS adapter for HTTPS
    adapter = TLSFingerprintAdapter(ciphers=profile["ciphers"])
    session.mount("https://", adapter)

    # Build realistic header set — order matters for fingerprinting
    headers = {}

    # Sec-Fetch-* and Sec-Ch-Ua headers are present in Chromium-based browsers only
    for key in [
        "user_agent",
        "accept",
        "accept_language",
        "accept_encoding",
        "sec_ch_ua",
        "sec_ch_ua_mobile",
        "sec_ch_ua_platform",
        "sec_fetch_dest",
        "sec_fetch_mode",
        "sec_fetch_site",
        "sec_fetch_user",
        "upgrade_insecure_requests",
    ]:
        if key in profile:
            # Convert snake_case to Header-Case
            header_name = key.replace("_", "-").title()
            if header_name == "User-Agent":
                header_name = "User-Agent"
            elif header_name == "Accept-Language":
                header_name = "Accept-Language"
            elif header_name == "Accept-Encoding":
                header_name = "Accept-Encoding"
            elif key.startswith("sec_"):
                header_name = key.replace("_", "-").replace("sec-", "Sec-")
            elif key == "upgrade_insecure_requests":
                header_name = "Upgrade-Insecure-Requests"
            headers[header_name] = profile[key]

    session.headers.update(headers)
    return session, {"profile_name": profile_name, **profile}


def rotate_session(current_profile: str = None) -> tuple[requests.Session, dict]:
    """
    Return a session with a DIFFERENT profile than the current one.
    Used to vary fingerprint between logical request groups.
    """
    available = [p for p in BROWSER_PROFILES if p != current_profile]
    return build_session(random.choice(available))


def describe_ja3_detection() -> str:
    """
    Return a plaintext explanation of JA3-based bot detection for documentation.
    """
    return """
JA3 Fingerprinting — How CDNs Detect Bots at the TLS Layer
===========================================================

JA3 (Salesforce, 2017) creates an MD5 hash from TLS ClientHello fields:
  1. TLS version (e.g., 771 = TLSv1.2, 772 = TLSv1.3)
  2. Cipher suites in order (e.g., 4865-4867-4866-...)
  3. Extensions list (e.g., 0-23-65281-10-11-35-16-5-13-18-51-45-43-27)
  4. Elliptic curves (e.g., 29-23-24)
  5. Elliptic curve point formats (e.g., 0)

Concatenated and MD5-hashed → 32-char hex fingerprint.

Default Python requests/urllib3 produces a well-known hash that Cloudflare
and Akamai flag as automated tooling. Rotating cipher suite ordering changes
field 2, producing a different hash on each session rotation.

Full JA3 replication (including extension ordering) requires curl-impersonate
or a custom TLS implementation. This module provides meaningful cipher rotation
that defeats signature-based JA3 blocklists while remaining within Python's
standard ssl module.

Detection arms race:
  Defense: JA3 → JA3S (server response fingerprint) → JARM (probing fingerprint)
  Offense: cipher rotation → full ClientHello replication → traffic normalization
"""


def compute_approximate_ja3(profile_name: str) -> str:
    """
    Compute an approximate JA3 hash for a given browser profile.
    Uses cipher suite ordering as the primary variable component.
    This is a simplified calculation — real JA3 requires live TLS capture.
    """
    if profile_name not in BROWSER_PROFILES:
        return "unknown"

    profile = BROWSER_PROFILES[profile_name]
    ciphers_str = profile.get("ciphers", "")

    # Map cipher names to their IANA numeric IDs (partial — common suites)
    cipher_ids = {
        "TLS_AES_128_GCM_SHA256": "4865",
        "TLS_AES_256_GCM_SHA384": "4866",
        "TLS_CHACHA20_POLY1305_SHA256": "4867",
        "ECDHE-ECDSA-AES128-GCM-SHA256": "49195",
        "ECDHE-RSA-AES128-GCM-SHA256": "49199",
        "ECDHE-ECDSA-CHACHA20-POLY1305": "52393",
        "ECDHE-RSA-CHACHA20-POLY1305": "52392",
        "ECDHE-ECDSA-AES256-GCM-SHA384": "49196",
        "ECDHE-RSA-AES256-GCM-SHA384": "49200",
        "ECDHE-ECDSA-AES256-SHA": "49162",
        "ECDHE-RSA-AES256-SHA": "49172",
        "ECDHE-ECDSA-AES128-SHA": "49161",
        "ECDHE-RSA-AES128-SHA": "49171",
        "AES128-GCM-SHA256": "156",
        "AES256-GCM-SHA384": "157",
        "AES128-SHA": "47",
        "AES256-SHA": "53",
        "ECDHE-ECDSA-AES256-SHA384": "49188",
        "ECDHE-RSA-AES256-SHA384": "49192",
        "ECDHE-ECDSA-AES128-SHA256": "49187",
        "ECDHE-RSA-AES128-SHA256": "49191",
    }

    cipher_nums = []
    for name in ciphers_str.split(":"):
        name = name.strip()
        if name in cipher_ids:
            cipher_nums.append(cipher_ids[name])

    # Build approximate JA3 string: version, ciphers, (extensions/curves fixed)
    ja3_str = f"771,{'-'.join(cipher_nums)},0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0"
    return hashlib.md5(ja3_str.encode()).hexdigest()


def list_profiles() -> None:
    """Print all available browser profiles with their JA3 notes."""
    print("\n[*] Available Browser Fingerprint Profiles")
    print("=" * 60)
    for name, profile in BROWSER_PROFILES.items():
        ja3_hash = compute_approximate_ja3(name)
        print(f"\n  {name}")
        print(f"    UA:   {profile['user_agent'][:60]}...")
        print(f"    JA3:  {ja3_hash} (approx)")
        print(f"    Note: {profile.get('ja3_note', '')}")
    print()
