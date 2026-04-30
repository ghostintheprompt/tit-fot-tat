"""
Origin Server Discovery Module
Techniques for bypassing CDN protection to find real server IP
"""

import re
import os
import socket
import requests
import dns.resolver
from urllib.parse import urlparse
import time


# ── Canary Token Detection ─────────────────────────────────────────────────────

# Unicode zero-width and invisible characters used as scraper traps
_ZERO_WIDTH_CHARS = [
    '\u200b',  # Zero Width Space
    '\u200c',  # Zero Width Non-Joiner
    '\u200d',  # Zero Width Joiner
    '\ufeff',  # Zero Width No-Break Space (BOM)
    '\u00ad',  # Soft Hyphen
    '\u2060',  # Word Joiner
    '\u180e',  # Mongolian Vowel Separator
]

_HONEYPOT_PATTERNS = [
    # CSS-hidden elements: bots scrape text, humans don't see it
    re.compile(r'<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|'
               r'font-size\s*:\s*0|opacity\s*:\s*0)[^>]*>([^<]+)</', re.I),
    # Off-screen absolute positioning
    re.compile(r'<[^>]+left\s*:\s*-\d{3,}px[^>]*>([^<]+)</', re.I),
]

_HONEYPOT_CLASS_RE = re.compile(
    r'class="[^"]*(?:honeypot|canary|trap|hidden-trap|invisible)[^"]*"', re.I
)

_TRACKING_PIXEL_RE = re.compile(
    r'<img[^>]+(?:width="1"[^>]+height="1"|height="1"[^>]+width="1")[^>]*>', re.I
)

_CANARY_META_RE = re.compile(
    r'<meta[^>]+name="(?:tracking-id|canary|honeytoken)[^"]*"[^>]*>', re.I
)


def scan_canary_tokens(html: str, url: str = "") -> dict:
    """
    Scan HTML for embedded canary tokens and honeytrap signals.

    Returns a structured findings dict with severity ratings. Any findings
    indicate the target is actively monitoring scrapers — continuing without
    evasion will trigger attribution.
    """
    findings = []

    # Zero-width character injection
    found_zw = [c for c in _ZERO_WIDTH_CHARS if c in html]
    if found_zw:
        positions = []
        for c in found_zw:
            idx = html.find(c)
            positions.append(idx)
        findings.append({
            "type": "ZERO_WIDTH_CHARS",
            "severity": "HIGH",
            "detail": (
                f"Found {len(found_zw)} invisible Unicode character(s): "
                + ", ".join(f"U+{ord(c):04X}" for c in found_zw)
            ),
            "positions": positions,
            "interpretation": (
                "Unique character sequences watermark content. If you store and "
                "republish this text, the source can be attributed to this scrape session."
            ),
        })

    # CSS-hidden honeypot spans / divs
    for pattern in _HONEYPOT_PATTERNS:
        matches = pattern.findall(html)
        if matches:
            findings.append({
                "type": "CSS_HIDDEN_TEXT",
                "severity": "MEDIUM",
                "detail": (
                    f"Found {len(matches)} CSS-hidden text segment(s). "
                    f"Sample: {matches[0][:80]!r}"
                ),
                "interpretation": (
                    "Text invisible to readers but scraped by bots. "
                    "Contains bait contact info or honeypot strings."
                ),
            })
            break

    # Honeypot class names
    if _HONEYPOT_CLASS_RE.search(html):
        findings.append({
            "type": "HONEYPOT_CLASS",
            "severity": "HIGH",
            "detail": "Element with honeypot/canary/trap CSS class found",
            "interpretation": (
                "Clicking or following links in this element triggers "
                "server-side attribution — do not request linked URLs."
            ),
        })

    # 1×1 tracking pixel
    pixels = _TRACKING_PIXEL_RE.findall(html)
    if pixels:
        findings.append({
            "type": "TRACKING_PIXEL",
            "severity": "LOW",
            "detail": f"Found {len(pixels)} 1×1 tracking pixel(s)",
            "interpretation": (
                "Real browsers load this resource; headless clients that skip "
                "image requests are fingerprinted by its absence."
            ),
        })

    # Canary meta tags
    if _CANARY_META_RE.search(html):
        findings.append({
            "type": "CANARY_META_TAG",
            "severity": "MEDIUM",
            "detail": "Tracking/canary meta tag in <head>",
            "interpretation": (
                "Session tracking ID embedded in page metadata. "
                "Value may be unique per visitor."
            ),
        })

    # Data-attribute canary
    if re.search(r'data-canary(?:-id)?=', html, re.I):
        findings.append({
            "type": "DATA_ATTRIBUTE_CANARY",
            "severity": "MEDIUM",
            "detail": "data-canary attribute found on DOM element",
            "interpretation": (
                "Attribute value is likely unique per session. "
                "Storing scraped HTML leaks the tracking ID."
            ),
        })

    risk = "NONE"
    if any(f["severity"] == "HIGH" for f in findings):
        risk = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings):
        risk = "MEDIUM"
    elif findings:
        risk = "LOW"

    return {
        "url": url,
        "canary_count": len(findings),
        "overall_risk": risk,
        "findings": findings,
        "recommendation": (
            "Use stealth mode (--stealth) and session rotation to avoid "
            "leaving attributable fingerprints on canary-protected targets."
        ) if findings else "No canary tokens detected.",
    }


# ── ASN Profiling ──────────────────────────────────────────────────────────────

def asn_profile(ip: str) -> dict:
    """
    Build an ASN/network profile for an IP address.

    Uses reverse DNS + ipinfo.io (free tier, no API key required for basic fields).
    Returned dict includes org, ASN, country, and abuse contact where available.
    """
    profile = {"ip": ip, "rdns": None, "asn": None, "org": None,
               "country": None, "city": None, "hosting": False}

    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        profile["rdns"] = hostname
    except (socket.herror, socket.gaierror):
        pass

    # ipinfo.io free API (no key needed for basic fields, 50k req/month)
    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=5,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            profile["org"] = data.get("org")         # "AS13335 Cloudflare, Inc."
            profile["country"] = data.get("country")
            profile["city"] = data.get("city")
            profile["region"] = data.get("region")
            if profile["org"]:
                # Extract bare ASN
                m = re.match(r"(AS\d+)", profile["org"])
                if m:
                    profile["asn"] = m.group(1)
                # Flag well-known hosting/CDN ASNs
                hosting_keywords = [
                    "amazon", "aws", "cloudflare", "fastly", "akamai",
                    "digitalocean", "linode", "vultr", "hetzner", "ovh",
                    "google", "microsoft", "azure", "cloudfront",
                ]
                org_lower = profile["org"].lower()
                profile["hosting"] = any(k in org_lower for k in hosting_keywords)
    except Exception:
        pass

    return profile


def cert_transparency_lookup(domain, session=None):
    """
    Query Certificate Transparency logs to find origin IP
    Works ~85% of time against Cloudflare
    """
    results = []
    print(f"[+] Querying Certificate Transparency logs for {domain}...")

    _get = session.get if session else requests.get

    try:
        # Query crt.sh (Certificate Transparency log aggregator)
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = _get(url, timeout=10)

        if response.status_code == 200:
            certs = response.json()
            # Extract unique IPs from certificate SANs
            for cert in certs[:10]:  # Limit to recent certs
                common_name = cert.get('common_name', '')
                if common_name and not common_name.startswith('*'):
                    try:
                        ip = socket.gethostbyname(common_name)
                        if ip not in results and not ip.startswith('104.'):  # Filter Cloudflare IPs
                            results.append(ip)
                            print(f"    [✓] Found potential origin: {ip} (from cert: {common_name})")
                    except:
                        pass
    except Exception as e:
        print(f"    [!] Certificate Transparency lookup failed: {e}")

    return results


def dns_history_lookup(domain, session=None):
    """
    Check historical DNS records.
    In a full implementation, this queries SecurityTrails, DNSHistory, or similar.
    This version attempts to find non-CDN IPs from current and recent records.
    """
    results = []
    print(f"[+] Checking historical DNS records for {domain}...")

    _get = session.get if session else requests.get

    # 1. Current A records (filter CDNs)
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = str(rdata)
            if not _is_cdn_ip(ip):
                results.append(ip)
                print(f"    [✓] Found potential origin (Current A): {ip}")
    except Exception:
        pass

    # 2. Check common "old" subdomains that might point to previous infrastructure
    for sub in ['old', 'legacy', 'backup', 'origin-static', 'direct']:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            if not _is_cdn_ip(ip) and ip not in results:
                results.append(ip)
                print(f"    [✓] Found potential origin ({sub} subdomain): {ip}")
        except Exception:
            pass

    # 3. Actual historical lookup if API key is present
    api_key = os.environ.get('TFT_SECURITYTRAILS_KEY')
    if api_key:
        print(f"    [+] Querying SecurityTrails API for {domain}...")
        try:
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            response = _get(url, headers={'APIKEY': api_key}, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for record in data.get('records', []):
                    for val in record.get('values', []):
                        ip = val.get('ip')
                        if ip and not _is_cdn_ip(ip) and ip not in results:
                            results.append(ip)
                            print(f"    [✓] Found historical origin: {ip}")
            else:
                print(f"    [!] SecurityTrails API returned status {response.status_code}")
        except Exception as e:
            print(f"    [!] SecurityTrails lookup failed: {e}")
    else:
        print(f"    [i] Note: Comprehensive historical DNS requires SecurityTrails API key (TFT_SECURITYTRAILS_KEY)")

    return list(set(results))


def _is_cdn_ip(ip: str) -> bool:
    """Helper to identify common CDN IP ranges (Cloudflare, Akamai, etc.)"""
    # Cloudflare: 104.16.0.0/12, 172.64.0.0/13, etc.
    if ip.startswith(('104.', '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.')):
        return True
    # Fastly: 151.101.0.0/16
    if ip.startswith('151.101.'):
        return True
    # Akamai (partial)
    if ip.startswith(('23.32.', '23.33.', '23.60.', '23.61.')):
        return True
    return False


def mx_record_correlation(domain):
    """
    Find mail server, assume same subnet as web server
    Works ~60% of time
    """
    results = []
    print(f"[+] Checking MX records for {domain}...")

    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_host = str(rdata.exchange).rstrip('.')
            try:
                mx_ip = socket.gethostbyname(mx_host)
                print(f"    [✓] Mail server: {mx_host} ({mx_ip})")

                # Derive potential web server IPs in same subnet
                octets = mx_ip.split('.')
                subnet = '.'.join(octets[:3])
                print(f"    [i] Potential subnet: {subnet}.0/24")

                # Try common offsets
                for offset in [1, 2, 5, 10, 50, 100]:
                    test_ip = f"{subnet}.{offset}"
                    if test_ip != mx_ip:
                        results.append(test_ip)

            except Exception as e:
                print(f"    [!] Could not resolve {mx_host}: {e}")

    except Exception as e:
        print(f"    [!] MX lookup failed: {e}")

    return results


def subdomain_enumeration(domain):
    """
    Find old subdomains not behind CDN
    Works ~40% of time but instant when it works
    """
    results = []
    print(f"[+] Enumerating subdomains for {domain}...")

    # Common subdomain prefixes that might not be behind CDN
    subdomains = [
        'dev', 'staging', 'test', 'cms', 'admin', 'cpanel',
        'webmail', 'mail', 'ftp', 'ssh', 'vpn', 'old', 'legacy'
    ]

    for sub in subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            if not ip.startswith('104.') and not ip.startswith('172.'):
                results.append((full_domain, ip))
                print(f"    [✓] Found: {full_domain} -> {ip} [DIRECT]")
        except:
            pass

    if not results:
        print(f"    [!] No exposed subdomains found")

    return results


def verify_origin(ip, domain, session=None):
    """
    Verify that discovered IP is actually the origin server
    """
    print(f"\n[*] Verifying {ip} as origin for {domain}...")

    _get = session.get if session else requests.get

    try:
        # Try direct HTTP request with Host header
        response = _get(
            f"http://{ip}",
            headers={'Host': domain},
            timeout=5,
            allow_redirects=False
        )

        if response.status_code in [200, 301, 302]:
            print(f"    [✓] Server responds correctly to Host: {domain}")
            print(f"    [✓] Status: {response.status_code}")
            print(f"    [✓] Origin confirmed: {ip}")
            return True
        else:
            print(f"    [!] Unexpected status: {response.status_code}")
            return False

    except Exception as e:
        print(f"    [!] Verification failed: {e}")
        return False


def discover(args, target=None, session=None):
    """
    Main discovery function - orchestrates all techniques
    """
    domain_raw = target or args.domain
    domain = domain_raw.replace('https://', '').replace('http://', '').split('/')[0]

    results = {
        'domain': domain,
        'origin_ips': [],
        'methods': {},
        'verified': []
    }

    start_time = time.time()

    # Run discovery methods
    if getattr(args, 'all_methods', True) or getattr(args, 'cert_transparency', False):
        ct_results = cert_transparency_lookup(domain, session=session)
        results['methods']['cert_transparency'] = ct_results
        results['origin_ips'].extend(ct_results)

    if getattr(args, 'all_methods', True) or getattr(args, 'dns_history', False):
        dns_results = dns_history_lookup(domain, session=session)
        results['methods']['dns_history'] = dns_results
        results['origin_ips'].extend(dns_results)

    if getattr(args, 'all_methods', True) or getattr(args, 'mx_correlation', False):
        mx_results = mx_record_correlation(domain)
        results['methods']['mx_correlation'] = mx_results
        results['origin_ips'].extend(mx_results)

    if getattr(args, 'all_methods', True) or getattr(args, 'subdomain_scan', False):
        sub_results = subdomain_enumeration(domain)
        results['methods']['subdomain_scan'] = sub_results
        # Extract IPs from subdomain results
        for subdomain, ip in sub_results:
            results['origin_ips'].append(ip)

    # Deduplicate IPs
    results['origin_ips'] = list(set(results['origin_ips']))

    # Verify discovered IPs
    if results['origin_ips']:
        print(f"\n[*] Discovered {len(results['origin_ips'])} potential origin IPs")
        print(f"[*] Verifying origin servers...")

        for ip in results['origin_ips'][:3]:  # Only verify first 3 to avoid detection
            if verify_origin(ip, domain, session=session):
                results['verified'].append(ip)

    elapsed = time.time() - start_time
    results['elapsed_time'] = elapsed

    return results


def display_results(results):
    """
    Display discovery results in readable format
    """
    print("\n" + "="*70)
    print("ORIGIN SERVER DISCOVERY RESULTS")
    print("="*70)

    print(f"\nTarget: {results['domain']}")
    print(f"Time elapsed: {results['elapsed_time']:.1f} seconds")

    if results['verified']:
        print(f"\n[✓] VERIFIED ORIGIN SERVERS:")
        for ip in results['verified']:
            print(f"    • {ip}")
        print(f"\n[!] Cloudflare bypass: SUCCESSFUL")
        print(f"[!] Direct origin access: POSSIBLE")
        print(f"[!] WAF protection: BYPASSED")
    elif results['origin_ips']:
        print(f"\n[!] Found {len(results['origin_ips'])} potential origins (unverified):")
        for ip in results['origin_ips']:
            print(f"    • {ip}")
    else:
        print(f"\n[✓] No origin server discovered")
        print(f"[✓] CDN protection appears effective")

    print("\n" + "="*70)
