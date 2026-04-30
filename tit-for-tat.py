#!/usr/bin/env python3
"""
Tit for Tat - Newsroom Security Testing Framework
February 2026

AUTHORIZED TESTING ONLY
Unauthorized use violates federal law (CFAA, Computer Misuse Act, etc.)
"""

import argparse
import json
import sys
from core import origin, cms, rss, reporting, comments


def banner():
    """Display tool banner"""
    print("""
╔════════════════════════════════════════════════════════════════╗
║  TIT FOR TAT - Newsroom Security Testing Framework            ║
║  February 2026                                                 ║
║                                                                ║
║  AUTHORIZED TESTING ONLY                                       ║
║  Unauthorized testing = Federal crime                          ║
╚════════════════════════════════════════════════════════════════╝
""")


def main():
    banner()

    # Common parent parser for shared arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('--stealth', action='store_true',
                                help='Apply behavioral jitter and browser fingerprint rotation')

    parser = argparse.ArgumentParser(
        description='Newsroom Security Testing Framework',
        epilog='Use only on authorized targets. Unauthorized testing violates federal law.'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Origin server discovery
    origin_parser = subparsers.add_parser('origin', parents=[parent_parser], help='Discover origin server (Cloudflare bypass)')
    origin_parser.add_argument('--domain', required=True, help='Target domain')
    origin_parser.add_argument('--all-methods', action='store_true', help='Try all discovery methods')
    origin_parser.add_argument('--cert-transparency', action='store_true', help='Certificate Transparency logs')
    origin_parser.add_argument('--dns-history', action='store_true', help='Historical DNS records')
    origin_parser.add_argument('--mx-correlation', action='store_true', help='MX record correlation')
    origin_parser.add_argument('--subdomain-scan', action='store_true', help='Subdomain enumeration')

    # CMS scanning
    cms_parser = subparsers.add_parser('cms-scan', parents=[parent_parser], help='Scan CMS for vulnerabilities')
    cms_parser.add_argument('--url', required=True, help='Target URL')
    cms_parser.add_argument('--check-plugins', action='store_true', help='Check for vulnerable plugins')
    cms_parser.add_argument('--check-drafts', action='store_true', help='Test draft exposure')

    # Comment platform scanning
    comment_parser = subparsers.add_parser('comments-scan', parents=[parent_parser], help='Analyze comment platform security')
    comment_parser.add_argument('--url', required=True, help='Target URL')

    # RSS monitoring
    rss_parser = subparsers.add_parser('rss', parents=[parent_parser], help='Monitor RSS feeds for leaks')
    rss_parser.add_argument('--domain', required=True, help='Target domain')
    rss_parser.add_argument('--enumerate-all', action='store_true', help='Find all RSS feeds')
    rss_parser.add_argument('--monitor', action='store_true', help='Continuous monitoring')
    rss_parser.add_argument('--interval', type=int, default=300, help='Check interval (seconds)')

    # Full audit
    audit_parser = subparsers.add_parser('audit', parents=[parent_parser], help='Full defensive security audit')
    audit_parser.add_argument('--target', required=True, help='Target site URL/domain')
    audit_parser.add_argument('--origin-discovery', action='store_true', help='Include origin discovery')
    audit_parser.add_argument('--cms-scan', action='store_true', help='Include CMS scan')
    audit_parser.add_argument('--comments-analysis', action='store_true', help='Include comments analysis')
    audit_parser.add_argument('--rss-analysis', action='store_true', help='Include RSS analysis')
    audit_parser.add_argument('--output', help='Output report file (HTML)')

    # Forensic fetch — fetch URL, produce chain-of-custody report
    forensic_parser = subparsers.add_parser(
        'forensic', parents=[parent_parser], help='Fetch URL and produce forensic integrity report'
    )
    forensic_parser.add_argument('--url', required=True, help='URL to fetch and document')
    forensic_parser.add_argument('--output-dir', default='forensics',
                                 help='Directory for chain-of-custody JSON (default: forensics/)')
    forensic_parser.add_argument('--entropy-score', action='store_true',
                                 help='Print behavioral entropy report after fetch')

    # Canary scanner — detect honeytokens in a target page
    canary_parser = subparsers.add_parser(
        'canary-scan', parents=[parent_parser], help='Scan a URL for embedded canary tokens and honeytrap signals'
    )
    canary_parser.add_argument('--url', required=True, help='URL to scan')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Global stealth configuration
    session = None
    if getattr(args, 'stealth', False):
        print("[*] Stealth Mode: Enabled (Fingerprint rotation + Jitter)")
        session, _ = _make_session(True)
        try:
            from evasion.behavioral import StealthRequestor
            session = StealthRequestor(session.get)
        except ImportError:
            print("[!] Could not load evasion modules, using standard session")

    # Execute command
    try:
        if args.command == 'origin':
            print(f"\n[*] Starting origin server discovery for {args.domain}\n")
            results = origin.discover(args, session=session)
            origin.display_results(results)

        elif args.command == 'cms-scan':
            print(f"\n[*] Starting CMS security scan for {args.url}\n")
            results = cms.scan(args, session=session)
            cms.display_results(results)

        elif args.command == 'comments-scan':
            print(f"\n[*] Starting comment platform analysis for {args.url}\n")
            results = comments.scan(args, session=session)
            comments.display_results(results)

        elif args.command == 'rss':
            print(f"\n[*] Starting RSS analysis for {args.domain}\n")
            results = rss.analyze(args, session=session)
            rss.display_results(results)

        elif args.command == 'audit':
            print(f"\n[*] Starting full security audit for {args.target}\n")
            results = {
                'target': args.target,
                'timestamp': None
            }

            if args.origin_discovery:
                print("\n[+] Phase 1: Origin Server Discovery")
                results['origin'] = origin.discover(args, target=args.target, session=session)

            if args.cms_scan:
                print("\n[+] Phase 2: CMS Security Testing")
                results['cms'] = cms.scan(args, target=args.target, session=session)

            if args.comments_analysis:
                print("\n[+] Phase 3: Comment Platform Analysis")
                results['comments'] = comments.scan(args, target=args.target, session=session)

            if args.rss_analysis:
                print("\n[+] Phase 4: RSS Feed Analysis")
                results['rss'] = rss.analyze(args, target=args.target, session=session)

            # Generate report
            if args.output:
                print(f"\n[*] Generating report: {args.output}")
                reporting.generate_html(results, args.output)
            else:
                reporting.display_summary(results)

        elif args.command == 'forensic':
            _cmd_forensic(args, session=session)

        elif args.command == 'canary-scan':
            _cmd_canary_scan(args, session=session)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _make_session(stealth: bool):
    """Return (session, profile) with optional fingerprint rotation."""
    if stealth:
        try:
            from evasion.fingerprint import build_session
            import random
            profile_name = random.choice(["chrome_120", "firefox_120", "safari_17"])
            session, profile = build_session(profile_name)
            print(f"[*] Stealth: using browser profile '{profile_name}'")
            return session, profile
        except ImportError:
            pass

    import requests as _req
    return _req.Session(), {}


def _cmd_forensic(args, session=None):
    """fetch → chain-of-custody report, optional stealth + entropy scoring."""
    import socket as _socket
    import requests as _req

    print(f"\n[*] Forensic fetch: {args.url}\n")

    if session is None:
        _sess, profile = _make_session(getattr(args, 'stealth', False))
        _get = _sess.get
    else:
        _get = session.get

    try:
        resp = _get(args.url, timeout=15)
        content = resp.content
        source_ip = None

        # Resolve IP for ASN profiling
        from urllib.parse import urlparse as _up
        host = _up(args.url).hostname
        try:
            source_ip = _socket.gethostbyname(host)
        except Exception:
            pass

        asn = None
        if source_ip:
            print(f"[*] Resolved {host} → {source_ip}")
            asn = origin.asn_profile(source_ip)
            print(f"[*] ASN: {asn.get('org', 'unknown')} | "
                  f"Country: {asn.get('country', '?')} | "
                  f"Hosting: {asn.get('hosting', False)}")

        coc = reporting.chain_of_custody(
            url=args.url,
            content=content,
            source_ip=source_ip or "",
            asn_data=asn,
            extra={"http_status": resp.status_code,
                   "content_type": resp.headers.get("Content-Type", "")},
        )

        path = reporting.save_coc_report(coc, output_dir=args.output_dir)
        print(f"\n[+] SHA-256:    {coc['sha256']}")
        print(f"[+] HMAC-SHA256: {coc['hmac_sha256'][:16]}…")
        print(f"[+] Collected:  {coc['collected_at']}")
        print(f"[+] Report saved: {path}")

        if args.entropy_score:
            # If session is a StealthRequestor, it has entropy_report
            if hasattr(session, 'entropy_report'):
                report = session.entropy_report()
                print(f"\n[*] Behavioral Entropy Report:")
                print(f"    Entropy:       {report.get('entropy_bits', 'n/a')} bits")
                print(f"    Human-likeness:{report.get('human_likeness', 'n/a')}")
                print(f"    Detection risk:{report.get('detection_risk', 'n/a')}")

    except Exception as e:
        print(f"[!] Fetch failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def _cmd_canary_scan(args, session=None):
    """Fetch a page and report all embedded canary tokens."""
    import requests as _req

    print(f"\n[*] Canary token scan: {args.url}\n")

    if session is None:
        _sess, _ = _make_session(getattr(args, 'stealth', False))
        _get = _sess.get
    else:
        _get = session.get

    try:
        resp = _get(args.url, timeout=15)
    except Exception as e:
        print(f"[!] Fetch failed: {e}")
        sys.exit(1)

    result = origin.scan_canary_tokens(resp.text, url=args.url)

    print("=" * 60)
    print("CANARY TOKEN SCAN RESULTS")
    print("=" * 60)
    print(f"URL:          {result['url']}")
    print(f"Tokens found: {result['canary_count']}")
    print(f"Overall risk: {result['overall_risk']}")

    if result["findings"]:
        print()
        for f in result["findings"]:
            sev_color = {"HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]", "CRITICAL": "[!!]"}
            prefix = sev_color.get(f["severity"], "[?]")
            print(f"  {prefix} {f['type']} ({f['severity']})")
            print(f"      {f['detail']}")
            print(f"      → {f['interpretation']}")
            print()
    else:
        print("\n[✓] No canary tokens detected")

    print(f"Recommendation: {result['recommendation']}")
    print("=" * 60)


if __name__ == '__main__':
    main()
