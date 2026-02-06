#!/usr/bin/env python3
"""
Tit for Tat - Newsroom Security Testing Framework
February 2026

AUTHORIZED TESTING ONLY
Unauthorized use violates federal law (CFAA, Computer Misuse Act, etc.)
"""

import argparse
import sys
from core import origin, cms, rss, reporting


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

    parser = argparse.ArgumentParser(
        description='Newsroom Security Testing Framework',
        epilog='Use only on authorized targets. Unauthorized testing violates federal law.'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Origin server discovery
    origin_parser = subparsers.add_parser('origin', help='Discover origin server (Cloudflare bypass)')
    origin_parser.add_argument('--domain', required=True, help='Target domain')
    origin_parser.add_argument('--all-methods', action='store_true', help='Try all discovery methods')
    origin_parser.add_argument('--cert-transparency', action='store_true', help='Certificate Transparency logs')
    origin_parser.add_argument('--dns-history', action='store_true', help='Historical DNS records')
    origin_parser.add_argument('--mx-correlation', action='store_true', help='MX record correlation')
    origin_parser.add_argument('--subdomain-scan', action='store_true', help='Subdomain enumeration')

    # CMS scanning
    cms_parser = subparsers.add_parser('cms-scan', help='Scan CMS for vulnerabilities')
    cms_parser.add_argument('--url', required=True, help='Target URL')
    cms_parser.add_argument('--check-plugins', action='store_true', help='Check for vulnerable plugins')
    cms_parser.add_argument('--check-drafts', action='store_true', help='Test draft exposure')

    # RSS monitoring
    rss_parser = subparsers.add_parser('rss', help='Monitor RSS feeds for leaks')
    rss_parser.add_argument('--domain', required=True, help='Target domain')
    rss_parser.add_argument('--enumerate-all', action='store_true', help='Find all RSS feeds')
    rss_parser.add_argument('--monitor', action='store_true', help='Continuous monitoring')
    rss_parser.add_argument('--interval', type=int, default=300, help='Check interval (seconds)')

    # Full audit
    audit_parser = subparsers.add_parser('audit', help='Full defensive security audit')
    audit_parser.add_argument('--target', required=True, help='Target site URL/domain')
    audit_parser.add_argument('--origin-discovery', action='store_true', help='Include origin discovery')
    audit_parser.add_argument('--cms-scan', action='store_true', help='Include CMS scan')
    audit_parser.add_argument('--rss-analysis', action='store_true', help='Include RSS analysis')
    audit_parser.add_argument('--output', help='Output report file (HTML)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    try:
        if args.command == 'origin':
            print(f"\n[*] Starting origin server discovery for {args.domain}\n")
            results = origin.discover(args)
            origin.display_results(results)

        elif args.command == 'cms-scan':
            print(f"\n[*] Starting CMS security scan for {args.url}\n")
            results = cms.scan(args)
            cms.display_results(results)

        elif args.command == 'rss':
            print(f"\n[*] Starting RSS analysis for {args.domain}\n")
            results = rss.analyze(args)
            rss.display_results(results)

        elif args.command == 'audit':
            print(f"\n[*] Starting full security audit for {args.target}\n")
            results = {
                'target': args.target,
                'timestamp': None
            }

            if args.origin_discovery:
                print("\n[+] Phase 1: Origin Server Discovery")
                origin_args = argparse.Namespace(domain=args.target, all_methods=True)
                results['origin'] = origin.discover(origin_args)

            if args.cms_scan:
                print("\n[+] Phase 2: CMS Security Testing")
                cms_args = argparse.Namespace(url=args.target, check_plugins=True, check_drafts=True)
                results['cms'] = cms.scan(cms_args)

            if args.rss_analysis:
                print("\n[+] Phase 3: RSS Feed Analysis")
                rss_args = argparse.Namespace(domain=args.target, enumerate_all=True, monitor=False)
                results['rss'] = rss.analyze(rss_args)

            # Generate report
            if args.output:
                print(f"\n[*] Generating report: {args.output}")
                reporting.generate_html(results, args.output)
            else:
                reporting.display_summary(results)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
