"""
RSS Feed Analysis Module
Detect leaking RSS feeds that expose drafts and embargoed content
"""

import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import re
import time


def discover_feeds(domain):
    """
    Find all RSS/Atom feeds for a domain
    """
    print(f"[+] Discovering RSS feeds for {domain}...")

    feeds_found = []
    base_url = f"https://{domain}"

    # Common RSS feed paths
    common_paths = [
        '/feed',
        '/rss',
        '/feed.xml',
        '/rss.xml',
        '/atom.xml',
        '/feed/',
        '/blog/feed',
        '/news/feed',
        '/category/investigations/feed',
        '/drafts/feed',  # Misconfigured draft feed
        '/author/*/feed',
    ]

    for path in common_paths:
        test_url = base_url + path
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'xml' in content_type or 'rss' in content_type or 'atom' in content_type:
                    feeds_found.append(test_url)
                    print(f"    [✓] Found: {test_url}")
        except:
            pass

    # Parse homepage for feed links
    try:
        response = requests.get(base_url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Look for feed links in HTML
        for link in soup.find_all('link', type=re.compile('(rss|atom)')):
            feed_url = link.get('href')
            if feed_url and feed_url not in feeds_found:
                if feed_url.startswith('http'):
                    feeds_found.append(feed_url)
                else:
                    feeds_found.append(base_url + feed_url)
                print(f"    [✓] Found: {feed_url}")

    except Exception as e:
        print(f"    [i] Homepage parse failed: {e}")

    if not feeds_found:
        print(f"    [!] No RSS feeds discovered")

    return feeds_found


def analyze_feed(feed_url):
    """
    Analyze RSS feed for sensitive information leaks
    """
    print(f"\n[+] Analyzing feed: {feed_url}")

    issues = []

    try:
        response = requests.get(feed_url, timeout=10)
        content = response.text

        # Parse XML
        root = ET.fromstring(content)

        # Count items
        items = root.findall('.//item') or root.findall('.//{http://www.w3.org/2005/Atom}entry')
        print(f"    [i] Items found: {len(items)}")

        for idx, item in enumerate(items[:5]):  # Check first 5 items
            # Extract title and description
            title_elem = item.find('title') or item.find('{http://www.w3.org/2005/Atom}title')
            desc_elem = item.find('description') or item.find('{http://www.w3.org/2005/Atom}summary')

            title = title_elem.text if title_elem is not None else ''
            description = desc_elem.text if desc_elem is not None else ''

            # Check for draft/embargo indicators
            draft_indicators = [
                'DRAFT', 'draft', 'Draft',
                'EMBARGO', 'embargo', 'Embargo',
                '[INTERNAL]', 'internal',
                'DO NOT PUBLISH', 'unpublished',
                'CONFIDENTIAL'
            ]

            for indicator in draft_indicators:
                if indicator in title or indicator in description:
                    print(f"    [!] LEAK DETECTED in item {idx + 1}")
                    print(f"        Title: {title[:80]}")
                    issues.append({
                        'type': 'draft_leak',
                        'indicator': indicator,
                        'title': title
                    })
                    break

            # Check for source information in description
            source_patterns = [
                r'source[:\s]+([a-zA-Z\s]+)',
                r'contact[:\s]+([a-zA-Z\s]+)',
                r'meeting[:\s]+\d{1,2}[/\-]\d{1,2}',
                r'\b\d{3}[-.]\d{3}[-.]\d{4}\b',  # Phone numbers
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Emails
            ]

            for pattern in source_patterns:
                matches = re.findall(pattern, description)
                if matches:
                    print(f"    [!] SENSITIVE INFO in item {idx + 1}")
                    print(f"        Pattern: {pattern}")
                    issues.append({
                        'type': 'pii_leak',
                        'pattern': pattern,
                        'matches': matches
                    })

    except Exception as e:
        print(f"    [!] Feed analysis failed: {e}")

    return issues


def monitor_feeds(domain, feeds, interval):
    """
    Continuously monitor feeds for changes
    """
    print(f"\n[*] Starting continuous monitoring (interval: {interval}s)")
    print(f"[*] Press Ctrl+C to stop\n")

    seen_items = set()

    try:
        while True:
            for feed_url in feeds:
                try:
                    response = requests.get(feed_url, timeout=10)
                    root = ET.fromstring(response.text)
                    items = root.findall('.//item') or root.findall('.//{http://www.w3.org/2005/Atom}entry')

                    for item in items[:5]:
                        # Create unique ID for item
                        title_elem = item.find('title') or item.find('{http://www.w3.org/2005/Atom}title')
                        guid_elem = item.find('guid') or item.find('{http://www.w3.org/2005/Atom}id')

                        title = title_elem.text if title_elem is not None else ''
                        guid = guid_elem.text if guid_elem is not None else title

                        item_id = f"{feed_url}:{guid}"

                        if item_id not in seen_items:
                            seen_items.add(item_id)

                            # Check for leaks in new items
                            draft_indicators = ['DRAFT', 'EMBARGO', 'INTERNAL', 'CONFIDENTIAL']
                            if any(ind in title for ind in draft_indicators):
                                print(f"[!] ALERT: New potentially leaked item")
                                print(f"    Feed: {feed_url}")
                                print(f"    Title: {title}")
                                print(f"    Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

                except Exception as e:
                    print(f"[!] Monitor error for {feed_url}: {e}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n[*] Monitoring stopped")


def analyze(args):
    """
    Main RSS analysis function
    """
    domain = args.domain.replace('https://', '').replace('http://', '').split('/')[0]

    results = {
        'domain': domain,
        'feeds': [],
        'issues': []
    }

    # Discover feeds
    if args.enumerate_all:
        feeds = discover_feeds(domain)
        results['feeds'] = feeds

        # Analyze each feed
        for feed_url in feeds:
            issues = analyze_feed(feed_url)
            if issues:
                results['issues'].extend(issues)

    # Start monitoring if requested
    if args.monitor and results['feeds']:
        monitor_feeds(domain, results['feeds'], args.interval)

    return results


def display_results(results):
    """
    Display RSS analysis results
    """
    print("\n" + "="*70)
    print("RSS FEED ANALYSIS RESULTS")
    print("="*70)

    print(f"\nDomain: {results['domain']}")
    print(f"Feeds discovered: {len(results['feeds'])}")

    if results['feeds']:
        print(f"\n[+] RSS Feeds:")
        for feed in results['feeds']:
            print(f"    • {feed}")

    if results['issues']:
        print(f"\n[!] SECURITY ISSUES FOUND:")
        for issue in results['issues']:
            if issue['type'] == 'draft_leak':
                print(f"    • Draft/Embargo leak: {issue['indicator']}")
                print(f"      Title: {issue['title'][:80]}")
            elif issue['type'] == 'pii_leak':
                print(f"    • PII/Source leak detected")
                print(f"      Pattern: {issue['pattern']}")
    else:
        print(f"\n[✓] No obvious leaks detected in RSS feeds")

    print("\n" + "="*70)
