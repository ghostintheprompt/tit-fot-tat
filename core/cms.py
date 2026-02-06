"""
CMS Security Testing Module
Focus on WordPress editorial plugins and draft exposure
"""

import requests
from bs4 import BeautifulSoup
import re


VULNERABLE_PLUGINS = {
    'editflow': {
        'versions': ['0.8.1', '0.8.0', '0.7.x'],
        'vuln': 'Privilege escalation - contributors can access drafts',
        'cve': 'CVE-2023-XXXXX'
    },
    'co-authors-plus': {
        'versions': ['3.5.12', '3.5.11', '3.5.x'],
        'vuln': 'Role bypass allows unauthorized draft access',
        'cve': 'CVE-2023-YYYYY'
    },
    'advanced-custom-fields-pro': {
        'versions': ['all'],
        'vuln': 'Metadata exposure via REST API',
        'cve': 'N/A (design flaw)'
    }
}


def detect_wordpress(url):
    """
    Detect if site is running WordPress
    """
    print(f"[+] Detecting CMS type...")

    try:
        response = requests.get(url, timeout=10)
        content = response.text.lower()

        if 'wp-content' in content or 'wordpress' in content:
            print(f"    [✓] WordPress detected")

            # Try to get version
            version_match = re.search(r'wordpress ([0-9.]+)', content)
            if version_match:
                version = version_match.group(1)
                print(f"    [i] Version: {version}")
                return 'wordpress', version

            return 'wordpress', 'unknown'
        else:
            print(f"    [!] WordPress not detected")
            return None, None

    except Exception as e:
        print(f"    [!] Detection failed: {e}")
        return None, None


def scan_plugins(url):
    """
    Detect installed plugins and check for known vulnerabilities
    """
    print(f"\n[+] Scanning for editorial plugins...")

    plugins_found = []

    # Common plugin paths
    plugin_paths = [
        '/wp-content/plugins/edit-flow/readme.txt',
        '/wp-content/plugins/co-authors-plus/readme.txt',
        '/wp-content/plugins/advanced-custom-fields-pro/readme.txt',
        '/wp-content/plugins/custom-editorial-workflow/readme.txt'
    ]

    for path in plugin_paths:
        full_url = url.rstrip('/') + path
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                # Extract plugin name and version
                plugin_name = path.split('/plugins/')[1].split('/')[0]
                version_match = re.search(r'Stable tag: ([0-9.]+)', response.text)
                version = version_match.group(1) if version_match else 'unknown'

                plugins_found.append({
                    'name': plugin_name,
                    'version': version,
                    'path': path
                })

                print(f"    [✓] Found: {plugin_name} v{version}")

                # Check if vulnerable
                for vuln_plugin, details in VULNERABLE_PLUGINS.items():
                    if vuln_plugin in plugin_name:
                        if version in details['versions'] or details['versions'] == ['all']:
                            print(f"        [!] VULNERABLE: {details['vuln']}")
                            print(f"        [!] CVE: {details['cve']}")

        except:
            pass

    if not plugins_found:
        print(f"    [i] No editorial plugins detected (or paths protected)")

    return plugins_found


def test_draft_exposure(url):
    """
    Test if unpublished drafts are accessible
    """
    print(f"\n[+] Testing draft exposure...")

    exposure_points = []

    # Test REST API
    api_url = url.rstrip('/') + '/wp-json/wp/v2/posts?status=draft'
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            drafts = response.json()
            if drafts:
                print(f"    [!] CRITICAL: {len(drafts)} draft posts accessible via REST API")
                exposure_points.append({
                    'method': 'REST API',
                    'url': api_url,
                    'count': len(drafts)
                })
        elif response.status_code == 401:
            print(f"    [✓] REST API requires authentication")
    except Exception as e:
        print(f"    [i] REST API test failed: {e}")

    # Test editorial workflow URLs
    workflow_urls = [
        '/wp-admin/edit.php?post_status=draft',
        '/wp-admin/edit.php?post_status=pending',
        '/?post_type=post&post_status=draft'
    ]

    for test_url in workflow_urls:
        full_url = url.rstrip('/') + test_url
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200 and 'draft' in response.text.lower():
                print(f"    [!] Potential draft exposure: {test_url}")
                exposure_points.append({
                    'method': 'Direct URL',
                    'url': test_url,
                    'status': 'accessible'
                })
        except:
            pass

    if not exposure_points:
        print(f"    [✓] No obvious draft exposure detected")

    return exposure_points


def scan(args):
    """
    Main CMS scanning function
    """
    results = {
        'url': args.url,
        'cms_type': None,
        'cms_version': None,
        'plugins': [],
        'vulnerabilities': [],
        'draft_exposure': []
    }

    # Detect CMS
    cms_type, cms_version = detect_wordpress(args.url)
    results['cms_type'] = cms_type
    results['cms_version'] = cms_version

    if not cms_type:
        print("\n[i] Non-WordPress CMS detected or CMS hidden")
        print("[i] Limited scanning available")
        return results

    # Scan plugins
    if args.check_plugins:
        plugins = scan_plugins(args.url)
        results['plugins'] = plugins

    # Test draft exposure
    if args.check_drafts:
        exposure = test_draft_exposure(args.url)
        results['draft_exposure'] = exposure

    return results


def display_results(results):
    """
    Display CMS scan results
    """
    print("\n" + "="*70)
    print("CMS SECURITY SCAN RESULTS")
    print("="*70)

    print(f"\nTarget: {results['url']}")

    if results['cms_type']:
        print(f"CMS: {results['cms_type'].title()} {results['cms_version']}")
    else:
        print(f"CMS: Not detected")

    if results['plugins']:
        print(f"\n[+] Editorial Plugins Found: {len(results['plugins'])}")
        for plugin in results['plugins']:
            print(f"    • {plugin['name']} v{plugin['version']}")

    if results['draft_exposure']:
        print(f"\n[!] DRAFT EXPOSURE DETECTED:")
        for exposure in results['draft_exposure']:
            print(f"    • Method: {exposure['method']}")
            print(f"      URL: {exposure['url']}")

    print("\n" + "="*70)
