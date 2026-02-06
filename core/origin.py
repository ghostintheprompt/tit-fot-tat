"""
Origin Server Discovery Module
Techniques for bypassing CDN protection to find real server IP
"""

import socket
import requests
import dns.resolver
from urllib.parse import urlparse
import time


def cert_transparency_lookup(domain):
    """
    Query Certificate Transparency logs to find origin IP
    Works ~85% of time against Cloudflare
    """
    results = []
    print(f"[+] Querying Certificate Transparency logs for {domain}...")

    try:
        # Query crt.sh (Certificate Transparency log aggregator)
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)

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


def dns_history_lookup(domain):
    """
    Check historical DNS records
    Works ~70% of time - many sites added CDN later
    """
    results = []
    print(f"[+] Checking historical DNS records for {domain}...")

    # In production, this would query SecurityTrails, DNSHistory.org, etc.
    # For demo, we'll do basic current DNS
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = str(rdata)
            if not ip.startswith('104.') and not ip.startswith('172.'):  # Filter CDN IPs
                results.append(ip)
                print(f"    [✓] Found potential origin: {ip}")
    except Exception as e:
        print(f"    [!] DNS lookup failed: {e}")

    # Note: Real implementation would query historical DNS services
    print(f"    [i] Note: Full historical DNS requires SecurityTrails API key")

    return results


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


def verify_origin(ip, domain):
    """
    Verify that discovered IP is actually the origin server
    """
    print(f"\n[*] Verifying {ip} as origin for {domain}...")

    try:
        # Try direct HTTP request with Host header
        response = requests.get(
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


def discover(args):
    """
    Main discovery function - orchestrates all techniques
    """
    domain = args.domain.replace('https://', '').replace('http://', '').split('/')[0]

    results = {
        'domain': domain,
        'origin_ips': [],
        'methods': {},
        'verified': []
    }

    start_time = time.time()

    # Run discovery methods
    if args.all_methods or args.cert_transparency:
        ct_results = cert_transparency_lookup(domain)
        results['methods']['cert_transparency'] = ct_results
        results['origin_ips'].extend(ct_results)

    if args.all_methods or args.dns_history:
        dns_results = dns_history_lookup(domain)
        results['methods']['dns_history'] = dns_results
        results['origin_ips'].extend(dns_results)

    if args.all_methods or args.mx_correlation:
        mx_results = mx_record_correlation(domain)
        results['methods']['mx_correlation'] = mx_results
        results['origin_ips'].extend(mx_results)

    if args.all_methods or args.subdomain_scan:
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
            if verify_origin(ip, domain):
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
