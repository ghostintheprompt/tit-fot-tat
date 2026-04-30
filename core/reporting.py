"""
Reporting Module
Generate security audit reports in various formats
"""

import hashlib
import hmac
import json
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


# ── Chain of Custody ──────────────────────────────────────────────────────────

_COC_HMAC_KEY = os.environ.get("TFT_HMAC_KEY", "tit-for-tat-default-key").encode()


def chain_of_custody(
    url: str,
    content: bytes,
    source_ip: str,
    extra: Optional[Dict[str, Any]] = None,
    asn_data: Optional[Dict] = None,
) -> Dict:
    """
    Generate a Forensic Integrity Report for a single fetched resource.

    Produces a tamper-evident record linking the URL, content hash, network
    provenance, and collection timestamp. The record can be used to demonstrate
    chain of custody in legal or editorial attribution proceedings.

    Fields:
      sha256          — hex digest of raw content bytes
      hmac_sha256     — HMAC-SHA256 using TFT_HMAC_KEY env var (proves record
                        was produced by this tool instance, not forged later)
      collected_at    — ISO-8601 UTC timestamp
      collector_host  — hostname of the machine that performed the fetch
      source_ip       — IP address the content was served from
      content_length  — bytes
      asn_profile     — org/ASN/country from ipinfo.io (if provided)
    """
    sha256 = hashlib.sha256(content).hexdigest()

    report: Dict[str, Any] = {
        "schema_version": "1.0",
        "url": url,
        "source_ip": source_ip,
        "content_length": len(content),
        "sha256": sha256,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collector_host": socket.gethostname(),
    }

    if asn_data:
        report["asn_profile"] = {
            k: asn_data.get(k)
            for k in ("ip", "rdns", "asn", "org", "country", "city", "hosting")
        }

    if extra:
        report["extra"] = extra

    # HMAC over the canonical JSON body (sorted keys, no whitespace)
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["hmac_sha256"] = hmac.new(_COC_HMAC_KEY, canonical, hashlib.sha256).hexdigest()

    return report


def save_coc_report(report: Dict, output_dir: str = "forensics") -> Path:
    """Write a chain-of-custody record to disk and return the path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = report["url"].split("//")[-1].replace("/", "_").replace(":", "-")[:60]
    path = out / f"coc_{ts}_{slug}.json"
    path.write_text(json.dumps(report, indent=2))
    return path


def generate_html(results, output_file):
    """
    Generate HTML security audit report
    """
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Tit for Tat Security Audit Report</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background: #0a1628;
            color: #f5f1e3;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1 {{
            color: #f0c825;
            border-bottom: 2px solid #f0c825;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #f0c825;
            margin-top: 30px;
        }}
        .critical {{
            background: #ff4444;
            color: white;
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #cc0000;
        }}
        .warning {{
            background: #ffaa00;
            color: black;
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #cc8800;
        }}
        .info {{
            background: #333;
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #666;
        }}
        .success {{
            background: #44ff44;
            color: black;
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #00cc00;
        }}
        pre {{
            background: #1a1a1a;
            padding: 15px;
            overflow-x: auto;
            border: 1px solid #333;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <h1>Tit for Tat Security Audit Report</h1>
    <div class="info">
        <strong>Target:</strong> {results['target']}<br>
        <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
        <strong>Framework:</strong> Tit for Tat v0.1.0
    </div>
"""

    # Origin Server Discovery Section
    if 'origin' in results:
        html += "<h2>Origin Server Discovery</h2>"
        origin = results['origin']

        if origin.get('verified'):
            html += f"""
<div class="critical">
    <strong>CRITICAL: Origin Server Exposed</strong><br>
    Cloudflare bypass successful. Direct origin access possible.<br>
    Verified IPs: {', '.join(origin['verified'])}
</div>
<div class="info">
    WAF protection: BYPASSED<br>
    Rate limiting: BYPASSED<br>
    DDoS protection: INEFFECTIVE
</div>
"""
        else:
            html += """
<div class="success">
    No origin server exposure detected.<br>
    CDN protection appears effective.
</div>
"""

    # CMS Security Section
    if 'cms' in results:
        html += "<h2>CMS Security Analysis</h2>"
        cms = results['cms']

        if cms.get('cms_type'):
            html += f"""
<div class="info">
    <strong>CMS Detected:</strong> {cms['cms_type'].title()} {cms.get('cms_version', 'unknown')}<br>
</div>
"""

            if cms.get('plugins'):
                html += "<h3>Editorial Plugins Found</h3><ul>"
                for plugin in cms['plugins']:
                    html += f"<li>{plugin['name']} v{plugin['version']}</li>"
                html += "</ul>"

            if cms.get('draft_exposure'):
                html += """
<div class="critical">
    <strong>CRITICAL: Draft Content Exposure Detected</strong><br>
    Unpublished content may be accessible to unauthorized users.
</div>
<ul>
"""
                for exposure in cms['draft_exposure']:
                    html += f"<li>{exposure['method']}: {exposure['url']}</li>"
                html += "</ul>"

            if cms.get('metadata_leaks', {}).get('leaks'):
                html += """
<div class="warning">
    <strong>WARNING: Metadata Persistence Detected</strong><br>
    Sensitive metadata (EXIF/PDF Info) found in served media.
</div>
<ul>
"""
                for leak in cms['metadata_leaks']['leaks']:
                    html += f"<li>{leak['type']} in {leak['source']} ({leak.get('severity', 'LOW')})</li>"
                html += "</ul>"

    # Comment Platform Section
    if 'comments' in results:
        html += "<h2>Comment Platform Analysis</h2>"
        comm = results['comments']

        if comm.get('platform'):
            html += f"<div class='info'><strong>Platform:</strong> {comm['platform'].title()}</div>"

            if comm.get('moderators'):
                html += "<h3>Potential Moderators Found</h3><ul>"
                for mod in comm['moderators']:
                    html += f"<li>{mod['name']} ({mod['type']})</li>"
                html += "</ul>"

            if comm.get('phishing_vectors'):
                html += "<div class='warning'><strong>PHISHING VECTORS DETECTED</strong></div><ul>"
                for vector in comm['phishing_vectors']:
                    html += f"<li>{vector['type']}: {vector['detail']}</li>"
                html += "</ul>"

            if comm.get('auth_security'):
                auth = comm['auth_security']
                html += f"""
<div class="info">
    <strong>Auth Security:</strong><br>
    Requires Login: {'Yes' if auth.get('requires_auth') else 'No'}<br>
    CAPTCHA: {'Present' if auth.get('has_captcha') else 'Absent'}<br>
    CSRF Protection: {'Present' if auth.get('has_nonce') else 'Absent'}
</div>
"""

    # RSS Feed Analysis Section
    if 'rss' in results:
        html += "<h2>RSS Feed Analysis</h2>"
        rss = results['rss']

        if rss.get('feeds'):
            html += f"<div class='info'><strong>Feeds Discovered:</strong> {len(rss['feeds'])}</div>"
            html += "<ul>"
            for feed in rss['feeds']:
                html += f"<li>{feed}</li>"
            html += "</ul>"

            if rss.get('issues'):
                html += """
<div class="critical">
    <strong>SECURITY ISSUES DETECTED IN RSS FEEDS</strong>
</div>
<ul>
"""
                for issue in rss['issues']:
                    if issue['type'] == 'draft_leak':
                        html += f"<li>Draft/Embargo leak: {issue['indicator']}</li>"
                    elif issue['type'] == 'pii_leak':
                        html += f"<li>PII/Source information leak detected</li>"
                html += "</ul></div>"

    # Recommendations
    html += """
<h2>Recommendations</h2>
<div class="warning">
    <strong>Immediate Actions Required:</strong>
    <ul>
"""

    if results.get('origin', {}).get('verified'):
        html += """
        <li>Configure origin server to reject requests not from Cloudflare IPs</li>
        <li>Rotate server IP address if possible</li>
        <li>Enable additional origin protection measures</li>
"""

    if results.get('cms', {}).get('draft_exposure'):
        html += """
        <li>Restrict REST API access to authenticated users only</li>
        <li>Audit and update editorial workflow plugins</li>
        <li>Implement proper role-based access control</li>
"""

    if results.get('rss', {}).get('issues'):
        html += """
        <li>Audit all RSS feeds for draft/embargo content leaks</li>
        <li>Filter RSS feeds by publication status</li>
        <li>Remove PII and source information from feed descriptions</li>
"""

    html += """
    </ul>
</div>

<div class="footer">
    <strong>Tit for Tat - Newsroom Security Testing Framework</strong><br>
    Report generated for authorized security testing only.<br>
    Protect the press. Even when it's complicated.
</div>
</body>
</html>
"""

    # Write report
    with open(output_file, 'w') as f:
        f.write(html)

    print(f"[✓] HTML report generated: {output_file}")


def display_summary(results):
    """
    Display text summary of audit results
    """
    print("\n" + "="*70)
    print("SECURITY AUDIT SUMMARY")
    print("="*70)

    print(f"\nTarget: {results['target']}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Count issues
    critical_count = 0
    warning_count = 0

    if results.get('origin', {}).get('verified'):
        critical_count += 1

    if results.get('cms', {}).get('draft_exposure'):
        critical_count += len(results['cms']['draft_exposure'])

    if results.get('cms', {}).get('metadata_leaks', {}).get('leaks'):
        warning_count += len(results['cms']['metadata_leaks']['leaks'])

    if results.get('comments', {}).get('phishing_vectors'):
        warning_count += len(results['comments']['phishing_vectors'])

    if results.get('rss', {}).get('issues'):
        critical_count += len(results['rss']['issues'])

    print(f"\n[!] Critical Issues: {critical_count}")
    print(f"[!] Warnings: {warning_count}")

    if critical_count > 0 or warning_count > 0:
        print("\n[!] VULNERABILITIES DETECTED")

        if results.get('origin', {}).get('verified'):
            print("    • Origin server exposed (Cloudflare bypass) [CRITICAL]")

        if results.get('cms', {}).get('draft_exposure'):
            print(f"    • Draft content exposure ({len(results['cms']['draft_exposure'])} endpoints) [CRITICAL]")

        if results.get('rss', {}).get('issues'):
            print(f"    • RSS feed information leaks ({len(results['rss']['issues'])} issues) [CRITICAL]")

        if results.get('cms', {}).get('metadata_leaks', {}).get('leaks'):
            print(f"    • Metadata persistence in media ({len(results['cms']['metadata_leaks']['leaks'])} leaks) [WARNING]")

        if results.get('comments', {}).get('phishing_vectors'):
            print(f"    • Comment phishing vectors ({len(results['comments']['phishing_vectors'])} vectors) [WARNING]")

    else:
        print("\n[✓] No critical vulnerabilities detected")
        print("[✓] Basic security posture appears sound")

    print("\n" + "="*70)
