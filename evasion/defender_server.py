#!/usr/bin/env python3
"""
Detection Validation Server — Blue Team View
=============================================
Acts as the "Defender" in a scraper forensics lab.

Serves a test page embedded with canary tokens and logging hooks.
When any client (including tit-for-tat itself) scrapes it, the server
records every footprint the scraper leaves. After the test, it generates
a "Defender's Report" showing exactly what signals a real SOC analyst or
WAF rule engine would see.

This demonstrates both sides of the detection problem:
  Red:  "Can I avoid leaving fingerprints?"
  Blue: "Here is exactly what you left behind."

Usage:
  # Terminal 1: start the defender server
  python evasion/defender_server.py --port 8888 --output defender_report.json

  # Terminal 2: run tit-for-tat against it
  python tit-for-tat.py origin --domain localhost:8888
  python tit-for-tat.py forensic --url http://localhost:8888 --stealth

  # Terminal 1: Ctrl+C to stop and generate report
"""

import json
import time
import hashlib
import argparse
import threading
from datetime import datetime, timezone
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Dict
from pathlib import Path

# Canary tokens embedded in the served page — any scraper that reads and
# stores these values reveals it processed content indiscriminately
CANARY_TOKENS = {
    "honeypot_anchor": "http://canary.localhost/track/a7f3e291",
    "invisible_image": "http://canary.localhost/pixel/b2c8d445.gif",
    "zero_width_text": "Confidential\u200bReport\u200c2026",  # contains ZWSP + ZWNJ
    "css_hidden_email": "source-trap@honeypot.internal",
    "meta_tracking_id": "CANARY-SESSION-9f2a1b3c",
}

_access_log: List[Dict] = []
_log_lock = threading.Lock()


def _log_request(handler: BaseHTTPRequestHandler, canary_hit: bool = False):
    """Record a request in the access log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "timestamp_unix": time.time(),
        "remote_addr": handler.client_address[0],
        "method": handler.command,
        "path": handler.path,
        "user_agent": handler.headers.get("User-Agent", ""),
        "accept": handler.headers.get("Accept", ""),
        "accept_language": handler.headers.get("Accept-Language", ""),
        "accept_encoding": handler.headers.get("Accept-Encoding", ""),
        "referer": handler.headers.get("Referer", ""),
        "sec_fetch_dest": handler.headers.get("Sec-Fetch-Dest", ""),
        "sec_fetch_mode": handler.headers.get("Sec-Fetch-Mode", ""),
        "sec_fetch_site": handler.headers.get("Sec-Fetch-Site", ""),
        "connection": handler.headers.get("Connection", ""),
        "cookie": bool(handler.headers.get("Cookie")),
        "canary_hit": canary_hit,
        # Fingerprint analysis
        "has_sec_headers": bool(handler.headers.get("Sec-Fetch-Dest")),
        "accepts_all": "*/*" in handler.headers.get("Accept", ""),
        "no_language": not bool(handler.headers.get("Accept-Language")),
    }

    with _log_lock:
        _access_log.append(entry)


def _build_test_page() -> bytes:
    """
    Build a test HTML page with embedded canary tokens of every type.
    The tokens are subtle enough that a human viewer wouldn't notice them.
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="tracking-id" content="{CANARY_TOKENS['meta_tracking_id']}">
  <title>Research Portal</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }}
    h1 {{ color: #333; }}

    /* CSS-hidden honeytoken — visible to scrapers, invisible to humans */
    .honeypot-text {{
      position: absolute;
      left: -9999px;
      top: -9999px;
      font-size: 0;
      opacity: 0;
      visibility: hidden;
    }}

    /* Invisible honeypot link */
    .honeypot-link {{
      display: none;
      visibility: hidden;
    }}
  </style>
</head>
<body>
  <h1>Research Content</h1>

  <p>This page contains publicly available research material.</p>

  <p>
    The following article discusses data attribution and origin tracking in
    modern content distribution networks.
    {CANARY_TOKENS['zero_width_text']}
  </p>

  <!-- Honeypot anchor: display:none — bots scrape it, humans never click it -->
  <a href="{CANARY_TOKENS['honeypot_anchor']}" class="honeypot-link"
     aria-hidden="true" tabindex="-1">
    Do not follow this link
  </a>

  <!-- CSS-hidden contact: invisible to readers, scraped by bots -->
  <span class="honeypot-text">
    Contact our team: {CANARY_TOKENS['css_hidden_email']}
  </span>

  <!-- 1x1 tracking pixel: real browsers load this, bots that don't render CSS do not -->
  <img src="{CANARY_TOKENS['invisible_image']}" width="1" height="1"
       style="position:absolute;left:-9999px;" alt="" aria-hidden="true">

  <h2>Latest Articles</h2>
  <ul>
    <li><a href="/article/1">Understanding CDN Architecture</a></li>
    <li><a href="/article/2">Web Security Fundamentals</a></li>
    <li><a href="/article/3">Bot Detection Methods</a></li>
  </ul>

  <!-- Data attribute canary — bots parsing DOM attributes will capture this -->
  <div data-canary-id="ATTR-TRAP-{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
       style="display:none">
  </div>

  <footer>
    <p>Research Portal &copy; 2026</p>
  </footer>
</body>
</html>"""
    return html.encode("utf-8")


class DefenderHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that logs all request metadata for forensic analysis.
    """

    def do_GET(self):
        # Check if this is a canary token hit
        is_canary = any(
            canary_path in self.path
            for canary_path in ["/track/", "/pixel/", "/canary/"]
        )

        _log_request(self, canary_hit=is_canary)

        if self.path == "/" or self.path == "/index.html":
            content = _build_test_page()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(content)

        elif self.path.startswith("/article/"):
            content = b"<html><body><h1>Article Content</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(content)

        elif is_canary:
            # 1x1 transparent GIF
            gif = (
                b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
                b"!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
                b"\x00\x00\x02\x02D\x01\x00;"
            )
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.end_headers()
            self.wfile.write(gif)

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default access log — we log our own
        pass


def _analyze_logs(logs: List[Dict]) -> Dict:
    """
    Analyze collected request logs to identify bot fingerprints.
    Returns a structured forensics report.
    """
    if not logs:
        return {"error": "No requests logged"}

    # Group by IP
    by_ip = defaultdict(list)
    for entry in logs:
        by_ip[entry["remote_addr"]].append(entry)

    bot_indicators = []
    client_profiles = {}

    for ip, reqs in by_ip.items():
        indicators = []
        user_agents = list({r["user_agent"] for r in reqs})
        request_count = len(reqs)

        # Timing analysis
        if len(reqs) >= 3:
            timestamps = [r["timestamp_unix"] for r in reqs]
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]

            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                cv = std_dev / mean_interval if mean_interval > 0 else 0  # Coefficient of variation

                if cv < 0.15:
                    indicators.append({
                        "type": "TIMING_REGULARITY",
                        "detail": f"Request intervals CV={cv:.3f} — highly regular (human CV typically >0.5)",
                        "severity": "HIGH",
                    })
                elif cv < 0.30:
                    indicators.append({
                        "type": "TIMING_SEMI_REGULAR",
                        "detail": f"Request intervals CV={cv:.3f} — semi-regular",
                        "severity": "MEDIUM",
                    })

        # Header analysis — bots often have missing or unusual headers
        for req in reqs:
            if req["no_language"]:
                indicators.append({
                    "type": "MISSING_ACCEPT_LANGUAGE",
                    "detail": "No Accept-Language header — browsers always send this",
                    "severity": "HIGH",
                })
                break

            if req["accepts_all"] and not req["has_sec_headers"]:
                indicators.append({
                    "type": "BOT_ACCEPT_PATTERN",
                    "detail": "Accept: */* without Sec-Fetch headers — library default",
                    "severity": "MEDIUM",
                })
                break

        # User-Agent analysis
        for ua in user_agents:
            if not ua:
                indicators.append({
                    "type": "MISSING_USER_AGENT",
                    "detail": "Empty User-Agent — automated client",
                    "severity": "CRITICAL",
                })
            elif "python" in ua.lower() or "urllib" in ua.lower() or "requests" in ua.lower():
                indicators.append({
                    "type": "BOT_USER_AGENT",
                    "detail": f"Library User-Agent detected: {ua[:60]}",
                    "severity": "CRITICAL",
                })

        # Canary token hits
        canary_hits = [r for r in reqs if r["canary_hit"]]
        if canary_hits:
            indicators.append({
                "type": "CANARY_TRIGGERED",
                "detail": f"{len(canary_hits)} requests to canary/honeypot endpoints",
                "severity": "HIGH",
            })

        # Request velocity
        if len(reqs) >= 5:
            duration = timestamps[-1] - timestamps[0] if len(reqs) >= 2 else 0
            rps = len(reqs) / duration if duration > 0 else float("inf")
            if rps > 2.0:
                indicators.append({
                    "type": "HIGH_REQUEST_RATE",
                    "detail": f"{rps:.2f} requests/second — exceeds typical human rate",
                    "severity": "HIGH",
                })

        risk_level = "LOW"
        if any(i["severity"] == "CRITICAL" for i in indicators):
            risk_level = "CRITICAL"
        elif any(i["severity"] == "HIGH" for i in indicators):
            risk_level = "HIGH"
        elif any(i["severity"] == "MEDIUM" for i in indicators):
            risk_level = "MEDIUM"

        client_profiles[ip] = {
            "ip": ip,
            "total_requests": request_count,
            "user_agents": user_agents,
            "bot_indicators": indicators,
            "risk_level": risk_level,
            "canary_hits": len([r for r in reqs if r["canary_hit"]]),
        }

        if indicators:
            bot_indicators.extend([(ip, i) for i in indicators])

    return {
        "report_id": f"DEF-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_requests": len(logs),
        "unique_clients": len(by_ip),
        "canary_token_hits": sum(1 for r in logs if r["canary_hit"]),
        "client_profiles": client_profiles,
        "bot_indicator_count": len(bot_indicators),
        "embedded_canary_tokens": {k: "PRESENT" for k in CANARY_TOKENS},
        "detection_summary": _summarize_detections(client_profiles),
    }


def _summarize_detections(profiles: Dict) -> List[str]:
    summary = []
    for ip, profile in profiles.items():
        risk = profile["risk_level"]
        indicators = [i["type"] for i in profile["bot_indicators"]]
        if indicators:
            summary.append(
                f"{ip}: {risk} — {', '.join(indicators[:3])}"
                + ("..." if len(indicators) > 3 else "")
            )
    return summary


def run_server(port: int = 8888, output: str = None):
    server = HTTPServer(("0.0.0.0", port), DefenderHandler)
    print(f"[*] Defender server running on http://localhost:{port}")
    print(f"[*] Serving test page with embedded canary tokens")
    print(f"[*] Logging all request metadata for forensic analysis")
    print(f"[*] Ctrl+C to stop and generate defender report\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("\n[*] Server stopped. Analyzing logs...")

        with _log_lock:
            logs = list(_access_log)

        report = _analyze_logs(logs)

        # Display summary
        print("\n" + "=" * 60)
        print("DEFENDER FORENSICS REPORT")
        print("=" * 60)
        print(f"Total requests:       {report['total_requests']}")
        print(f"Unique clients:       {report['unique_clients']}")
        print(f"Canary token hits:    {report['canary_token_hits']}")
        print(f"Bot indicators found: {report['bot_indicator_count']}")

        if report["detection_summary"]:
            print("\nDetected Clients:")
            for line in report["detection_summary"]:
                print(f"  {line}")

        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"\n[+] Full report saved: {output}")

        print("=" * 60)
        return report


def _parse_args():
    p = argparse.ArgumentParser(description="Tit for Tat — Defender Validation Server")
    p.add_argument("--port", type=int, default=8888, help="HTTP port (default: 8888)")
    p.add_argument("--output", default="forensics/defender_report.json",
                   help="JSON report output path")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run_server(port=args.port, output=args.output)
