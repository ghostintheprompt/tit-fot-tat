<img src="tit_for_tat.png" width="200">

# Tit-for-Tat
Penetration testing framework for newsroom infrastructure. — v1.0

**Red team tool. Blue team defense. February 2026.**

## What it does

Security testing tool targeting vulnerabilities specific to newsroom infrastructure:
- Origin server discovery (Cloudflare bypass techniques)
- CMS exploitation (WordPress editorial plugin vulnerabilities)
- Comment platform security testing
- RSS feed leak detection
- Comprehensive security auditing

## Legal Notice

**AUTHORIZED TESTING ONLY**

Unauthorized testing of news infrastructure = federal crime (CFAA in US, Computer Misuse Act in UK, equivalent laws globally).

Use on:
- Your own infrastructure
- Authorized red team engagements with written permission
- Defensive research in controlled labs

Do NOT use to:
- Target journalists you don't work for
- Steal investigations
- Identify sources
- Suppress truth

## Installation

```bash
git clone https://github.com/ghostintheprompt/tit-for-tat
cd tit-for-tat
pip install -r requirements.txt
```

## Quick Start

```bash
# Defensive audit (test your own site)
python tit-for-tat.py audit --target https://your-newsroom.com

# Origin discovery only
python tit-for-tat.py origin --domain your-site.com --all-methods

# Full security report
python tit-for-tat.py audit --target https://your-site.com --output report.html
```

## Capabilities

### Phase 1: Origin Server Discovery
- Certificate Transparency log analysis
- Historical DNS reconnaissance
- MX record correlation
- Subdomain enumeration
- Cloudflare bypass techniques

### Phase 2: CMS Security Testing
- WordPress version detection
- Plugin vulnerability scanning
- Privilege escalation testing
- Draft content exposure testing
- Editorial workflow analysis

### Phase 3: Comment Platform Analysis
- Moderator account enumeration
- Phishing vector identification
- Authentication security testing
- Session management analysis

### Phase 4: RSS Feed Monitoring
- Feed endpoint discovery
- Draft content leak detection
- Metadata exposure analysis
- Real-time monitoring capabilities

## Usage Examples

```bash
# Test for origin IP exposure
python tit-for-tat.py origin --domain newssite.com --cert-transparency

# Scan CMS for vulnerabilities
python tit-for-tat.py cms-scan --url https://newssite.com --check-plugins

# Monitor RSS feeds for leaks
python tit-for-tat.py rss --domain newssite.com --monitor --interval 300

# Full defensive audit
python tit-for-tat.py audit --target https://newssite.com \
  --origin-discovery \
  --cms-scan \
  --rss-analysis \
  --output defensive_report.html
```

## Architecture

```
tit-for-tat/
├── tit-for-tat.py          # Main CLI
├── core/
│   ├── origin.py           # Origin server discovery
│   ├── cms.py              # CMS exploitation
│   ├── comments.py         # Comment platform testing
│   ├── rss.py              # RSS monitoring
│   └── reporting.py        # Report generation
├── requirements.txt
└── README.md
```

## Why This Exists

**73 journalists killed in January 2026.** Newsrooms breached by nation-states. Sources exposed through infrastructure leaks. Generic security tools miss newsroom-specific vulnerabilities.

This tool:
- Identifies vulnerabilities before attackers do
- Enables defensive hardening
- Demonstrates real threats to newsroom security teams
- Makes threat landscape visible

## Platform Support

- **Primary:** Linux (native security tooling, standard pentest platform)
- **Supported:** macOS (development, testing)
- **Cross-platform:** Python 3.8+

## Development

```bash
# Clone repo
git clone https://github.com/ghostintheprompt/tit-for-tat
cd tit-for-tat

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Lint
flake8 core/ tit-for-tat.py
```

## Contributing

Security tool contributions welcome:
- New detection techniques
- Improved reporting
- Additional CMS coverage
- Bug fixes

## License

MIT License - See LICENSE file

## Disclaimer

Tool designed for authorized security testing and defensive hardening. Authors not responsible for misuse. Unauthorized testing violates federal law.

**Protect the press. Even when it's complicated.**

---

**Stack:** Python 3.8+, requests, BeautifulSoup4, dnspython, cryptography

**Purpose:** Defend journalists. Protect sources. Understand information warfare.

**Authorization:** Required. Always.

## Legal Notice

**AUTHORIZED TESTING ONLY**

Unauthorized testing of news infrastructure = federal crime (CFAA in US, Computer Misuse Act in UK, equivalent laws globally).

Use on:
- Your own infrastructure
- Authorized red team engagements with written permission
- Defensive research in controlled labs

Do NOT use to:
- Target journalists you don't work for
- Steal investigations
- Identify sources
- Suppress truth

## Installation

```bash
git clone https://github.com/ghostintheprompt/tit-for-tat
cd tit-for-tat
pip install -r requirements.txt
```

## Quick Start

```bash
# Defensive audit (test your own site)
python tit-for-tat.py audit --target https://your-newsroom.com

# Origin discovery only
python tit-for-tat.py origin --domain your-site.com --all-methods

# Full security report
python tit-for-tat.py audit --target https://your-site.com --output report.html
```

## Capabilities

### Phase 1: Origin Server Discovery
- Certificate Transparency log analysis
- Historical DNS reconnaissance
- MX record correlation
- Subdomain enumeration
- Cloudflare bypass techniques

### Phase 2: CMS Security Testing
- WordPress version detection
- Plugin vulnerability scanning
- Privilege escalation testing
- Draft content exposure testing
- Editorial workflow analysis

### Phase 3: Comment Platform Analysis
- Moderator account enumeration
- Phishing vector identification
- Authentication security testing
- Session management analysis

### Phase 4: RSS Feed Monitoring
- Feed endpoint discovery
- Draft content leak detection
- Metadata exposure analysis
- Real-time monitoring capabilities

## Usage Examples

```bash
# Test for origin IP exposure
python tit-for-tat.py origin --domain newssite.com --cert-transparency

# Scan CMS for vulnerabilities
python tit-for-tat.py cms-scan --url https://newssite.com --check-plugins

# Monitor RSS feeds for leaks
python tit-for-tat.py rss --domain newssite.com --monitor --interval 300

# Full defensive audit
python tit-for-tat.py audit --target https://newssite.com \
  --origin-discovery \
  --cms-scan \
  --rss-analysis \
  --output defensive_report.html
```

## Architecture

```
tit-for-tat/
├── tit-for-tat.py          # Main CLI
├── core/
│   ├── origin.py           # Origin server discovery
│   ├── cms.py              # CMS exploitation
│   ├── comments.py         # Comment platform testing
│   ├── rss.py              # RSS monitoring
│   └── reporting.py        # Report generation
├── requirements.txt
└── README.md
```

## Why This Exists

**73 journalists killed in January 2026.** Newsrooms breached by nation-states. Sources exposed through infrastructure leaks. Generic security tools miss newsroom-specific vulnerabilities.

This tool:
- Identifies vulnerabilities before attackers do
- Enables defensive hardening
- Demonstrates real threats to newsroom security teams
- Makes threat landscape visible

## Platform Support

- **Primary:** Linux (native security tooling, standard pentest platform)
- **Supported:** macOS (development, testing)
- **Cross-platform:** Python 3.8+

## Development

```bash
# Clone repo
git clone https://github.com/ghostintheprompt/tit-for-tat
cd tit-for-tat

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Lint
flake8 core/ tit-for-tat.py
```

## Contributing

Security tool contributions welcome:
- New detection techniques
- Improved reporting
- Additional CMS coverage
- Bug fixes

## License

MIT License - See LICENSE file

## Disclaimer

Tool designed for authorized security testing and defensive hardening. Authors not responsible for misuse. Unauthorized testing violates federal law.

**Protect the press. Even when it's complicated.**

---

**Stack:** Python 3.8+, requests, BeautifulSoup4, dnspython, cryptography

**Purpose:** Defend journalists. Protect sources. Understand information warfare.

**Authorization:** Required. Always.
