"""
CMS Security Testing Module
Focus on WordPress editorial plugins and draft exposure
"""

import io
import re
import struct
import requests
from bs4 import BeautifulSoup


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


def check_metadata_persistence(url: str) -> dict:
    """
    Check for metadata leakage in images and documents served by the target.

    Examines EXIF data in JPEG/PNG images (GPS coordinates, camera model,
    software) and PDF metadata (author, creator, creation date). These fields
    persist through CMS upload pipelines that don't strip metadata — a common
    OPSEC failure that can de-anonymize sources.

    Returns a structured findings dict; does NOT require Pillow or pypdf —
    uses lightweight header/byte parsing so the module stays dependency-free.
    """
    findings = {
        "url": url,
        "images_checked": 0,
        "pdfs_checked": 0,
        "leaks": [],
    }

    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        findings["error"] = str(e)
        return findings

    base = url.rstrip("/")

    # ── JPEG/PNG EXIF ────────────────────────────────────────────────────────
    img_tags = soup.find_all("img", src=True)
    for tag in img_tags[:20]:  # cap at 20 to avoid hammering
        src = tag["src"]
        if not src.startswith("http"):
            src = base + ("" if src.startswith("/") else "/") + src.lstrip("/")

        ext = src.split("?")[0].lower()
        if not any(ext.endswith(e) for e in (".jpg", ".jpeg", ".png", ".tif", ".tiff")):
            continue

        try:
            r = requests.get(src, timeout=5, stream=True)
            chunk = b""
            for block in r.iter_content(65536):
                chunk += block
                if len(chunk) >= 65536:
                    break

            findings["images_checked"] += 1
            exif = _parse_jpeg_exif(chunk)
            if exif:
                leak = {"source": src, "type": "IMAGE_EXIF", "fields": exif}
                findings["leaks"].append(leak)
                if "GPSLatitude" in exif or "GPSLongitude" in exif:
                    leak["severity"] = "CRITICAL"
                    leak["detail"] = "GPS coordinates found — can geolocate source/photographer"
                elif any(k in exif for k in ("Make", "Model", "Software")):
                    leak["severity"] = "MEDIUM"
                    leak["detail"] = "Camera/software metadata present — device fingerprinting possible"
                else:
                    leak["severity"] = "LOW"
        except Exception:
            pass

    # ── PDF Metadata ─────────────────────────────────────────────────────────
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if not href.lower().endswith(".pdf"):
            continue
        if not href.startswith("http"):
            href = base + ("" if href.startswith("/") else "/") + href.lstrip("/")

        try:
            r = requests.get(href, timeout=8, stream=True)
            chunk = b""
            for block in r.iter_content(8192):
                chunk += block
                if len(chunk) >= 8192:
                    break

            findings["pdfs_checked"] += 1
            pdf_meta = _parse_pdf_info(chunk)
            if pdf_meta:
                findings["leaks"].append({
                    "source": href,
                    "type": "PDF_METADATA",
                    "severity": "MEDIUM",
                    "fields": pdf_meta,
                    "detail": "PDF Info dictionary present — author, software, creation date may identify source",
                })
        except Exception:
            pass

    return findings


def _parse_jpeg_exif(data: bytes) -> dict:
    """
    Extract a handful of high-value EXIF tags from raw JPEG bytes.
    Handles little-endian (II) and big-endian (MM) TIFF containers.
    Returns {} if no EXIF APP1 marker is found.
    """
    # Find APP1 marker (FF E1) containing "Exif\x00\x00"
    idx = data.find(b"\xff\xe1")
    if idx == -1:
        return {}
    segment = data[idx + 4:]
    if not segment.startswith(b"Exif\x00\x00"):
        return {}
    tiff = segment[6:]

    byte_order = tiff[:2]
    if byte_order == b"II":
        endian = "<"
    elif byte_order == b"MM":
        endian = ">"
    else:
        return {}

    ifd_offset = struct.unpack_from(endian + "I", tiff, 4)[0]

    # Tag IDs we care about
    TAGS = {
        0x010f: "Make",
        0x0110: "Model",
        0x0131: "Software",
        0x013b: "Artist",
        0x8298: "Copyright",
        0x9003: "DateTimeOriginal",
        0x8825: "GPSInfoIFD",
    }

    result = {}
    try:
        num_entries = struct.unpack_from(endian + "H", tiff, ifd_offset)[0]
        for i in range(num_entries):
            entry_offset = ifd_offset + 2 + i * 12
            tag_id = struct.unpack_from(endian + "H", tiff, entry_offset)[0]
            type_id = struct.unpack_from(endian + "H", tiff, entry_offset + 2)[0]
            count = struct.unpack_from(endian + "I", tiff, entry_offset + 4)[0]
            value_offset = struct.unpack_from(endian + "I", tiff, entry_offset + 8)[0]

            if tag_id == 0x8825:
                result["GPSInfoIFD"] = "present"
                # Peek into GPS sub-IFD for lat/lon presence
                try:
                    gps_entries = struct.unpack_from(endian + "H", tiff, value_offset)[0]
                    gps_tags = set()
                    for j in range(gps_entries):
                        gps_tag = struct.unpack_from(endian + "H", tiff, value_offset + 2 + j * 12)[0]
                        gps_tags.add(gps_tag)
                    if 2 in gps_tags:
                        result["GPSLatitude"] = "present"
                    if 4 in gps_tags:
                        result["GPSLongitude"] = "present"
                except Exception:
                    pass
            elif tag_id in TAGS and type_id == 2:  # ASCII string
                size = min(count, 64)
                if size <= 4:
                    # Value fits inline
                    raw = struct.pack(endian + "I", value_offset)[:size]
                else:
                    raw = tiff[value_offset: value_offset + size]
                result[TAGS[tag_id]] = raw.rstrip(b"\x00").decode("latin-1", errors="replace")
    except Exception:
        pass

    return result


def _parse_pdf_info(data: bytes) -> dict:
    """
    Extract PDF Info dictionary fields from raw PDF header bytes.
    Looks for /Author, /Creator, /Producer, /CreationDate.
    """
    result = {}
    text = data.decode("latin-1", errors="replace")

    for key in ("Author", "Creator", "Producer", "CreationDate", "Title"):
        m = re.search(rf"/{key}\s*\(([^)]*)\)", text)
        if m:
            result[key] = m.group(1).strip()

    return result


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
