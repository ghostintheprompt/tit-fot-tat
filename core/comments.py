"""
Comment Platform Analysis Module
Focus on moderator enumeration, phishing vectors, and auth security
"""

import requests
from bs4 import BeautifulSoup
import re


def detect_comment_platform(url, session=None):
    """
    Detect which comment platform is in use (Native WP, Disqus, etc.)
    """
    print(f"[+] Detecting comment platform...")

    _get = session.get if session else requests.get

    try:
        response = _get(url, timeout=10)
        content = response.text.lower()

        if 'disqus.com/embed.js' in content:
            print(f"    [✓] Platform: Disqus")
            return 'disqus'
        elif 'wp-comments-post.php' in content or 'comment-respond' in content:
            print(f"    [✓] Platform: WordPress Native")
            return 'wordpress'
        elif 'facebook.com/plugins/comments' in content:
            print(f"    [✓] Platform: Facebook Comments")
            return 'facebook'
        else:
            print(f"    [!] No common comment platform detected")
            return 'unknown'

    except Exception as e:
        print(f"    [!] Detection failed: {e}")
        return None


def enumerate_moderators(url, platform, session=None):
    """
    Attempt to find moderator accounts via comment metadata or API
    """
    print(f"\n[+] Enumerating potential moderator accounts...")

    _get = session.get if session else requests.get

    moderators = []

    if platform == 'wordpress':
        # WP REST API user enumeration
        api_url = url.rstrip('/') + '/wp-json/wp/v2/users'
        try:
            response = _get(api_url, timeout=5)
            if response.status_code == 200:
                users = response.json()
                for user in users:
                    # Look for clues of moderator/admin status
                    role = user.get('slug', '')
                    name = user.get('name', '')
                    moderators.append({'name': name, 'slug': role, 'type': 'REST API'})
                    print(f"    [✓] Found user: {name} (@{role})")
        except:
            pass

        # Parse recent comments for "Author" labels
        try:
            response = _get(url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            # Look for comment-author-admin or similar classes
            admin_comments = soup.select('.bypostauthor, .comment-author-admin')
            for comment in admin_comments:
                author_name = comment.select_one('.fn, .comment-author')
                if author_name:
                    name = author_name.get_text(strip=True)
                    if name not in [m['name'] for m in moderators]:
                        moderators.append({'name': name, 'type': 'HTML Class'})
                        print(f"    [✓] Found moderator (HTML class): {name}")
        except:
            pass

    return moderators


def identify_phishing_vectors(url, platform, session=None):
    """
    Identify potential vectors for comment-based phishing
    """
    print(f"\n[+] Identifying phishing vectors...")

    _get = session.get if session else requests.get

    vectors = []

    try:
        response = _get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for unauthenticated URL fields in comment form
        if platform == 'wordpress':
            url_field = soup.find('input', {'name': 'url'})
            if url_field:
                print(f"    [!] Vector: Unauthenticated URL field (allows link injection)")
                vectors.append({
                    'type': 'Link Injection',
                    'detail': 'Unauthenticated URL field allows profiles to link to external sites'
                })

            # Check for allowed HTML tags
            notes = soup.find(class_='comment-notes')
            if notes and ('<a>' in notes.text or '<code>' in notes.text):
                print(f"    [!] Vector: Allowed HTML tags in comments")
                vectors.append({
                    'type': 'HTML Injection',
                    'detail': f'Allowed tags: {notes.get_text(strip=True)}'
                })

        # Check for Disqus "guest" comments
        if platform == 'disqus':
            # This would require checking Disqus config via their API or script settings
            print(f"    [i] Disqus guest comment status should be verified via portal")

    except Exception as e:
        print(f"    [!] Phishing vector scan failed: {e}")

    return vectors


def analyze_auth_security(url, platform, session=None):
    """
    Check if comment submission is gated or has security features (reCAPTCHA, etc.)
    Also performs session management analysis if cookies are present.
    """
    print(f"\n[+] Analyzing authentication security...")

    _get = session.get if session else requests.get

    security = {
        'requires_auth': False,
        'has_captcha': False,
        'has_nonce': False,
        'session_security': {}
    }

    try:
        response = _get(url, timeout=10)
        content = response.text.lower()

        if 'log in to reply' in content or 'must be logged in' in content:
            print(f"    [✓] Authentication: REQUIRED")
            security['requires_auth'] = True
        else:
            print(f"    [!] Authentication: NOT REQUIRED (Guest comments allowed)")

        if 'recaptcha' in content or 'g-recaptcha' in content or 'hcaptcha' in content:
            print(f"    [✓] CAPTCHA detected")
            security['has_captcha'] = True
        else:
            print(f"    [!] NO CAPTCHA detected")

        if platform == 'wordpress':
            if '_wpnonce' in content or 'ak_js' in content: # Akismet uses JS nonce
                print(f"    [✓] Anti-CSRF/Spam tokens detected")
                security['has_nonce'] = True
            else:
                print(f"    [!] NO Anti-CSRF tokens found in comment form")

        # Session Management Analysis
        cookies = response.cookies
        if cookies:
            print(f"    [+] Analyzing {len(cookies)} session cookies...")
            for cookie in cookies:
                c_info = {
                    'name': cookie.name,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly') or getattr(cookie, 'httponly', False),
                    'secure': cookie.secure,
                    'samesite': getattr(cookie, 'samesite', 'None')
                }
                security['session_security'][cookie.name] = c_info
                
                flags = []
                if not c_info['httponly']: flags.append("MISSING HttpOnly")
                if not c_info['secure']: flags.append("MISSING Secure")
                
                if flags:
                    print(f"    [!] Cookie '{cookie.name}': {', '.join(flags)}")
                else:
                    print(f"    [✓] Cookie '{cookie.name}': All security flags present")

    except Exception as e:
        print(f"    [!] Auth security analysis failed: {e}")

    return security


def scan(args, target=None, session=None):
    """
    Main comment platform analysis function
    """
    # Handle both audit and comment-scan command args
    url = target or getattr(args, 'url', None)

    results = {
        'url': url,
        'platform': None,
        'moderators': [],
        'phishing_vectors': [],
        'auth_security': {}
    }

    if not url:
        return results

    # Detect platform
    platform = detect_comment_platform(url, session=session)
    results['platform'] = platform

    if not platform or platform == 'unknown':
        return results

    # Enumerate moderators
    results['moderators'] = enumerate_moderators(url, platform, session=session)

    # Identify phishing vectors
    results['phishing_vectors'] = identify_phishing_vectors(url, platform, session=session)

    # Analyze auth security
    results['auth_security'] = analyze_auth_security(url, platform, session=session)

    return results


def display_results(results):
    """
    Display comment analysis results
    """
    print("\n" + "="*70)
    print("COMMENT PLATFORM ANALYSIS RESULTS")
    print("="*70)

    print(f"\nTarget: {results['url']}")
    print(f"Platform: {results['platform'].title() if results['platform'] else 'Unknown'}")

    if results['moderators']:
        print(f"\n[+] Potential Moderators: {len(results['moderators'])}")
        for mod in results['moderators']:
            print(f"    • {mod['name']} ({mod['type']})")

    if results['phishing_vectors']:
        print(f"\n[!] PHISHING VECTORS:")
        for vector in results['phishing_vectors']:
            print(f"    • {vector['type']}: {vector['detail']}")

    if results.get('auth_security'):
        print(f"\n[+] Auth Security:")
        print(f"    • Requires login: {'Yes' if results['auth_security']['requires_auth'] else 'No'}")
        print(f"    • CAPTCHA: {'Present' if results['auth_security']['has_captcha'] else 'Absent'}")
        print(f"    • CSRF Tokens: {'Present' if results['auth_security']['has_nonce'] else 'Absent'}")

    print("\n" + "="*70)
