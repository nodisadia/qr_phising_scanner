import re
import ssl
import socket
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


def get_hostname(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return urlparse(url).netloc


def check_ssl_state(url):
    """
    Returns: 1 (trusted/good), 0 (suspicious), -1 (bad/no SSL)
    Mimics the UCI dataset's SSLfinal_State encoding.
    """
    hostname = get_hostname(url)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            s.getpeercert()
            return 1
    except ssl.SSLCertVerificationError:
        return -1
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return -1
    except Exception:
        return 0


def check_domain_age(url):
    """
    Returns: 1 (domain older than 6 months), -1 (younger, or lookup failed)
    """
    hostname = get_hostname(url)
    try:
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return -1
        if created.tzinfo is not None:
            created = created.replace(tzinfo=None)
        age_days = (datetime.now() - created).days
        return 1 if age_days > 180 else -1
    except Exception:
        return -1


def check_registration_length(url):
    """
    Returns: 1 (>1 year remaining on registration), -1 (short/expiring soon, or lookup failed)
    """
    hostname = get_hostname(url)
    try:
        w = whois.whois(hostname)
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry is None:
            return -1
        if expiry.tzinfo is not None:
            expiry = expiry.replace(tzinfo=None)
        days_remaining = (expiry - datetime.now()).days
        return 1 if days_remaining > 365 else -1
    except Exception:
        return -1


def fetch_page(url):
    """
    Safely fetches a page's HTML. Returns (html_text, final_url) or (None, None) on failure.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        response = requests.get(
            url,
            timeout=5,
            headers={'User-Agent': 'Mozilla/5.0 (QR-Phishing-Scanner-Bot)'},
            allow_redirects=True
        )
        return response.text, response.url
    except requests.RequestException:
        return None, None


def analyze_html(url):
    """
    Fetches the page and extracts 12 HTML-based features.
    Returns -1 for every feature if the page can't be fetched at all.
    """
    html, final_url = fetch_page(url)
    hostname = get_hostname(url)

    if html is None:
        return {k: -1 for k in [
            'Favicon', 'port', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags',
            'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect',
            'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe'
        ]}

    soup = BeautifulSoup(html, 'html.parser')

    # Favicon: is it loaded from the same domain?
    favicon_tag = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
    if favicon_tag and favicon_tag.get('href'):
        favicon_url = urljoin(final_url, favicon_tag['href'])
        favicon = 1 if hostname in favicon_url else -1
    else:
        favicon = 0

    # port
    port = 1 if (':' not in hostname or hostname.endswith(':80') or hostname.endswith(':443')) else -1

    # Request_URL: % of images/scripts/iframes/links loaded from external domains
    tags = soup.find_all(['img', 'script', 'iframe', 'link'])
    total = len(tags)
    external = 0
    for tag in tags:
        src = tag.get('src') or tag.get('href')
        if src:
            full = urljoin(final_url, src)
            if hostname not in full:
                external += 1
    request_url = 1 if total == 0 or (external / total) < 0.3 else -1

    # URL_of_Anchor: % of <a href> links pointing elsewhere or nowhere
    anchors = soup.find_all('a', href=True)
    if not anchors:
        url_of_anchor = 0
    else:
        bad = sum(
            1 for a in anchors
            if a['href'].startswith('#') or 'javascript:void' in a['href']
            or (hostname not in urljoin(final_url, a['href']))
        )
        ratio = bad / len(anchors)
        url_of_anchor = 1 if ratio < 0.3 else (-1 if ratio > 0.67 else 0)

    # Links_in_tags: reuse external-resource ratio as a proxy
    links_in_tags = request_url

    # SFH (Server Form Handler)
    forms = soup.find_all('form')
    if not forms:
        sfh = 0
    else:
        action = forms[0].get('action', '')
        if action == '' or action == 'about:blank':
            sfh = -1
        elif hostname in urljoin(final_url, action):
            sfh = 1
        else:
            sfh = 0

    # Submitting_to_email
    submitting_to_email = -1 if 'mailto:' in html else 1

    # Abnormal_URL
    abnormal_url = 1 if hostname in final_url else -1

    # Redirect
    redirect = -1 if final_url.rstrip('/') not in (
        ('http://' + hostname).rstrip('/'), ('https://' + hostname).rstrip('/')
    ) else 1

    # JS-based checks (approximate, raw-HTML presence)
    on_mouseover = -1 if 'onmouseover' in html.lower() else 1
    right_click = -1 if 'event.button==2' in html.lower() or 'contextmenu' in html.lower() else 1
    popup = -1 if 'window.open(' in html.lower() else 1
    iframe = -1 if soup.find('iframe') else 1

    return {
        'Favicon': favicon, 'port': port, 'Request_URL': request_url,
        'URL_of_Anchor': url_of_anchor, 'Links_in_tags': links_in_tags, 'SFH': sfh,
        'Submitting_to_email': submitting_to_email, 'Abnormal_URL': abnormal_url,
        'Redirect': redirect, 'on_mouseover': on_mouseover,
        'RightClick': right_click, 'popUpWidnow': popup, 'Iframe': iframe
    }


def get_lexical_features(url):
    """
    Pure string-based features, UCI -1/0/1 encoded. No network call needed.
    """
    if not url.startswith(('http://', 'https://')):
        full_url = 'http://' + url
    else:
        full_url = url
    hostname = get_hostname(url)

    having_ip = -1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) else 1

    url_length = -1 if len(full_url) < 54 else (0 if len(full_url) <= 75 else 1)

    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    shortening_service = -1 if any(s in full_url for s in shorteners) else 1

    having_at = -1 if '@' in full_url else 1
    double_slash = -1 if full_url.count('//') > 1 else 1
    prefix_suffix = -1 if '-' in hostname else 1
    having_subdomain = -1 if hostname.count('.') > 2 else (0 if hostname.count('.') == 2 else 1)
    https_token = -1 if 'https' in hostname else 1

    return {
        'having_IP_Address': having_ip, 'URL_Length': url_length,
        'Shortining_Service': shortening_service, 'having_At_Symbol': having_at,
        'double_slash_redirecting': double_slash, 'Prefix_Suffix': prefix_suffix,
        'having_Sub_Domain': having_subdomain, 'HTTPS_token': https_token
    }


def check_dns_record(url):
    """
    Returns: 1 (DNS resolves — legitimate signal), -1 (doesn't resolve — suspicious)
    """
    hostname = get_hostname(url)
    try:
        socket.gethostbyname(hostname)
        return 1
    except socket.gaierror:
        return -1


def check_web_traffic(url):
    """
    Stand-in for Alexa-based web_traffic (Alexa shut down in 2022).
    Approximates 'is this a well-known site' using domain age + successful DNS
    as a loose proxy, since we don't have a free live traffic-ranking API.
    Returns: 1 (likely established site), -1 (likely low-traffic/unknown), 0 (unclear)
    """
    age = check_domain_age(url)
    dns = check_dns_record(url)
    if dns == -1:
        return -1
    return 1 if age == 1 else 0


def check_page_rank(url):
    """
    Stand-in for the old Google PageRank / Alexa rank (both discontinued).
    No free reliable API exists for this anymore, so we return neutral.
    Kept as a feature for the model but always contributes 0 (no info) live.
    """
    return 0


def check_google_index(url):
    """
    Whether the site is indexed by Google. There's no free official API for this;
    a real implementation would need scraping Google search results (fragile, against ToS)
    or a paid SEO API. We use DNS resolution as a very loose proxy instead.
    Returns: 1 (resolves, assume indexed), -1 (doesn't resolve)
    """
    return check_dns_record(url)


def check_links_pointing_to_page(url):
    """
    Stand-in for backlink count (needs a paid SEO API like Ahrefs/Moz for real data).
    Returns neutral — no live signal available for free.
    """
    return 0


def check_statistical_report(url):
    """
    Original UCI feature checked against known phishing-associated IPs/hosts (StopBadware, PhishTank lists).
    Stand-in: flag if hostname appears in a small local blocklist check via PhishTank's free feed
    (left as 0/neutral here — wire up a real PhishTank API call if you have a key).
    """
    return 0


if __name__ == '__main__':
    test_urls = ['google.com', 'github.com', 'this-domain-does-not-exist-xyz123.com']
    for url in test_urls:
        print(
            url,
            '-> SSL:', check_ssl_state(url),
            '| Age:', check_domain_age(url),
            '| RegLength:', check_registration_length(url)
        )

    html, final_url = fetch_page('google.com')
    print("\nFetched:", final_url, "| length:", len(html) if html else None)

    print("\nHTML features for google.com:")
    print(analyze_html('google.com'))

    print("\nLexical features for google.com:")
    print(get_lexical_features('google.com'))


    print("\nRemaining 6 features for google.com:")
    print({
        'DNSRecord': check_dns_record('google.com'),
        'web_traffic': check_web_traffic('google.com'),
        'Page_Rank': check_page_rank('google.com'),
        'Google_Index': check_google_index('google.com'),
        'Links_pointing_to_page': check_links_pointing_to_page('google.com'),
        'Statistical_report': check_statistical_report('google.com'),
    })