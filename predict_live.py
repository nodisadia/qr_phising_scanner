import joblib
import pandas as pd
from live_features import (
    check_ssl_state, check_domain_age, check_registration_length,
    analyze_html, get_lexical_features, check_dns_record,
    check_web_traffic, check_page_rank, check_google_index,
    check_links_pointing_to_page, check_statistical_report
)

model = joblib.load('model_uci.pkl')

# Must match the exact column order train_model_uci.py used (X.columns after dropping 'id' and 'Result')
FEATURE_ORDER = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]


def gather_all_features(url):
    lexical = get_lexical_features(url)
    html_features = analyze_html(url)

    features = {
        **lexical,
        'SSLfinal_State': check_ssl_state(url),
        'Domain_registeration_length': check_registration_length(url),
        **html_features,
        'age_of_domain': check_domain_age(url),
        'DNSRecord': check_dns_record(url),
        'web_traffic': check_web_traffic(url),
        'Page_Rank': check_page_rank(url),
        'Google_Index': check_google_index(url),
        'Links_pointing_to_page': check_links_pointing_to_page(url),
        'Statistical_report': check_statistical_report(url),
    }
    return features


def predict_url_uci(url):
    print(f"Analyzing {url}... (this takes a few seconds, checks SSL/WHOIS/page content live)")
    features = gather_all_features(url)

    # Order columns to match training exactly
    ordered = {k: features[k] for k in FEATURE_ORDER}
    df = pd.DataFrame([ordered])

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]

    return {
        'url': url,
        'verdict': 'SAFE' if prediction == 1 else 'PHISHING/UNSAFE',
        'confidence': round(max(probability) * 100, 1),
        'features_used': features
    }


if __name__ == '__main__':
    test_urls = ['google.com', 'github.com', 'bit.ly/3xample']
    for url in test_urls:
        result = predict_url_uci(url)
        print(f"\n{result['url']} -> {result['verdict']} ({result['confidence']}% confidence)")