import re
from qr_decode import scan_qr
from predict_live import predict_url_uci


def looks_like_url(text):
    """
    Basic sanity check: does this look like a domain/URL, not random text?
    Requires at least one dot and no spaces.
    """
    if ' ' in text:
        return False
    if '.' not in text:
        return False
    return bool(re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', text))


def scan_and_check(image_path):
    """
    Full pipeline: QR image -> decoded content -> ML + live-feature phishing verdict.
    """
    decoded = scan_qr(image_path)
    if decoded is None:
        return {'error': 'No QR code detected in image'}

    if not looks_like_url(decoded):
        return {'error': f'QR code contains non-URL content: "{decoded}" — not a website link, so no safety check applies'}

    result = predict_url_uci(decoded)
    result['decoded_from_qr'] = True
    return result


if __name__ == '__main__':
    result = scan_and_check('test_qr.png')
    print(result)