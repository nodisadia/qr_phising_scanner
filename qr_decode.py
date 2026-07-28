from pyzbar.pyzbar import decode
from PIL import Image

def scan_qr(image_path):
    """
    Decodes a QR code from an image file. Returns the decoded string, or None if no QR found.
    """
    try:
        img = Image.open(image_path)
        result = decode(img)
        if result:
            return result[0].data.decode('utf-8')
        return None
    except Exception as e:
        print(f"Error reading image: {e}")
        return None


if __name__ == '__main__':
    test_image = 'test_qr.png'  # you'll generate this next
    url = scan_qr(test_image)
    print("Decoded URL:", url)