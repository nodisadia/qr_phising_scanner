from flask import Flask, request, render_template_string, jsonify
from scan_and_check import scan_and_check, looks_like_url
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

PAGE = """
<!DOCTYPE html>
<html>
<head><title>QR Phishing Scanner</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
    <h1>QR Code &amp; Phishing URL Scanner</h1>

    <h2>Upload an image</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="qr_image" accept="image/*" required>
        <button type="submit">Scan</button>
    </form>
    {% if result %}
        <hr>
        {% if result.error %}
            <p style="color: orange;">{{ result.error }}</p>
        {% else %}
            <h2>Decoded URL: {{ result.url }}</h2>
            <h2 style="color: {{ 'green' if result.verdict == 'SAFE' else 'red' }};">
                Verdict: {{ result.verdict }} ({{ result.confidence }}% confidence)
            </h2>
            <details>
                <summary>Show feature details</summary>
                <pre>{{ result.features_used }}</pre>
            </details>
        {% endif %}
    {% endif %}

    <hr>
    <h2>Or scan with camera</h2>
    <video id="video" width="400" height="300" style="border:1px solid #ccc;"></video>
    <br>
    <button id="startCamera">Start Camera</button>
    <button id="stopCamera" style="display:none;">Stop Camera</button>
    <div id="cameraResult" style="margin-top:15px;"></div>

    <canvas id="canvas" hidden></canvas>

    <script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"></script>
    <script>
    const video = document.getElementById('video');
    const canvas = document.getElementById('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const startBtn = document.getElementById('startCamera');
    const stopBtn = document.getElementById('stopCamera');
    const resultDiv = document.getElementById('cameraResult');
    let stream = null;
    let scanning = false;
    let lastScanned = null;

    startBtn.onclick = async () => {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        video.srcObject = stream;
        video.play();
        startBtn.style.display = 'none';
        stopBtn.style.display = 'inline';
        scanning = true;
        resultDiv.innerHTML = '';
        requestAnimationFrame(tick);
    };

    stopBtn.onclick = () => {
        scanning = false;
        stream.getTracks().forEach(track => track.stop());
        startBtn.style.display = 'inline';
        stopBtn.style.display = 'none';
    };

    function tick() {
        if (!scanning) return;
        if (video.readyState === video.HAVE_ENOUGH_DATA) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);
            console.log('scanning frame...', code);
            if (code && code.data !== lastScanned) {
                lastScanned = code.data;
                resultDiv.innerHTML = '<p>Detected: ' + code.data + ' \u2014 analyzing...</p>';
                checkUrl(code.data);
            }
        }
        requestAnimationFrame(tick);
    }

    async function checkUrl(url) {
        const res = await fetch('/check_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        const data = await res.json();
        if (data.error) {
            resultDiv.innerHTML = '<p style="color:orange;">' + data.error + '</p>';
        } else {
            const color = data.verdict === 'SAFE' ? 'green' : 'red';
            resultDiv.innerHTML =
                '<h3>Decoded: ' + data.url + '</h3>' +
                '<h3 style="color:' + color + ';">Verdict: ' + data.verdict + ' (' + data.confidence + '% confidence)</h3>';
        }
    }
    </script>
</body>
</html>
"""


@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        file = request.files['qr_image']
        path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(path)
        result = scan_and_check(path)
    return render_template_string(PAGE, result=result)


@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    decoded = data.get('url', '')

    if not looks_like_url(decoded):
        return jsonify({'error': f'Non-URL content: "{decoded}"'})

    from predict_live import predict_url_uci
    result = predict_url_uci(decoded)
    result['decoded_from_qr'] = True
    result['confidence'] = float(result['confidence'])
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc')