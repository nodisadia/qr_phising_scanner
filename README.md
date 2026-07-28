# QR Code & Phishing URL Scanner

A machine learning–powered tool that scans QR codes (via file upload or live camera) and analyzes the embedded URL in real time to determine whether it's likely safe or a phishing/malicious link.

Built as a standalone cybersecurity project combining QR decoding, live web/network feature extraction, and a trained classifier — not just a lookup against a static blocklist.

---

## Features

- **QR decoding** — via file upload or live browser camera scanning
- **Machine learning verdict** — a Random Forest classifier trained on the UCI Phishing Websites dataset, achieving **97.4% test accuracy**
- **30 live-computed features per URL**, spanning:
  - Lexical URL analysis (length, IP-as-hostname, shortener detection, `@` symbols, hyphens, subdomain count, etc.)
  - Live SSL certificate validation
  - Live WHOIS lookups (domain age, registration length)
  - Live HTML page analysis (favicon origin, external resource ratio, anchor tag behavior, form handler destination, popup/redirect/iframe detection)
  - DNS resolution check
- **Explainable output** — every verdict comes with the full feature breakdown that produced it, not just a black-box score
- **Edge-case hardened** — gracefully handles non-QR images, non-URL QR content, unreachable domains, and malformed file uploads without crashing

---

## How It Works

```
QR Image / Camera Feed
        │
        ▼
   QR Decoding (pyzbar / jsQR)
        │
        ▼
   Decoded text validated as URL-like
        │
        ▼
   30 features extracted live:
     ├─ Lexical (from the URL string itself)
     ├─ SSL certificate check
     ├─ WHOIS domain age / registration length
     ├─ HTML page fetch + parse (BeautifulSoup)
     └─ DNS resolution
        │
        ▼
   Random Forest model predicts: SAFE or PHISHING/UNSAFE
        │
        ▼
   Verdict + confidence + feature breakdown shown to user
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| ML | scikit-learn (Random Forest) |
| QR decoding (upload) | pyzbar, Pillow |
| QR decoding (camera) | jsQR (JavaScript, via browser `getUserMedia`) |
| URL/domain analysis | `ssl`, `socket`, `python-whois`, `requests`, `BeautifulSoup` |
| Data handling | pandas |

---

## Dataset

**[UCI Phishing Websites Dataset](https://www.kaggle.com/datasets/akashkr/phishing-website-dataset)** (ARFF-to-CSV conversion), 11,055 rows, 30 pre-defined features plus a binary label (`Result`: 1 = legitimate, -1 = phishing).

This dataset was chosen after an initial attempt using a larger raw-URL dataset (651k rows) revealed a class-imbalance bias in that data — bare domains with no path were disproportionately labeled malicious in the training set, causing false positives on legitimate short URLs like `google.com`. The UCI dataset's pre-engineered, domain-expert-selected features avoided this issue and produced a more reliable, better-calibrated model.

### Model performance

- **Accuracy:** 97.4%
- **Top predictive features:** `SSLfinal_State`, `URL_of_Anchor`, `web_traffic`, `having_Sub_Domain`

---

## Known Limitations

Full transparency on where this project's live-feature approximations diverge from the original dataset's methodology:

- **`Page_Rank`, `Links_pointing_to_page`, `Statistical_report`** — the original dataset sourced these from services (Alexa rankings, backlink APIs) that are now discontinued or require paid access. These three features return a neutral value (0) at inference time rather than a real live signal, so the model relies on the remaining 27 features for its verdict.
- **`web_traffic` and `Google_Index`** — approximated via DNS resolution and domain age as loose proxies, since no free live API exists for either anymore.
- **HTML-based features** (`URL_of_Anchor`, `SFH`, `on_mouseover`, etc.) are computed with simplified heuristics rather than the exact original feature-engineering methodology, since that wasn't publicly documented in full detail.
- **Camera-based scanning requires a secure origin** (`localhost` or HTTPS) per browser security policy — it will not work over a plain `http://` connection to a device on the local network without a tool like ngrok to provide HTTPS tunneling.

These limitations are a deliberate, documented tradeoff between fidelity to the original research and building something that actually runs live, for free, today.

---

## Setup

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
git clone <your-repo-url>
cd qr-phishing-scanner
python -m venv venv

# Activate the virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### Running

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

- **Upload scanning:** works immediately, no special setup
- **Camera scanning:** works on `127.0.0.1`/`localhost` out of the box; for use on another device (e.g. your phone), use a tool like [ngrok](https://ngrok.com) to get an HTTPS tunnel, since browsers block camera access on insecure origins

---

## Project Structure

```
qr-phishing-scanner/
├── app.py                  # Flask app (routes, camera + upload UI)
├── qr_decode.py             # QR decoding from uploaded images (pyzbar)
├── scan_and_check.py        # Pipeline: QR → URL validation → prediction
├── predict_live.py          # Loads model, assembles 30 features, returns verdict
├── live_features.py         # SSL, WHOIS, HTML-scraping, DNS, lexical feature functions
├── train_model_uci.py       # Model training script
├── model_uci.pkl            # Trained Random Forest model
├── data_uci/                 # UCI Phishing Websites dataset
└── requirements.txt
```

---

## Retraining the Model

```bash
python train_model_uci.py
```

This prints accuracy, a classification report, a confusion matrix, and feature importances, then saves the model to `model_uci.pkl`.

---

## Author

Nodi — Cyber Security Engineering, University of Frontier Technology, Bangladesh (UFTB)
