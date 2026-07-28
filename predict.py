import joblib
import pandas as pd
from features import extract_features

model = joblib.load('model.pkl')

def predict_url(url):
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    probability = model.predict_proba(features_df)[0]

    return {
        'url': url,
        'verdict': 'UNSAFE' if prediction == 1 else 'SAFE',
        'confidence': round(max(probability) * 100, 1)
    }

if __name__ == '__main__':
    test_urls = [
        'google.com',
        'http://www.garage-pirenne.be/index.php?option=com',
        'br-icloud.com.br',
        'paypal-secure-login.verify-account.tk',
    ]
    for url in test_urls:
        result = predict_url(url)
        print(result)