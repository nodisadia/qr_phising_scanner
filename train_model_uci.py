import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

df = pd.read_csv('data_uci/uci-ml-phishing-dataset.csv')

# Drop id — it's just a row number, not a real feature
df = df.drop('id', axis=1)

X = df.drop('Result', axis=1)
y = df['Result']

print("Feature columns:", list(X.columns))
print("Label distribution:\n", y.value_counts())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\nTraining model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification report:")
print(classification_report(y_test, y_pred))
print("\nConfusion matrix:")
print(confusion_matrix(y_test, y_pred))

# Check which features mattered most — useful for your demo explanation
importances = pd.Series(model.feature_importances_, index=X.columns).sort_values(ascending=False)
print("\nTop 10 most important features:")
print(importances.head(10))

joblib.dump(model, 'model_uci.pkl')
print("\nModel saved as model_uci.pkl")