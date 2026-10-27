"""
train_model.py

Trains the SUPERVISED classifier on labeled phishing vs legitimate
URLs. Expects phishing_urls.csv with columns: url, label (1=phishing,
0=legitimate). Falls back to a tiny built-in dataset if not found —
replace with a real dataset (Kaggle/UCI) before final submission.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from feature_extraction import extract_url_features, features_to_vector

DATA_PATH = "phishing_urls.csv"
MODEL_PATH = "phishing_model.pkl"

FALLBACK_DATA = [
    ("https://www.google.com", 0), ("https://www.github.com", 0),
    ("https://www.wikipedia.org", 0), ("https://www.python.org", 0),
    ("https://www.microsoft.com", 0), ("https://www.amazon.com", 0),
    ("http://secure-paypa1-login.com", 1), ("http://192.168.1.5/login.php", 1),
    ("http://amaz0n-support.verify-account.com", 1), ("http://bit.ly/3xR7kLp", 1),
    ("http://update-your-account-now.com/signin", 1), ("http://g00gle-secure.com", 1),
]


def load_dataset():
    if os.path.exists(DATA_PATH):
        df = pd.read_csv(DATA_PATH)
        return list(zip(df["url"], df["label"]))
    print(f"'{DATA_PATH}' not found \u2014 using small built-in fallback dataset.")
    print("Replace this with a real Kaggle/UCI phishing URL dataset before final submission.")
    return FALLBACK_DATA


def main():
    data = load_dataset()
    urls, labels = zip(*data)
    X = np.array([features_to_vector(extract_url_features(u)) for u in urls])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
    )
    model = RandomForestClassifier(n_estimators=200, random_state=42)
    model.fit(X_train, y_train)

    if len(X_test) > 0:
        preds = model.predict(X_test)
        print(classification_report(y_test, preds, zero_division=0))

    joblib.dump(model, MODEL_PATH)
    print(f"Model saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
