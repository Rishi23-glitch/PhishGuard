"""
anomaly_detector.py

The NON-SIGNATURE part of the detection pipeline. Trained ONLY on
legitimate URLs, so it learns what "normal" looks like and flags
anything that deviates — including phishing it has never seen before.
"""

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from feature_extraction import extract_url_features, features_to_vector

MODEL_PATH = "anomaly_model.pkl"


def train_anomaly_model(legit_urls_csv: str = None):
    if legit_urls_csv:
        df = pd.read_csv(legit_urls_csv)
        urls = df["url"].tolist()
    else:
        urls = [
            "https://www.google.com", "https://www.wikipedia.org", "https://www.github.com",
            "https://www.microsoft.com", "https://www.amazon.com", "https://www.nytimes.com",
            "https://www.python.org", "https://www.reddit.com", "https://www.linkedin.com", "https://www.apple.com",
        ]
    X = np.array([features_to_vector(extract_url_features(u)) for u in urls])
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_PATH)
    print(f"Anomaly model trained on {len(urls)} legitimate URLs -> {MODEL_PATH}")
    return model


def load_anomaly_model():
    return joblib.load(MODEL_PATH)


def score_anomaly(model, url: str) -> dict:
    features = extract_url_features(url)
    vector = np.array([features_to_vector(features)])
    raw_score = model.decision_function(vector)[0]
    anomaly_score = int(max(0, min(100, (0.5 - raw_score) * 100)))
    is_anomaly = model.predict(vector)[0] == -1
    return {"anomaly_score": anomaly_score, "is_anomaly": bool(is_anomaly)}


if __name__ == "__main__":
    train_anomaly_model()
