"""
feature_extraction.py

Turns a raw URL string into a fixed-size numeric feature vector.
Both the supervised classifier (train_model.py) and the anomaly
detector (anomaly_detector.py) use this SAME function, so a URL is
always represented the same way no matter which model looks at it.
"""

import re
import tldextract

FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_digits", "num_at",
    "num_subdomains", "has_ip", "has_https", "is_shortened", "has_suspicious_word",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
SUSPICIOUS_WORDS = {"login", "verify", "secure", "account", "update", "confirm", "signin"}
IP_PATTERN = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def extract_url_features(url: str) -> dict:
    url = url.strip()
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_at": url.count("@"),
        "num_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "has_ip": 1 if IP_PATTERN.search(url) else 0,
        "has_https": 1 if url.lower().startswith("https://") else 0,
        "is_shortened": 1 if domain in SHORTENERS else 0,
        "has_suspicious_word": 1 if any(w in url.lower() for w in SUSPICIOUS_WORDS) else 0,
    }


def features_to_vector(features: dict) -> list:
    return [features[name] for name in FEATURE_NAMES]
