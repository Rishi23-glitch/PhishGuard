"""
app.py — PhishGuard backend (final, with dashboard history)

Endpoints:
  POST /check-url       -> ML + masking + anomaly fusion verdict
  POST /check-email     -> email heuristic verdict
  GET  /network-alerts  -> live alerts from Snort's log
  GET  /history         -> recent scans (powers the dashboard + history tab)
  GET  /stats           -> aggregate counts for the dashboard

Scan history is kept in memory (resets when the server restarts).
That's intentional for a course project — swap HISTORY for a real
database (SQLite/Postgres) if you want it to persist long-term.
"""

import os
import uuid
from datetime import datetime

import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

from feature_extraction import extract_url_features, features_to_vector
from masking_detector import analyze_masking
from anomaly_detector import load_anomaly_model, score_anomaly
from snort_integration import get_recent_alerts

app = Flask(__name__)
CORS(app)

CLASSIFIER_PATH = "phishing_model.pkl"
classifier = joblib.load(CLASSIFIER_PATH) if os.path.exists(CLASSIFIER_PATH) else None
anomaly_model = load_anomaly_model() if os.path.exists("anomaly_model.pkl") else None

WEIGHT_CLASSIFIER = 0.5
WEIGHT_MASKING = 0.3
WEIGHT_ANOMALY = 0.2

HISTORY = []  # newest appended at the end; /history reverses for display
MAX_HISTORY = 200


def _record_scan(scan_type, input_value, verdict, score, reasons):
    HISTORY.append({
        "id": str(uuid.uuid4())[:8],
        "type": scan_type,
        "input": input_value[:120],
        "verdict": verdict,
        "score": score,
        "reasons": reasons,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    if len(HISTORY) > MAX_HISTORY:
        del HISTORY[0]


@app.route("/check-url", methods=["POST"])
def check_url():
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    reasons = []
    classifier_score = 0
    if classifier is not None:
        features = extract_url_features(url)
        vector = np.array([features_to_vector(features)])
        proba = classifier.predict_proba(vector)[0]
        classifier_score = round(proba[1] * 100)
        if classifier_score >= 60:
            reasons.append({"type": "model", "text": "URL structure matches known phishing patterns"})

    masking_result = analyze_masking(url)
    for r in masking_result["reasons"]:
        reasons.append({"type": "masking", "text": r})

    anomaly_score = 0
    if anomaly_model is not None:
        anomaly_result = score_anomaly(anomaly_model, url)
        anomaly_score = anomaly_result["anomaly_score"]
        if anomaly_result["is_anomaly"]:
            reasons.append({"type": "anomaly", "text": "URL structure is statistically unusual compared to legitimate sites"})

    final_score = round(
        classifier_score * WEIGHT_CLASSIFIER
        + masking_result["masking_score"] * WEIGHT_MASKING
        + anomaly_score * WEIGHT_ANOMALY
    )
    final_score = min(final_score, 97)

    if not reasons:
        reasons.append({"type": "clean", "text": "No suspicious patterns detected across any detection layer"})

    verdict = "phishing" if final_score >= 60 else "caution" if final_score >= 30 else "safe"
    _record_scan("url", url, verdict, final_score, reasons)

    return jsonify({"verdict": verdict, "score": final_score, "reasons": reasons})


@app.route("/check-email", methods=["POST"])
def check_email():
    data = request.get_json(force=True)
    text = (data or {}).get("text", "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400

    reasons = []
    score = 5
    lowered = text.lower()

    if any(w in lowered for w in ["urgent", "immediately", "24 hours", "suspend", "verify now", "act now"]):
        reasons.append({"type": "content", "text": "Urgency / pressure language detected"})
        score += 30

    if any(w in lowered for w in ["password", "ssn", "bank account", "card number", "otp"]):
        reasons.append({"type": "content", "text": "Requests sensitive credentials directly"})
        score += 35

    if not reasons:
        reasons.append({"type": "clean", "text": "No urgency language or credential requests found"})

    score = min(score, 97)
    verdict = "phishing" if score >= 60 else "caution" if score >= 30 else "safe"
    _record_scan("email", text, verdict, score, reasons)

    return jsonify({"verdict": verdict, "score": score, "reasons": reasons})


@app.route("/network-alerts", methods=["GET"])
def network_alerts():
    return jsonify(get_recent_alerts(limit=20))


@app.route("/history", methods=["GET"])
def history():
    limit = int(request.args.get("limit", 50))
    return jsonify({"scans": list(reversed(HISTORY))[:limit]})


@app.route("/stats", methods=["GET"])
def stats():
    total = len(HISTORY)
    phishing = sum(1 for h in HISTORY if h["verdict"] == "phishing")
    caution = sum(1 for h in HISTORY if h["verdict"] == "caution")
    safe = sum(1 for h in HISTORY if h["verdict"] == "safe")
    return jsonify({
        "total_scans": total, "phishing": phishing, "caution": caution, "safe": safe,
        "urls_scanned": sum(1 for h in HISTORY if h["type"] == "url"),
        "emails_scanned": sum(1 for h in HISTORY if h["type"] == "email"),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")
