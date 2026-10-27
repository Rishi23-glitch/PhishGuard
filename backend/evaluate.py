"""
evaluate.py — produces the measurements for Section 7 of the paper.

Run from the backend folder AFTER you have put a real dataset at
phishing_urls.csv (columns: url,label  where 1 = phishing, 0 = legitimate;
an optional 'date' column makes the zero-day test time-based).

    python evaluate.py

Outputs: results.md (paste-ready tables) and results.json.
Nothing here is made up: every number comes from your data.
"""

import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from feature_extraction import extract_url_features, features_to_vector
from masking_detector import check_punycode, check_redirect_chain

DATA_PATH = "phishing_urls.csv"
SEED = 42

if not os.path.exists(DATA_PATH):
    sys.exit(f"{DATA_PATH} not found. Put a real labeled dataset there first.")

df = pd.read_csv(DATA_PATH).dropna(subset=["url", "label"])
df["label"] = df["label"].astype(int)
n_total, n_phish = len(df), int(df["label"].sum())
print(f"Loaded {n_total} URLs ({n_phish} phishing, {n_total - n_phish} legitimate)")

# ---- split: time-based if a date column exists, otherwise stratified random ----
if "date" in df.columns:
    df = df.sort_values("date")
    cut = int(len(df) * 0.8)
    train, test = df.iloc[:cut], df.iloc[cut:]
    split_note = "time-based (oldest 80% train, newest 20% test)"
else:
    train, test = train_test_split(df, test_size=0.2, random_state=SEED, stratify=df["label"])
    split_note = "stratified random 80/20 (no date column, so this is a proxy for unseen data)"


def vec(urls):
    return np.array([features_to_vector(extract_url_features(u)) for u in urls])


Xtr, ytr = vec(train["url"]), train["label"].values
Xte, yte = vec(test["url"]), test["label"].values

# ---- 7.2 classifier ----
clf = RandomForestClassifier(n_estimators=200, random_state=SEED).fit(Xtr, ytr)
prob = clf.predict_proba(Xte)[:, 1]
pred = (prob >= 0.5).astype(int)
cm = confusion_matrix(yte, pred, labels=[0, 1])
tn, fp, fn, tp = cm.ravel()
clf_metrics = {
    "accuracy": accuracy_score(yte, pred),
    "precision": precision_score(yte, pred, zero_division=0),
    "recall": recall_score(yte, pred, zero_division=0),
    "f1": f1_score(yte, pred, zero_division=0),
    "roc_auc": roc_auc_score(yte, prob) if len(set(yte)) > 1 else float("nan"),
    "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
}

# ---- 7.3 zero-day proxy: classifier vs anomaly vs either ----
legit_train = Xtr[ytr == 0]
iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=SEED).fit(legit_train)
anom = (iso.predict(Xte) == -1)          # True = flagged as anomalous
clf_flag = pred == 1
either = clf_flag | anom


def rates(flag):
    phish, legit = yte == 1, yte == 0
    return {
        "detection_rate": float(flag[phish].mean()) if phish.any() else float("nan"),
        "false_positive_rate": float(flag[legit].mean()) if legit.any() else float("nan"),
    }


zero_day = {
    "classifier_only": rates(clf_flag),
    "anomaly_only": rates(anom),
    "classifier_or_anomaly": rates(either),
}

# ---- 7.4 masking: punycode (offline) + redirect chain (needs internet) ----
punycode_cases = [("http://xn--80ak6aa92e.com", True), ("http://xn--pple-43d.com", True),
                  ("https://www.google.com", False), ("https://www.python.org", False)]
puny_ok = sum(check_punycode(u)[0] == expected for u, expected in punycode_cases)
redirect = {"tested": False}
try:
    flagged, reason = check_redirect_chain("https://httpbin.org/redirect/4")
    if reason and "could not be reached" in reason:
        redirect = {"tested": False, "error": "httpbin.org unreachable (offline?) - not counted"}
    else:
        redirect = {"tested": True, "flagged": bool(flagged), "reason": reason}
except Exception as e:  # no internet etc.
    redirect = {"tested": False, "error": str(e)}

results = {
    "dataset": {"total": n_total, "phishing": n_phish, "legitimate": n_total - n_phish,
                "train": len(train), "test": len(test), "split": split_note},
    "classifier": clf_metrics, "zero_day_proxy": zero_day,
    "masking": {"punycode_correct": f"{puny_ok}/{len(punycode_cases)}", "redirect_chain": redirect},
}
json.dump(results, open("results.json", "w"), indent=2)

pct = lambda x: f"{x * 100:.2f}%"
md = f"""## 7.1 Dataset and setup
Total URLs: {n_total} ({n_phish} phishing, {n_total - n_phish} legitimate). Train: {len(train)}, test: {len(test)}. Split: {split_note}.

## 7.2 Classifier performance (held-out test set)
| Metric | Value |
|---|---|
| Accuracy | {pct(clf_metrics['accuracy'])} |
| Precision | {pct(clf_metrics['precision'])} |
| Recall | {pct(clf_metrics['recall'])} |
| F1-score | {pct(clf_metrics['f1'])} |
| ROC-AUC | {clf_metrics['roc_auc']:.4f} |

Confusion matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}

## 7.3 Unseen-pattern (zero-day proxy) comparison
| Configuration | Phishing detection rate | False-positive rate |
|---|---|---|
| Classifier only | {pct(zero_day['classifier_only']['detection_rate'])} | {pct(zero_day['classifier_only']['false_positive_rate'])} |
| Anomaly layer only | {pct(zero_day['anomaly_only']['detection_rate'])} | {pct(zero_day['anomaly_only']['false_positive_rate'])} |
| Classifier OR anomaly | {pct(zero_day['classifier_or_anomaly']['detection_rate'])} | {pct(zero_day['classifier_or_anomaly']['false_positive_rate'])} |

## 7.4 Masking checks
Punycode check correct on {puny_ok}/{len(punycode_cases)} cases. Redirect-chain test: {redirect}.
"""
open("results.md", "w", encoding="utf-8").write(md)
print(md)
print("Saved results.md and results.json")
