## 7.1 Dataset and setup
Total URLs: 235370 (100520 phishing, 134850 legitimate). Train: 188296, test: 47074. Split: stratified random 80/20 (no date column, so this is a proxy for unseen data).

## 7.2 Classifier performance (held-out test set)
| Metric | Value |
|---|---|
| Accuracy | 96.64% |
| Precision | 98.01% |
| Recall | 94.04% |
| F1-score | 95.99% |
| ROC-AUC | 0.9879 |

Confusion matrix: TN=26587, FP=383, FN=1198, TP=18906

## 7.3 Unseen-pattern (zero-day proxy) comparison
| Configuration | Phishing detection rate | False-positive rate |
|---|---|---|
| Classifier only | 94.04% | 1.42% |
| Anomaly layer only | 57.71% | 5.15% |
| Classifier OR anomaly | 95.02% | 5.74% |

## 7.4 Masking checks
Punycode check correct on 4/4 cases. Redirect-chain test: {'tested': True, 'flagged': True, 'reason': 'URL redirects 4 times before landing on its final page'}.
