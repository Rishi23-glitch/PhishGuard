# PhishGuard

Phishing detection and awareness platform — React frontend, Flask backend
with a 3-layer ML detection pipeline (classifier + masking detector +
anomaly detector), plus live Snort network monitoring.

## Folder structure

```
PhishGuard/
├── frontend/          React + Vite + Tailwind
│   └── src/App.jsx    the whole UI (sidebar, checker, history, quiz, network monitor)
└── backend/           Flask API + ML models
    ├── app.py                 main server (all endpoints)
    ├── feature_extraction.py  URL → numeric features
    ├── masking_detector.py    punycode / redirect / cloaking checks
    ├── anomaly_detector.py    Isolation Forest (non-signature detection)
    ├── train_model.py         trains the supervised classifier
    └── snort_integration.py   reads Snort's live alert log
```

## How to open this in VS Code

1. Unzip this folder anywhere (e.g. your Desktop).
2. In VS Code: **File → Open Folder** → select the `PhishGuard` folder.
3. Open **two terminals** inside VS Code (Terminal → New Terminal, then click
   the `+` to open a second one) — one for the backend, one for the frontend.

## Terminal 1 — Backend

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python anomaly_detector.py
python app.py
```

Leave this running. The API is now live at `http://localhost:5000`.

> **Snort integration (optional):** to see real alerts in the Network Monitor
> tab, run Snort separately inside WSL (`sudo snort -i eth0 -c /etc/snort/snort.conf -A fast -l /var/log/snort`)
> and run this backend from inside that same WSL session instead of
> PowerShell, so it can read Snort's log file directly. Without Snort
> running, the Network Monitor tab still works — it just shows a labeled
> demo alert instead of live ones.

## Terminal 2 — Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open the `localhost:5173` link it prints. The site is now fully working —
Overview, Checker, History, Awareness, and Network Monitor all live.

## Before your final submission

- Replace the small built-in training data in `train_model.py` with a real
  phishing URL dataset (`phishing_urls.csv`, columns: `url,label`) — search
  Kaggle or UCI for "phishing url dataset".
- Replace `anomaly_detector.py`'s built-in legitimate URL list with a larger
  one (e.g. the Tranco top-sites list) for a more realistic anomaly baseline.
