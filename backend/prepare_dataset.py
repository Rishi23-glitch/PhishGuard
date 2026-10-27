"""
prepare_dataset.py — turns a downloaded phishing dataset into the two files
PhishGuard needs:

    phishing_urls.csv   columns: url,label   (1 = phishing, 0 = legitimate)
    legit_urls.csv      column:  url          (legitimate only, for the anomaly model)

Usage (run inside the backend folder):

    python prepare_dataset.py          # step 1: look at samples, writes nothing
    python prepare_dataset.py 0        # step 2: say which label value means PHISHING

Optional: python prepare_dataset.py 0 myfile.csv   (if it can't find your file)
"""

import glob
import sys

import pandas as pd

OUTPUTS = {"phishing_urls.csv", "legit_urls.csv", "results.csv"}

# ---- find the downloaded CSV ----
if len(sys.argv) >= 3:
    path = sys.argv[2]
else:
    found = [f for f in glob.glob("*.csv") if f.lower() not in OUTPUTS]
    if len(found) != 1:
        print("I need exactly one downloaded dataset CSV in this folder.")
        print("CSV files I can see:", found or "none")
        print("Tell me which one: python prepare_dataset.py 0 YOUR_FILE.csv")
        sys.exit(1)
    path = found[0]

df = pd.read_csv(path)
cols = {c.lower(): c for c in df.columns}
if "url" not in cols or "label" not in cols:
    print("Could not find 'url' and 'label' columns. Columns in your file:")
    print(list(df.columns))
    sys.exit(1)

url_col, label_col = cols["url"], cols["label"]
print(f"Using file: {path}  ({len(df)} rows)")
print("Label counts:")
print(df[label_col].value_counts())

# ---- step 1: show samples so you can tell which label is phishing ----
if len(sys.argv) < 2:
    for value in sorted(df[label_col].unique()):
        print(f"\n5 example URLs where label = {value}:")
        for u in df[df[label_col] == value][url_col].head(5):
            print("   ", u)
    print("\nLook at the two lists. Which one looks like PHISHING?")
    print("Then run again, giving that number, e.g.:  python prepare_dataset.py 0")
    sys.exit(0)

# ---- step 2: write the files ----
phish_value = int(sys.argv[1])
labels = (df[label_col] == phish_value).astype(int)   # 1 = phishing
out = pd.DataFrame({"url": df[url_col], "label": labels}).dropna().drop_duplicates("url")
out.to_csv("phishing_urls.csv", index=False)
out[out["label"] == 0][["url"]].to_csv("legit_urls.csv", index=False)

print("\nDone.")
print(out["label"].value_counts().rename({1: "phishing (1)", 0: "legitimate (0)"}))
print("Wrote phishing_urls.csv and legit_urls.csv")