"""
PhishShield AI - Model Trainer v4
Sources: PhishTank + OpenPhish (phishing) | Tranco + Majestic (legit)
URLhaus removed -- malware URLs skew path_length feature causing false positives.

Usage:
    python train_model.py
"""

import pandas as pd
import numpy as np
import requests
import joblib
import math
import re
import io
import zipfile
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishShield-Research/4.0)"}
TARGET_PER_CLASS = 15000

# ── 1. DATA SOURCES ───────────────────────────────────────────────────────────

print("\n[1/5] Loading datasets...")

def fetch_phishtank(limit=15000):
    try:
        print("   Trying PhishTank...")
        r = requests.get("http://data.phishtank.com/data/online-valid.csv", headers=HEADERS, timeout=30)
        r.raise_for_status()
        df = pd.read_csv(io.StringIO(r.text), on_bad_lines="skip")
        col = next((c for c in df.columns if "url" in c.lower()), None)
        if col:
            urls = df[col].dropna().tolist()[:limit]
            print(f"   PhishTank: {len(urls)} URLs")
            return urls
    except Exception as e:
        print(f"   PhishTank failed: {e}")
    return []

def fetch_openphish(limit=15000):
    try:
        print("   Trying OpenPhish...")
        r = requests.get("https://openphish.com/feed.txt", headers=HEADERS, timeout=15)
        r.raise_for_status()
        urls = [u.strip() for u in r.text.splitlines() if u.strip().startswith("http")][:limit]
        print(f"   OpenPhish: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"   OpenPhish failed: {e}")
    return []

def fetch_tranco(limit=15000):
    try:
        print("   Trying Tranco top-1M...")
        r = requests.get("https://tranco-list.eu/top-1m.csv.zip", headers=HEADERS, timeout=60)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open(z.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"])
        domains = df["domain"].dropna().tolist()[:limit]
        urls = [f"https://{d}" for d in domains]
        print(f"   Tranco: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"   Tranco failed: {e}")
    return []

def fetch_majestic(limit=15000):
    try:
        print("   Trying Majestic Million...")
        r = requests.get("https://downloads.majestic.com/majestic_million.csv", headers=HEADERS, timeout=30)
        r.raise_for_status()
        df = pd.read_csv(io.StringIO(r.text), on_bad_lines="skip")
        col = next((c for c in df.columns if "domain" in c.lower()), None)
        if col:
            domains = df[col].dropna().tolist()[:limit]
            urls = [f"https://{d}" for d in domains]
            print(f"   Majestic: {len(urls)} URLs")
            return urls
    except Exception as e:
        print(f"   Majestic failed: {e}")
    return []

# Phishing
phish_urls = []
phish_urls += fetch_phishtank(15000)
phish_urls += fetch_openphish(15000)
phish_urls = list(dict.fromkeys(phish_urls))
print(f"\n   Total phishing URLs: {len(phish_urls)}")

# Legit
legit_urls = fetch_tranco(15000)
if len(legit_urls) < 1000:
    legit_urls += fetch_majestic(15000)
legit_urls = list(dict.fromkeys(legit_urls))
print(f"   Total legit URLs: {len(legit_urls)}")

if len(phish_urls) < 200 or len(legit_urls) < 200:
    print(f"\nERROR: Not enough data. Phishing: {len(phish_urls)}, Legit: {len(legit_urls)}")
    exit(1)

n = min(len(phish_urls), len(legit_urls), TARGET_PER_CLASS)
phish_urls = phish_urls[:n]
legit_urls = legit_urls[:n]
print(f"   Final: {n} phishing + {n} legit = {n*2} total\n")

# ── 2. FEATURE EXTRACTION ─────────────────────────────────────────────────────

print("[2/5] Extracting features...")

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".win", ".bid", ".download", ".racing", ".accountant",
    ".pw", ".cc", ".su", ".work",
}

# No brand names here -- they cause false positives on real brand sites
SUSPICIOUS_KEYWORDS = [
    "secure", "login", "verify", "update", "account", "banking",
    "confirm", "password", "signin", "webscr",
]

BRAND_NAMES = [
    "google", "amazon", "netflix", "paypal", "microsoft",
    "linkedin", "apple", "facebook", "instagram", "twitter",
    "bankofamerica", "chase", "wellsfargo", "dropbox", "github",
]

def url_entropy(url):
    if not url: return 0.0
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_features(url):
    url    = str(url).strip().lower()
    domain = re.sub(r"https?://", "", url).split("/")[0]
    parts  = domain.split(".")
    tld    = "." + parts[-1] if len(parts) > 1 else ""
    sld    = parts[-2] if len(parts) > 1 else domain
    path   = url[len(domain):]
    return {
        "url_length":         len(url),
        "domain_length":      len(domain),
        "path_length":        len(path),
        "subdomain_depth":    max(0, len(parts) - 2),
        "dot_count":          url.count("."),
        "hyphen_count":       domain.count("-"),
        "at_symbol":          int("@" in url),
        "double_slash":       int("//" in url[7:]),
        "digit_count":        sum(c.isdigit() for c in domain),
        "special_char_count": len(re.findall(r"[%&=\?\+\#\!\*]", url)),
        "url_entropy":        round(url_entropy(url), 4),
        "suspicious_tld":     int(tld in SUSPICIOUS_TLDS),
        "keyword_in_url":     int(any(k in url for k in SUSPICIOUS_KEYWORDS)),
        "brand_in_subdomain": int(any(b in domain and b not in sld for b in BRAND_NAMES)),
        "is_ip_address":      int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", domain))),
    }

FEATURE_COLS = list(extract_features("http://example.com").keys())

def build_dataframe(urls, label):
    rows = []
    for url in urls:
        try:
            rows.append({**extract_features(url), "label": label})
        except Exception:
            pass
    return pd.DataFrame(rows)

print("   Processing phishing URLs...")
df_phish = build_dataframe(phish_urls, label=1)
print("   Processing legit URLs...")
df_legit = build_dataframe(legit_urls, label=0)

df = pd.concat([df_phish, df_legit], ignore_index=True).dropna()
print(f"   Dataset: {len(df)} samples, {len(FEATURE_COLS)} features\n")

# ── 3. TRAIN ──────────────────────────────────────────────────────────────────

print("[3/5] Training Random Forest...")

X = df[FEATURE_COLS]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train_s, y_train)
print("   Training complete.\n")

# ── 4. EVALUATE ───────────────────────────────────────────────────────────────

print("[4/5] Evaluating...")

y_pred    = model.predict(X_test_s)
report    = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
cm        = confusion_matrix(y_test, y_pred)
cv_scores = cross_val_score(model, scaler.transform(X), y, cv=5, scoring="f1")

importances  = pd.Series(model.feature_importances_, index=FEATURE_COLS)
top_features = importances.sort_values(ascending=False).head(5)

print("="*55)
print("  PHISHSHIELD AI -- MODEL EVALUATION REPORT")
print("="*55)
print(report)
print(f"  Confusion Matrix:\n{cm}")
print(f"\n  5-Fold CV F1: {cv_scores.mean():.3f} +/- {cv_scores.std():.3f}")
print(f"\n  Top 5 features:\n{top_features.to_string()}")
print("="*55)

with open("phish_report.txt", "w") as f:
    f.write("PhishShield AI -- Model Evaluation Report\n")
    f.write("="*55 + "\n\n")
    f.write(report)
    f.write(f"\nConfusion Matrix:\n{cm}\n")
    f.write(f"\n5-Fold CV F1: {cv_scores.mean():.3f} +/- {cv_scores.std():.3f}\n")
    f.write(f"\nTop features:\n{top_features.to_string()}\n")

# ── 5. SAVE ───────────────────────────────────────────────────────────────────

print("\n[5/5] Saving artifacts...")
joblib.dump(model,        "phish_model.pkl")
joblib.dump(scaler,       "phish_scaler.pkl")
joblib.dump(FEATURE_COLS, "phish_features.pkl")
print("   phish_model.pkl")
print("   phish_scaler.pkl")
print("   phish_features.pkl")
print("\nDone. Run: git add *.pkl && git commit -m retrain && git push\n")