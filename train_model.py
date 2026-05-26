"""
PhishShield AI - Model Trainer v2
Run this once to train and save the phishing detection model.

Usage:
    python train_model.py

Output:
    phish_model.pkl      — trained Random Forest classifier
    phish_scaler.pkl     — feature scaler
    phish_features.pkl   — feature column order
    phish_report.txt     — accuracy metrics for your resume/README
"""

import pandas as pd
import numpy as np
import requests
import joblib
import math
import re
import io
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

# ── 1. LOAD DATA ──────────────────────────────────────────────────────────────

print("\n[1/5] Loading datasets...")

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishShield-Research/2.0)"}

def fetch_phishtank(limit=5000):
    """PhishTank verified phishing URLs — public CSV, no API key needed."""
    url = "http://data.phishtank.com/data/online-valid.csv"
    try:
        print("   Trying PhishTank live feed...")
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        df = pd.read_csv(io.StringIO(r.text), on_bad_lines="skip")
        # Column is 'url' in PhishTank CSV
        col = next((c for c in df.columns if "url" in c.lower()), None)
        if col:
            urls = df[col].dropna().tolist()[:limit]
            print(f"   PhishTank: {len(urls)} phishing URLs.")
            return urls
    except Exception as e:
        print(f"   PhishTank failed: {e}")
    return []

def fetch_openphish(limit=5000):
    """OpenPhish free feed — plain text, one URL per line."""
    url = "https://openphish.com/feed.txt"
    try:
        print("   Trying OpenPhish feed...")
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        urls = [u.strip() for u in r.text.splitlines() if u.strip().startswith("http")][:limit]
        print(f"   OpenPhish: {len(urls)} phishing URLs.")
        return urls
    except Exception as e:
        print(f"   OpenPhish failed: {e}")
    return []

def fetch_urlhaus(limit=5000):
    """URLhaus malware/phishing URLs — reliable CSV."""
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        print("   Trying URLhaus feed...")
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        # Skip comment lines starting with #
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        df = pd.read_csv(io.StringIO("\n".join(lines)), on_bad_lines="skip")
        col = next((c for c in df.columns if "url" in c.lower()), None)
        if col:
            urls = df[col].dropna().tolist()[:limit]
            print(f"   URLhaus: {len(urls)} malicious URLs.")
            return urls
    except Exception as e:
        print(f"   URLhaus failed: {e}")
    return []

def fetch_tranco(limit=5000):
    """Tranco top-1M legitimate domains — highly reliable."""
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        print("   Trying Tranco top domains...")
        import zipfile
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open(z.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"])
        domains = df["domain"].dropna().tolist()[:limit]
        urls = [f"https://{d}" for d in domains]
        print(f"   Tranco: {len(urls)} legitimate URLs.")
        return urls
    except Exception as e:
        print(f"   Tranco failed: {e}")
    return []

def fetch_alexa_fallback(limit=5000):
    """Majestic Million — fallback legit domains."""
    url = "https://downloads.majestic.com/majestic_million.csv"
    try:
        print("   Trying Majestic Million fallback...")
        r = requests.get(url, headers=HEADERS, timeout=20)
        r.raise_for_status()
        df = pd.read_csv(io.StringIO(r.text), on_bad_lines="skip")
        col = next((c for c in df.columns if "domain" in c.lower()), None)
        if col:
            domains = df[col].dropna().tolist()[:limit]
            urls = [f"https://{d}" for d in domains]
            print(f"   Majestic: {len(urls)} legitimate URLs.")
            return urls
    except Exception as e:
        print(f"   Majestic failed: {e}")
    return []

# Collect phishing URLs — try multiple sources
phish_urls = fetch_phishtank()
if len(phish_urls) < 100:
    phish_urls += fetch_openphish()
if len(phish_urls) < 100:
    phish_urls += fetch_urlhaus()

# Collect legit URLs — try multiple sources
legit_urls = fetch_tranco()
if len(legit_urls) < 100:
    legit_urls = fetch_alexa_fallback()

# Hard stop if we still don't have enough data
MIN_SAMPLES = 200
if len(phish_urls) < MIN_SAMPLES or len(legit_urls) < MIN_SAMPLES:
    print(f"""
ERROR: Not enough data to train.
  Phishing URLs collected: {len(phish_urls)}
  Legit URLs collected:    {len(legit_urls)}

This is likely a network issue. Please check your internet connection
and try again. If you're behind a firewall or VPN, try disabling it.
""")
    exit(1)

# Balance the dataset
n = min(len(phish_urls), len(legit_urls), 5000)
phish_urls = phish_urls[:n]
legit_urls = legit_urls[:n]
print(f"\n   Final: {n} phishing + {n} legit = {n*2} total samples")


# ── 2. FEATURE EXTRACTION ─────────────────────────────────────────────────────

print("\n[2/5] Extracting features...")

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".win", ".bid", ".download", ".racing", ".accountant"
}

SUSPICIOUS_KEYWORDS = [
    "secure", "login", "verify", "update", "account", "banking",
    "confirm", "password", "signin", "webscr", "paypal", "ebay",
    "amazon", "microsoft", "apple"
]

BRAND_NAMES = [
    "google", "amazon", "netflix", "paypal", "microsoft",
    "linkedin", "apple", "facebook", "instagram", "twitter"
]

def url_entropy(url: str) -> float:
    if not url:
        return 0.0
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def extract_features(url: str) -> dict:
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
        "brand_in_subdomain": int(any(b in domain and b not in sld
                                      for b in BRAND_NAMES)),
        "is_ip_address":      int(bool(re.fullmatch(
                                  r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", domain))),
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

print("   Processing legitimate URLs...")
df_legit = build_dataframe(legit_urls, label=0)

df = pd.concat([df_phish, df_legit], ignore_index=True).dropna()
print(f"   Dataset ready: {len(df)} samples, {len(FEATURE_COLS)} features")


# ── 3. TRAIN ──────────────────────────────────────────────────────────────────

print("\n[3/5] Training Random Forest classifier...")

X = df[FEATURE_COLS]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_s, y_train)
print("   Training complete.")


# ── 4. EVALUATE ───────────────────────────────────────────────────────────────

print("\n[4/5] Evaluating model...")

y_pred     = model.predict(X_test_s)
report     = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
cm         = confusion_matrix(y_test, y_pred)
cv_scores  = cross_val_score(model, scaler.transform(X), y, cv=5, scoring="f1")

importances = pd.Series(model.feature_importances_, index=FEATURE_COLS)
top_features = importances.sort_values(ascending=False).head(5)

print("\n" + "="*55)
print("  PHISHSHIELD AI — MODEL EVALUATION REPORT")
print("="*55)
print(report)
print(f"  Confusion Matrix:\n{cm}")
print(f"\n  5-Fold CV F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
print(f"\n  Top 5 features:\n{top_features.to_string()}")
print("="*55 + "\n")

with open("phish_report.txt", "w") as f:
    f.write("PhishShield AI — Model Evaluation Report\n")
    f.write("="*55 + "\n\n")
    f.write(report)
    f.write(f"\nConfusion Matrix:\n{cm}\n")
    f.write(f"\n5-Fold CV F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}\n")
    f.write(f"\nTop features:\n{top_features.to_string()}\n")

print("[4/5] Report saved to phish_report.txt")


# ── 5. SAVE ───────────────────────────────────────────────────────────────────

print("\n[5/5] Saving model artifacts...")
joblib.dump(model,        "phish_model.pkl")
joblib.dump(scaler,       "phish_scaler.pkl")
joblib.dump(FEATURE_COLS, "phish_features.pkl")

print("   phish_model.pkl")
print("   phish_scaler.pkl")
print("   phish_features.pkl")
print("\n✅ Done. Run server.py to start the API.\n")