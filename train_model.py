"""
PhishShield AI - Model Trainer v3
Pulls up to 50,000 URLs from multiple live sources for better separation.

Usage:
    python train_model.py

Output:
    phish_model.pkl
    phish_scaler.pkl
    phish_features.pkl
    phish_report.txt
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

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishShield-Research/3.0)"}
TARGET_PER_CLASS = 25000  # 25k phishing + 25k legit = 50k total

# ── 1. DATA SOURCES ───────────────────────────────────────────────────────────

print("\n[1/5] Loading datasets...")

def fetch_phishtank(limit=20000):
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

def fetch_openphish(limit=10000):
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

def fetch_urlhaus(limit=10000):
    try:
        print("   Trying URLhaus...")
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=HEADERS, timeout=30)
        r.raise_for_status()
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        df = pd.read_csv(io.StringIO("\n".join(lines)), on_bad_lines="skip")
        col = next((c for c in df.columns if "url" in c.lower()), None)
        if col:
            urls = df[col].dropna().tolist()[:limit]
            print(f"   URLhaus: {len(urls)} URLs")
            return urls
    except Exception as e:
        print(f"   URLhaus failed: {e}")
    return []

def fetch_phishstats(limit=10000):
    """PhishStats — free CSV, updated hourly."""
    try:
        print("   Trying PhishStats...")
        r = requests.get("https://phishstats.info/phish_score.csv", headers=HEADERS, timeout=30)
        r.raise_for_status()
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        df = pd.read_csv(io.StringIO("\n".join(lines)), on_bad_lines="skip", header=None)
        # PhishStats format: date, score, url, ip
        if df.shape[1] >= 3:
            urls = df.iloc[:, 2].dropna().tolist()[:limit]
            urls = [u for u in urls if str(u).startswith("http")]
            print(f"   PhishStats: {len(urls)} URLs")
            return urls
    except Exception as e:
        print(f"   PhishStats failed: {e}")
    return []

def fetch_tranco(limit=25000):
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

def fetch_majestic(limit=25000):
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

def fetch_cisco_umbrella(limit=25000):
    """Cisco Umbrella top 1M — highly reliable legit source."""
    try:
        print("   Trying Cisco Umbrella...")
        r = requests.get("https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", headers=HEADERS, timeout=60)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open(z.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"])
        domains = df["domain"].dropna().tolist()[:limit]
        urls = [f"https://{d}" for d in domains]
        print(f"   Cisco Umbrella: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"   Cisco Umbrella failed: {e}")
    return []

# ── Collect phishing URLs ─────────────────────────────────────────────────────
phish_urls = []
phish_urls += fetch_phishtank(20000)
phish_urls += fetch_openphish(10000)
phish_urls += fetch_urlhaus(10000)
phish_urls += fetch_phishstats(10000)

# Deduplicate
phish_urls = list(dict.fromkeys(phish_urls))
print(f"\n   Total phishing URLs collected: {len(phish_urls)}")

# ── Collect legit URLs ────────────────────────────────────────────────────────
legit_urls = []
legit_urls += fetch_tranco(25000)
if len(legit_urls) < 10000:
    legit_urls += fetch_majestic(25000)
if len(legit_urls) < 10000:
    legit_urls += fetch_cisco_umbrella(25000)

legit_urls = list(dict.fromkeys(legit_urls))
print(f"   Total legit URLs collected: {len(legit_urls)}")

# ── Guard ─────────────────────────────────────────────────────────────────────
MIN_SAMPLES = 500
if len(phish_urls) < MIN_SAMPLES or len(legit_urls) < MIN_SAMPLES:
    print(f"""
ERROR: Not enough data.
  Phishing: {len(phish_urls)}
  Legit:    {len(legit_urls)}
Check your internet connection and try again.
""")
    exit(1)

# Balance
n = min(len(phish_urls), len(legit_urls), TARGET_PER_CLASS)
phish_urls = phish_urls[:n]
legit_urls = legit_urls[:n]
print(f"\n   Final dataset: {n} phishing + {n} legit = {n*2} total")

# ── 2. FEATURE EXTRACTION ─────────────────────────────────────────────────────

print("\n[2/5] Extracting features...")

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".win", ".bid", ".download", ".racing", ".accountant",
    ".pw", ".cc", ".su", ".work",
}

# Brand names NOT included here — they're caught by brand_in_subdomain feature
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
    n_estimators=300,
    max_depth=25,
    min_samples_split=4,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train_s, y_train)
print("   Training complete.")

# ── 4. EVALUATE ───────────────────────────────────────────────────────────────

print("\n[4/5] Evaluating model...")

y_pred    = model.predict(X_test_s)
report    = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
cm        = confusion_matrix(y_test, y_pred)
cv_scores = cross_val_score(model, scaler.transform(X), y, cv=5, scoring="f1")

importances  = pd.Series(model.feature_importances_, index=FEATURE_COLS)
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
print("\n✅ Done. Push .pkl files to GitHub to deploy.\n")