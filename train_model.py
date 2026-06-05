"""
PhishShield AI - Model Trainer v5
Sources: PhishTank + OpenPhish (phishing) | Tranco (legit)
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

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishShield-Research/5.0)"}
TARGET_PER_CLASS = 5000
CONFIDENCE_THRESHOLD = 0.60

# ── TRUSTED DOMAIN WHITELIST ──────────────────────────────────────────────────
TRUSTED_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "accounts.google.com", "mail.google.com", "drive.google.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "microsoftonline.com", "azure.com", "bing.com",
    "apple.com", "icloud.com", "appleid.apple.com",
    "amazon.com", "amazon.in", "amazonaws.com",
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "paypal.com", "paypal.me",
    "chase.com", "bankofamerica.com", "wellsfargo.com",
    "twitter.com", "x.com", "linkedin.com", "reddit.com",
    "youtube.com", "tiktok.com", "snapchat.com",
    "slack.com", "discord.com", "zoom.us",
    "dropbox.com", "github.com", "gitlab.com",
    "netflix.com", "spotify.com",
    "cloudflare.com", "wikipedia.org", "archive.org",
    "chatgpt.com", "openai.com", "anthropic.com", "claude.ai", "console.anthropic.com",
    "railway.app", "vercel.app", "netlify.app",
}

def get_root_domain(url: str) -> str:
    url = str(url).strip().lower()
    domain = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def is_trusted(url: str) -> bool:
    url = str(url).strip().lower()
    domain = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in TRUSTED_DOMAINS:
            return True
    return False

# ── 1. LOAD DATA ──────────────────────────────────────────────────────────────
print("\n[1/5] Loading datasets...")

def fetch_phishtank(limit=5000):
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

def fetch_openphish(limit=5000):
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

def fetch_tranco(limit=5000):
    try:
        print("   Trying Tranco top-1M...")
        r = requests.get("https://tranco-list.eu/top-1m.csv.zip", headers=HEADERS, timeout=60)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open(z.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"])
        domains = df["domain"].dropna().tolist()
        # Spread across ranks for diversity
        selected = domains[:limit//3] + domains[1000:1000+limit//3] + domains[5000:5000+limit//3]
        urls = [f"https://{d}/" for d in selected[:limit]]
        print(f"   Tranco: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"   Tranco failed: {e}")
    return []

# Collect phishing
phish_urls = fetch_phishtank(TARGET_PER_CLASS)
if len(phish_urls) < 100:
    phish_urls += fetch_openphish(TARGET_PER_CLASS)
phish_urls += fetch_openphish(TARGET_PER_CLASS - len(phish_urls)) if len(phish_urls) < TARGET_PER_CLASS else []
phish_urls = list(dict.fromkeys(phish_urls))[:TARGET_PER_CLASS]

# Collect legit
legit_urls = fetch_tranco(TARGET_PER_CLASS)

if len(phish_urls) < 200 or len(legit_urls) < 200:
    print(f"\nERROR: Not enough data. Phishing: {len(phish_urls)}, Legit: {len(legit_urls)}")
    exit(1)

n = min(len(phish_urls), len(legit_urls))
phish_urls = phish_urls[:n]
legit_urls = legit_urls[:n]
print(f"\n   Final: {n} phishing + {n} legit = {n*2} total")

# ── 2. FEATURE EXTRACTION ─────────────────────────────────────────────────────
print("\n[2/5] Extracting features...")

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".win", ".bid", ".download", ".racing", ".accountant",
    ".pw", ".cc", ".su", ".work",
}

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
    url    = re.sub(r"^(https?://)www\.", r"\1", url)
    domain = re.sub(r"https?://", "", url).split("/")[0].split("?")[0].split("#")[0]
    parts  = domain.split(".")
    tld    = "." + parts[-1] if len(parts) > 1 else ""
    sld    = parts[-2] if len(parts) > 1 else domain
    path   = url[len(domain):]

    brand_in_subdomain = int(
        any(b in domain and b != sld for b in BRAND_NAMES)
    )

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
        "brand_in_subdomain": brand_in_subdomain,
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
print(f"   Dataset: {len(df)} samples, {len(FEATURE_COLS)} features")

# ── 3. TRAIN ──────────────────────────────────────────────────────────────────
print("\n[3/5] Training Random Forest...")

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
print("   Training complete.")

# ── 4. EVALUATE ───────────────────────────────────────────────────────────────
print("\n[4/5] Evaluating...")

y_pred    = model.predict(X_test_s)
report    = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])
cm        = confusion_matrix(y_test, y_pred)
cv_scores = cross_val_score(model, scaler.transform(X), y, cv=5, scoring="f1")
importances  = pd.Series(model.feature_importances_, index=FEATURE_COLS)
top_features = importances.sort_values(ascending=False).head(5)

print("="*55)
print("  PHISHSHIELD AI — MODEL EVALUATION REPORT")
print("="*55)
print(report)
print(f"  Confusion Matrix:\n{cm}")
print(f"\n  5-Fold CV F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
print(f"\n  Top 5 features:\n{top_features.to_string()}")
print("="*55)

with open("phish_report.txt", "w") as f:
    f.write("PhishShield AI — Model Evaluation Report v5\n")
    f.write("="*55 + "\n\n")
    f.write(report)
    f.write(f"\nConfusion Matrix:\n{cm}\n")
    f.write(f"\n5-Fold CV F1: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}\n")
    f.write(f"\nTop features:\n{top_features.to_string()}\n")

# ── 5. SAVE ───────────────────────────────────────────────────────────────────
print("\n[5/5] Saving artifacts...")
joblib.dump(model,           "phish_model.pkl")
joblib.dump(scaler,          "phish_scaler.pkl")
joblib.dump(FEATURE_COLS,    "phish_features.pkl")
joblib.dump(TRUSTED_DOMAINS, "phish_trusted.pkl")
print("   phish_model.pkl")
print("   phish_scaler.pkl")
print("   phish_features.pkl")
print("   phish_trusted.pkl")

# ── 6. SMOKE TEST ─────────────────────────────────────────────────────────────
print("\n--- Smoke Test ---")

def predict_url(url):
    if is_trusted(url):
        return {"verdict": "SAFE", "confidence": 0.0, "reason": "Trusted whitelist"}
    feats = pd.DataFrame([extract_features(url)], columns=FEATURE_COLS)
    feats_s = scaler.transform(feats)
    prob = float(model.predict_proba(feats_s)[0][1])
    if prob >= 0.80:
        verdict = "PHISHING"
    elif prob >= CONFIDENCE_THRESHOLD:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    return {"verdict": verdict, "confidence": round(prob, 4), "reason": f"ML score {prob:.0%}"}

demo_urls = [
    "https://google.com",
    "https://www.youtube.com",
    "https://paypal.com",
    "https://chatgpt.com",
    "https://github.com",
    "http://paypa1-secure-login.xyz/verify/account",
    "http://192.168.1.1/banking/login",
    "http://secure-update-account.tk/confirm",
    "http://microsoft-login-verify.xyz/signin",
]

print(f"\n{'URL':<48} {'VERDICT':<12} {'CONF':>6}  REASON")
print("-" * 90)
for u in demo_urls:
    r = predict_url(u)
    print(f"{u:<48} {r['verdict']:<12} {r['confidence']:>6.2f}  {r['reason']}")

print("\n✅ Done. Run: railway up\n")