"""
PhishShield AI - FastAPI Backend
ML + Heuristic + WHOIS triple-layer phishing detection engine
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import os
import re
import math
import Levenshtein
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
import io
import zipfile
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

app = FastAPI()

DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost",
    "http://127.0.0.1",
]
allowed_origins = os.getenv("PHISHSHIELD_ALLOWED_ORIGINS")
if allowed_origins:
    cors_origins = [origin.strip() for origin in allowed_origins.split(",") if origin.strip()]
else:
    cors_origins = DEFAULT_ALLOWED_ORIGINS

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=r"^chrome-extension://[a-z]{32}$",
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROTECTED_BRANDS = [
    "google", "amazon", "netflix", "paypal", "microsoft",
    "linkedin", "apple", "facebook", "instagram", "twitter",
    "bankofamerica", "chase", "wellsfargo", "dropbox", "github"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".gq",
    ".ml", ".cf", ".ga", ".tk", ".pw", ".cc", ".su",
    ".win", ".bid", ".download", ".racing", ".accountant"
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

FEATURE_COLS = [
    'url_length', 'domain_length', 'path_length', 'subdomain_depth',
    'dot_count', 'hyphen_count', 'at_symbol', 'double_slash',
    'digit_count', 'special_char_count', 'url_entropy',
    'suspicious_tld', 'keyword_in_url', 'brand_in_subdomain', 'is_ip_address'
]

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishShield-Research/2.0)"}

def get_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

def extract_features_dict(url: str) -> dict:
    url = str(url).strip().lower()
    url = re.sub(r"^(https?://)www\.", r"\1", url)
    domain = re.sub(r"https?://", "", url).split("/")[0].split("?")[0].split("#")[0]
    parts = domain.split(".")
    tld = "." + parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else domain
    path = url[len(domain):]
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
        "url_entropy":        round(get_entropy(url), 4),
        "suspicious_tld":     int(tld in SUSPICIOUS_TLDS),
        "keyword_in_url":     int(any(k in url for k in SUSPICIOUS_KEYWORDS)),
        "brand_in_subdomain": int(any(b in domain and b not in sld for b in BRAND_NAMES)),
        "is_ip_address":      int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", domain))),
    }

def train_model():
    """Train model fresh on Railway using live data sources."""
    print("[PhishShield] Training model on Railway...")

    # Fetch phishing URLs
    phish_urls = []
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=HEADERS, timeout=30)
        lines = [l for l in r.text.splitlines() if not l.startswith("#") and l.strip()]
        import pandas as pd
        df = pd.read_csv(io.StringIO("\n".join(lines)), on_bad_lines="skip")
        df.columns = [str(i) for i in range(len(df.columns))]
        phish_urls = df["2"].dropna().tolist()[:5000]
        print(f"[PhishShield] Phishing URLs: {len(phish_urls)}")
    except Exception as e:
        print(f"[PhishShield] URLhaus failed: {e}")

    # Fetch legit URLs
    legit_urls = []
    try:
        r2 = requests.get("https://tranco-list.eu/top-1m.csv.zip", headers=HEADERS, timeout=60)
        with zipfile.ZipFile(io.BytesIO(r2.content)) as z:
            with z.open(z.namelist()[0]) as f:
                import pandas as pd
                df2 = pd.read_csv(f, header=None, names=["rank", "domain"])
        legit_urls = ["https://" + d for d in df2["domain"].dropna().tolist()[:5000]]
        print(f"[PhishShield] Legit URLs: {len(legit_urls)}")
    except Exception as e:
        print(f"[PhishShield] Tranco failed: {e}")

    if len(phish_urls) < 100 or len(legit_urls) < 100:
        print("[PhishShield] Not enough data — using fallback pkl files")
        return None, None

    import pandas as pd
    n = min(len(phish_urls), len(legit_urls), 5000)
    rows = []
    for url in phish_urls[:n]:
        try: rows.append({**extract_features_dict(url), "label": 1})
        except: pass
    for url in legit_urls[:n]:
        try: rows.append({**extract_features_dict(url), "label": 0})
        except: pass

    df = pd.DataFrame(rows).dropna()
    print(f"[PhishShield] Dataset: {len(df)} samples")

    X = df[FEATURE_COLS]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)

    model = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_split=5,
        class_weight="balanced", random_state=42, n_jobs=-1
    )
    model.fit(X_train_s, y_train)

    X_test_s = scaler.transform(X_test)
    acc = model.score(X_test_s, y_test)
    print(f"[PhishShield] Model accuracy: {acc:.3f}")

    joblib.dump(model,        os.path.join(BASE_DIR, "phish_model.pkl"))
    joblib.dump(scaler,       os.path.join(BASE_DIR, "phish_scaler.pkl"))
    joblib.dump(FEATURE_COLS, os.path.join(BASE_DIR, "phish_features.pkl"))
    print("[PhishShield] Model saved.")
    return model, scaler

# ── Load or train model ────────────────────────────────────────────────────────
try:
    model = joblib.load(os.path.join(BASE_DIR, "phish_model.pkl"))
    scaler = joblib.load(os.path.join(BASE_DIR, "phish_scaler.pkl"))
    feature_names = joblib.load(os.path.join(BASE_DIR, "phish_features.pkl"))

    # Validate model works correctly on a known safe URL
    test_features = extract_features_dict("https://google.com/")
    test_vals = [test_features[f] for f in FEATURE_COLS]
    test_scaled = scaler.transform([test_vals])
    test_score = round(float(model.predict_proba(test_scaled)[0][1]) * 100)
    print(f"[PhishShield] Model validation — google.com score: {test_score}%")

    if test_score > 20:
        print("[PhishShield] Model failed validation — retraining...")
        model, scaler = train_model()
        if model is None:
            raise RuntimeError("Retraining failed")
    else:
        print("[PhishShield] Model validated successfully.")

except Exception as e:
    print(f"[PhishShield] Model load failed: {e} — training fresh...")
    model, scaler = train_model()

class URLPayload(BaseModel):
    url: str

URL_MAX_LENGTH = 2048

def strip_www(url: str) -> str:
    return re.sub(r"^(https?://)www\.", r"\1", url)

def extract_features(url: str) -> list:
    d = extract_features_dict(url)
    return [d[f] for f in FEATURE_COLS]

def heuristic_layer(url: str, domain: str) -> tuple[int, list[str]]:
    bonus = 0
    flags = []
    domain = domain.lower()
    domain_clean = domain.replace("www.", "").split(".")[0]
    parsed_tld = "." + domain.split(".")[-1] if "." in domain else ""

    for brand in PROTECTED_BRANDS:
        dist = Levenshtein.distance(domain_clean, brand)
        if 1 <= dist <= 2:
            bonus += 30
            flags.append(f"Typosquatting detected — close match to {brand.upper()}")
            break

    if parsed_tld in SUSPICIOUS_TLDS:
        bonus += 15
        flags.append(f"Suspicious TLD: {parsed_tld}")

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url.lower():
            bonus += 10
            flags.append(f"Suspicious keyword: {kw}")
            break

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.replace("www.", "")):
        bonus += 20
        flags.append("IP address used as domain")

    if domain.count("-") >= 3:
        bonus += 10
        flags.append("Excessive hyphens in domain")

    return min(bonus, 40), flags

def domain_age_check(domain: str) -> tuple[int, str | None]:
    try:
        parts = domain.replace("www.", "").split(".")
        registrable = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        w = whois.whois(registrable)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return 0, None
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation_date).days
        if age_days < 30:
            return 25, f"Domain registered {age_days} days ago — extremely new (high risk)"
        elif age_days < 90:
            return 10, f"Domain registered {age_days} days ago — recently created (moderate risk)"
        else:
            return 0, None
    except Exception:
        return 0, None

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"service": "PhishShield AI", "version": "1.0.0", "status": "running"}

@app.post("/predict")
async def predict(payload: URLPayload):
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if len(url) > URL_MAX_LENGTH:
        raise HTTPException(status_code=400, detail="URL too long")

    lower_url = url.lower()
    if lower_url.startswith(("javascript:", "data:", "file:")):
        raise HTTPException(status_code=400, detail="Unsupported URL scheme")

    normalized_url = url if lower_url.startswith(("http://", "https://")) else "http://" + url
    normalized_url = strip_www(normalized_url)

    try:
        parsed = urlparse(normalized_url)
        domain = parsed.netloc or parsed.path
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed URL") from exc

    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP(S) URLs are supported")
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    features = extract_features(normalized_url)
    features_scaled = scaler.transform([features])
    ml_prob = float(model.predict_proba(features_scaled)[0][1])
    ml_score = round(ml_prob * 100)

    heuristic_bonus, flags = heuristic_layer(normalized_url, domain)

    age_bonus, age_flag = domain_age_check(domain)
    if age_flag:
        flags.append(age_flag)

    final_score = min(ml_score + heuristic_bonus + age_bonus, 100)

    if final_score >= 70:
        status = "DANGER"
    elif final_score >= 40:
        status = "MEDIUM"
    else:
        status = "SAFE"

    return {
        "status": status,
        "score": final_score,
        "ml_score": ml_score,
        "heuristic_bonus": heuristic_bonus,
        "age_bonus": age_bonus,
        "flags": flags,
        "domain": domain
    }