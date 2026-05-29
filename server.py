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

# Load model artifacts
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model = joblib.load(os.path.join(BASE_DIR, "phish_model.pkl"))
scaler = joblib.load(os.path.join(BASE_DIR, "phish_scaler.pkl"))
feature_names = joblib.load(os.path.join(BASE_DIR, "phish_features.pkl"))

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

class URLPayload(BaseModel):
    url: str

URL_MAX_LENGTH = 2048

def get_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

SUSPICIOUS_KEYWORDS = [
    "secure", "login", "verify", "update", "account", "banking",
    "confirm", "password", "signin", "webscr", "paypal", "ebay",
    "amazon", "microsoft", "apple"
]

BRAND_NAMES = [
    "google", "amazon", "netflix", "paypal", "microsoft",
    "linkedin", "apple", "facebook", "instagram", "twitter"
]

def extract_features(url: str) -> list:
    # Normalise exactly as train_model.py does: lowercase, strip scheme for domain parse
    url_lower = str(url).strip().lower()
    domain = re.sub(r"https?://", "", url_lower).split("/")[0].split("?")[0].split("#")[0]
    parts = domain.split(".")
    tld = "." + parts[-1] if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) > 1 else domain
    path = url_lower[len(domain):]
    subdomain_depth = max(0, len(parts) - 2)

    # Feature order MUST match phish_features.pkl exactly:
    # ['url_length', 'domain_length', 'path_length', 'subdomain_depth',
    #  'dot_count', 'hyphen_count', 'at_symbol', 'double_slash',
    #  'digit_count', 'special_char_count', 'url_entropy',
    #  'suspicious_tld', 'keyword_in_url', 'brand_in_subdomain', 'is_ip_address']
    features = [
        len(url_lower),                                                                         # 0: url_length
        len(domain),                                                                            # 1: domain_length
        len(path),                                                                              # 2: path_length
        subdomain_depth,                                                                        # 3: subdomain_depth
        url_lower.count("."),                                                                   # 4: dot_count
        domain.count("-"),                                                                      # 5: hyphen_count — domain only, matches training
        int("@" in url_lower),                                                                  # 6: at_symbol
        int("//" in url_lower[7:]),                                                             # 7: double_slash — skip scheme //, matches training
        sum(c.isdigit() for c in domain),                                                       # 8: digit_count — domain only, matches training
        len(re.findall(r"[%&=\?\+\#\!\*]", url_lower)),                                        # 9: special_char_count — matches training regex
        round(get_entropy(url_lower), 4),                                                       # 10: url_entropy — full URL, matches training
        int(tld in SUSPICIOUS_TLDS),                                                            # 11: suspicious_tld
        int(any(k in url_lower for k in SUSPICIOUS_KEYWORDS)),                                  # 12: keyword_in_url — full keyword list, matches training
        int(any(b in domain and b not in sld for b in BRAND_NAMES)),                            # 13: brand_in_subdomain — matches training logic
        int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", domain))),                     # 14: is_ip_address — matches training fullmatch
    ]
    return features

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
    """
    Returns (score_bonus, flag_string).
    Domains under 30 days old:  +25 bonus, flagged as high risk.
    Domains 30-90 days old:     +10 bonus, flagged as moderate risk.
    Domains over 90 days or lookup failure: 0 bonus, no flag.
    """
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
    try:
        parsed = urlparse(normalized_url)
        domain = parsed.netloc or parsed.path
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Malformed URL") from exc

    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP(S) URLs are supported")
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # ML layer
    features = extract_features(normalized_url)
    features_scaled = scaler.transform([features])
    ml_prob = float(model.predict_proba(features_scaled)[0][1])
    ml_score = round(ml_prob * 100)

    # Heuristic layer
    heuristic_bonus, flags = heuristic_layer(normalized_url, domain)

    # WHOIS domain age layer
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
