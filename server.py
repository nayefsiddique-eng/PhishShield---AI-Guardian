"""
PhishShield AI - FastAPI Backend
ML + Heuristic dual-layer phishing detection engine
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import os
import re
import math
import Levenshtein
from urllib.parse import urlparse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
    ".ml", ".cf", ".ga", ".tk", ".pw", ".cc", ".su"
}

class URLPayload(BaseModel):
    url: str

def get_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

def extract_features(url: str) -> list:
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc or parsed.path
        path = parsed.path or ""
        full = url
    except Exception:
        domain = url
        path = ""
        full = url

    domain_clean = domain.replace("www.", "")
    parts = domain_clean.split(".")
    subdomain_depth = max(0, len(parts) - 2)
    tld = "." + parts[-1] if len(parts) > 1 else ""

    features = [
        len(full),
        len(domain),
        subdomain_depth,
        full.count("."),
        full.count("-"),
        full.count("@"),
        full.count("//"),
        full.count("https"),
        int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_clean))),
        get_entropy(domain_clean),
        int(any(kw in full.lower() for kw in ["secure", "login", "verify", "update", "signin", "account", "banking"])),
        int(tld in SUSPICIOUS_TLDS),
        len(path),
        path.count("/"),
        int(bool(re.search(r"\d{4,}", domain_clean))),
    ]
    return features

def heuristic_layer(url: str, domain: str) -> tuple[int, list[str]]:
    bonus = 0
    flags = []
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

    for kw in ["secure", "login", "verify", "update", "signin", "account", "banking"]:
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

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"service": "PhishShield AI", "version": "1.0.0", "status": "running"}

@app.post("/predict")
async def predict(payload: URLPayload):
    url = payload.url.strip()

    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc or parsed.path
    except Exception:
        domain = url

    features = extract_features(url)
    features_scaled = scaler.transform([features])
    ml_prob = float(model.predict_proba(features_scaled)[0][1])
    ml_score = round(ml_prob * 100)

    heuristic_bonus, flags = heuristic_layer(url, domain)
    final_score = min(ml_score + heuristic_bonus, 100)

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
        "flags": flags,
        "domain": domain
    }