"""
PhishShield AI - FastAPI Backend v5
ML + Heuristic + Trusted Whitelist phishing detection engine
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import os
import re
import math
import Levenshtein
from urllib.parse import urlparse
import requests
import io
import zipfile
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

app = FastAPI()

DEFAULT_ALLOWED_ORIGINS = ["http://localhost", "http://127.0.0.1"]
allowed_origins = os.getenv("PHISHSHIELD_ALLOWED_ORIGINS")
if allowed_origins:
    cors_origins = [o.strip() for o in allowed_origins.split(",") if o.strip()]
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

# ── CONSTANTS ─────────────────────────────────────────────────────────────────
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
    "confirm", "password", "signin", "webscr"
]

BRAND_NAMES = [
    "google", "amazon", "netflix", "paypal", "microsoft",
    "linkedin", "apple", "facebook", "instagram", "twitter",
    "bankofamerica", "chase", "wellsfargo", "dropbox", "github",
]

FEATURE_COLS = [
    'url_length', 'domain_length', 'path_length', 'subdomain_depth',
    'dot_count', 'hyphen_count', 'at_symbol', 'double_slash',
    'digit_count', 'special_char_count', 'url_entropy',
    'suspicious_tld', 'keyword_in_url', 'brand_in_subdomain', 'is_ip_address'
]

HEADERS = {"User-Agent": "Mozilla/5.0 (PhishShield-Research/5.0)"}
CONFIDENCE_THRESHOLD = 0.60

# ── TRUSTED WHITELIST ─────────────────────────────────────────────────────────
DEFAULT_TRUSTED = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "bing.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazonaws.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "paypal.com", "paypal.me",
    "twitter.com", "x.com", "linkedin.com", "reddit.com",
    "youtube.com", "tiktok.com", "snapchat.com",
    "slack.com", "discord.com", "zoom.us",
    "dropbox.com", "github.com", "gitlab.com",
    "netflix.com", "spotify.com",
    "cloudflare.com", "wikipedia.org",
    "chatgpt.com", "openai.com", "anthropic.com", "claude.ai",
    "railway.app", "vercel.app", "netlify.app",
}

# Load whitelist from pkl if available, always merge with DEFAULT_TRUSTED
try:
    TRUSTED_DOMAINS = joblib.load(os.path.join(BASE_DIR, "phish_trusted.pkl"))
    TRUSTED_DOMAINS.update(DEFAULT_TRUSTED)  # always apply latest defaults
    print(f"[PhishShield] Loaded+merged whitelist: {len(TRUSTED_DOMAINS)} domains")
except Exception:
    TRUSTED_DOMAINS = DEFAULT_TRUSTED
    print(f"[PhishShield] Using default whitelist: {len(TRUSTED_DOMAINS)} domains")



# TLD suffixes that are inherently institutional/safe — any domain ending in
# these is treated as trusted without needing an explicit whitelist entry.
SAFE_TLD_SUFFIXES = {
    ".gov", ".gov.in", ".gov.uk", ".gov.au", ".gov.us",
    ".edu", ".edu.in", ".ac.in", ".ac.uk", ".ac.nz",
    ".mil",
    ".nic.in",
}

def is_trusted(url: str) -> bool:
    """Return True if domain is whitelisted OR ends with an institutional TLD."""
    url = str(url).strip().lower()
    domain = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]

    # Institutional TLD check (e.g. anything.gov.in, anything.ac.uk)
    for suffix in SAFE_TLD_SUFFIXES:
        if domain.endswith(suffix):
            return True

    # Whitelist: check domain and every parent level
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in TRUSTED_DOMAINS:
            return True
    return False


# ── FEATURE EXTRACTION ────────────────────────────────────────────────────────
def get_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


def strip_www(url: str) -> str:
    return re.sub(r"^(https?://)www\.", r"\1", url)


def extract_features_dict(url: str) -> dict:
    url = str(url).strip().lower()
    url = strip_www(url)
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
        "brand_in_subdomain": int(any(b in domain and b != sld for b in BRAND_NAMES)),
        "is_ip_address":      int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", domain))),
    }


def extract_features(url: str) -> list:
    d = extract_features_dict(url)
    return [d[f] for f in FEATURE_COLS]


# ── TRAINING ──────────────────────────────────────────────────────────────────
def fetch_phishing_urls() -> list:
    try:
        print("[PhishShield] Fetching OpenPhish...")
        r = requests.get("https://openphish.com/feed.txt", headers=HEADERS, timeout=20)
        r.raise_for_status()
        urls = [u.strip() for u in r.text.splitlines() if u.strip().startswith("http")]
        if len(urls) >= 100:
            print(f"[PhishShield] OpenPhish: {len(urls)} URLs")
            return urls[:5000]
    except Exception as e:
        print(f"[PhishShield] OpenPhish failed: {e}")
    return []


def fetch_legit_urls(n: int) -> list:
    try:
        print("[PhishShield] Fetching Tranco...")
        r = requests.get("https://tranco-list.eu/top-1m.csv.zip", headers=HEADERS, timeout=60)
        r.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            with z.open(z.namelist()[0]) as f:
                import pandas as pd
                df = pd.read_csv(f, header=None, names=["rank", "domain"])
        domains = df["domain"].dropna().tolist()
        selected = domains[:n//3] + domains[1000:1000+n//3] + domains[5000:5000+n//3]
        urls = ["https://" + d + "/" for d in selected[:n]]
        print(f"[PhishShield] Tranco: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"[PhishShield] Tranco failed: {e}")
    return []


def train_model():
    print("[PhishShield] Starting model training...")
    import pandas as pd

    phish_urls = fetch_phishing_urls()
    if len(phish_urls) < 100:
        print(f"[PhishShield] Not enough phishing data: {len(phish_urls)}")
        return None, None

    legit_urls = fetch_legit_urls(len(phish_urls))
    if len(legit_urls) < 100:
        print(f"[PhishShield] Not enough legit data: {len(legit_urls)}")
        return None, None

    n = min(len(phish_urls), len(legit_urls))
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
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=300, max_depth=20, min_samples_split=5,
        min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=-1
    )
    model.fit(X_train_s, y_train)
    acc = model.score(X_test_s, y_test)
    print(f"[PhishShield] Accuracy: {acc:.3f}")

    joblib.dump(model,        os.path.join(BASE_DIR, "phish_model.pkl"))
    joblib.dump(scaler,       os.path.join(BASE_DIR, "phish_scaler.pkl"))
    joblib.dump(FEATURE_COLS, os.path.join(BASE_DIR, "phish_features.pkl"))
    print("[PhishShield] Model saved.")
    return model, scaler


def validate_model(model, scaler) -> int:
    """Returns google.com ML score — should be 0 after whitelist bypass."""
    test = extract_features_dict("https://google.com/")
    test_vals = [test[f] for f in FEATURE_COLS]
    scaled = scaler.transform([test_vals])
    score = round(float(model.predict_proba(scaled)[0][1]) * 100)
    print(f"[PhishShield] ML validation — google.com raw ML: {score}%")
    return score


# ── LOAD OR TRAIN MODEL ───────────────────────────────────────────────────────
try:
    model = joblib.load(os.path.join(BASE_DIR, "phish_model.pkl"))
    scaler = joblib.load(os.path.join(BASE_DIR, "phish_scaler.pkl"))
    feature_names = joblib.load(os.path.join(BASE_DIR, "phish_features.pkl"))

    raw_score = validate_model(model, scaler)
    # Note: raw ML score for google.com may be nonzero but whitelist will override it
    # Only retrain if raw score is absurdly high (>50%) meaning model is totally broken
    if raw_score > 50:
        print("[PhishShield] Model badly miscalibrated — retraining...")
        model, scaler = train_model()
        if model is None:
            raise RuntimeError("Training failed")
    else:
        print("[PhishShield] Model OK.")

except Exception as e:
    print(f"[PhishShield] Startup error: {e} — training fresh model...")
    model, scaler = train_model()


# ── API ───────────────────────────────────────────────────────────────────────
class URLPayload(BaseModel):
    url: str

URL_MAX_LENGTH = 2048


def heuristic_layer(url: str, domain: str) -> tuple[int, list[str]]:
    bonus = 0
    flags = []
    url_lower = url.lower()
    domain = domain.lower()
    domain_parts = domain.split(".")
    domain_clean = re.sub(r"^www\.", "", domain).split(".")[0]
    sld = domain_parts[-2] if len(domain_parts) >= 2 else domain_clean
    parsed_tld = "." + domain_parts[-1] if "." in domain else ""

    # 1. Typosquat
    for brand in PROTECTED_BRANDS:
        dist = Levenshtein.distance(domain_clean, brand)
        if 1 <= dist <= 2:
            bonus += 30
            flags.append(f"Typosquatting: '{domain_clean}' looks like '{brand}' (edit distance {dist})")
            break

    # 2. Suspicious TLD
    if parsed_tld in SUSPICIOUS_TLDS:
        bonus += 15
        flags.append(f"High-risk free TLD: '{parsed_tld}' — frequently abused for phishing")

    # 3. ALL matching suspicious keywords (no break — report all)
    matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_kws:
        bonus += min(len(matched_kws) * 5, 15)
        flags.append(f"Phishing keyword(s) in URL: {', '.join(matched_kws)}")

    # 4. IP address as domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", re.sub(r"^www\.", "", domain)):
        bonus += 20
        flags.append("IP address used as domain — legitimate sites use domain names")

    # 5. Excessive hyphens
    if domain.count("-") >= 3:
        bonus += 10
        flags.append(f"Excessive hyphens in domain ({domain.count('-')}) — common obfuscation")

    # 6. Brand name in subdomain (not the actual brand domain)
    for brand in BRAND_NAMES:
        if brand in domain and brand != sld:
            bonus += 20
            flags.append(f"Brand '{brand}' in subdomain — impersonation pattern")
            break

    # 7. @ in URL
    if "@" in url:
        bonus += 25
        flags.append("'@' in URL — browser ignores everything before it (redirect trick)")

    return min(bonus, 45), flags


def ml_flags(features_dict: dict, ml_score: int) -> list[str]:
    """Human-readable explanations for why the ML model fired."""
    flags = []
    if ml_score < 40:
        return flags
    if features_dict.get("is_ip_address"):
        flags.append("ML: IP address domain detected")
    if features_dict.get("brand_in_subdomain"):
        flags.append("ML: Known brand found in subdomain (not in registered domain)")
    if features_dict.get("suspicious_tld"):
        flags.append("ML: TLD associated with phishing campaigns")
    if features_dict.get("keyword_in_url"):
        flags.append("ML: URL contains terms common in credential-phishing pages")
    if features_dict.get("subdomain_depth", 0) >= 3:
        flags.append(f"ML: Deep subdomain nesting (depth {features_dict['subdomain_depth']})")
    if features_dict.get("url_length", 0) > 100:
        flags.append(f"ML: Abnormally long URL ({features_dict['url_length']} chars)")
    if features_dict.get("hyphen_count", 0) >= 3:
        flags.append(f"ML: Many hyphens in domain ({features_dict['hyphen_count']})")
    if features_dict.get("at_symbol"):
        flags.append("ML: '@' symbol present in URL")
    if features_dict.get("digit_count", 0) >= 5:
        flags.append(f"ML: High digit count in domain ({features_dict['digit_count']})")
    if features_dict.get("url_entropy", 0) > 4.2:
        flags.append(f"ML: High URL randomness/entropy ({features_dict['url_entropy']:.2f})")
    if not flags and ml_score >= 60:
        flags.append(f"ML: Combination of URL features matches phishing patterns (score {ml_score}%)")
    return flags


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

    # ── WHITELIST CHECK — bypass ML entirely for trusted domains ──────────────
    if is_trusted(normalized_url):
        return {
            "status": "SAFE",
            "score": 0,
            "ml_score": 0,
            "heuristic_bonus": 0,
            "age_bonus": 0,
            "flags": [],
            "domain": domain,
            "whitelist": True
        }

    # ── ML LAYER ──────────────────────────────────────────────────────────────
    features_dict = extract_features_dict(normalized_url)
    features_list = [features_dict[f] for f in FEATURE_COLS]
    features_scaled = scaler.transform([features_list])
    ml_prob = float(model.predict_proba(features_scaled)[0][1])
    ml_score = round(ml_prob * 100)

    # ── HEURISTIC LAYER ───────────────────────────────────────────────────────
    heuristic_bonus, h_flags = heuristic_layer(normalized_url, domain)

    final_score = min(ml_score + heuristic_bonus, 100)

    if final_score >= 70:
        status = "DANGER"
    elif final_score >= 40:
        status = "MEDIUM"
    else:
        status = "SAFE"

    # Combine heuristic + ML-derived flags; suppress all flags on clean SAFE
    if status == "SAFE":
        all_flags = []
    else:
        all_flags = h_flags + ml_flags(features_dict, ml_score)
        # Deduplicate while preserving order
        seen = set()
        all_flags = [f for f in all_flags if not (f in seen or seen.add(f))]

    return {
        "status": status,
        "score": final_score,
        "ml_score": ml_score,
        "heuristic_bonus": heuristic_bonus,
        "flags": all_flags,
        "domain": domain,
        "whitelist": False,
    }