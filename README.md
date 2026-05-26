# PhishShield AI

> Real-time phishing detection Chrome extension powered by a Random Forest classifier trained on 10,000 live threat URLs.

![Version](https://img.shields.io/badge/version-2.0.0-blue) ![Accuracy](https://img.shields.io/badge/accuracy-99%25-brightgreen) ![F1](https://img.shields.io/badge/F1%20score-0.987-brightgreen) ![Manifest](https://img.shields.io/badge/Manifest-V3-orange)

---

## What it does

PhishShield AI runs silently in your browser and evaluates every page you visit in real time. It combines a machine learning model with a heuristic layer to detect phishing attempts before you interact with them.

When a threat is detected, it displays a full-width warning banner with the threat score and specific flags explaining why the page was flagged.

---

## How it works

```
Browser page load
      │
      ▼
content.js (MutationObserver, debounced)
  └─ Extracts: domain, password fields, payment fields, form count
      │
      ▼
background.js (Service Worker)
  ├─ Local heuristic: HTTP + password field → +35 risk
  └─ POST /api/v1/analyze-domain
          │
          ▼
    FastAPI backend (server.py)
      ├─ ML layer: Random Forest (15 URL features) → probability score
      └─ Heuristic layer: typosquatting, TLD risk, keyword detection
          │
          ▼
    Combined risk score (0–100)
      │
      ├─ Score ≥ 40 → Warning banner injected into page
      └─ Score stored → Popup displays ring + flags
```

---

## ML model

| Metric | Score |
|---|---|
| Accuracy | 99% |
| Precision (phishing) | 0.99 |
| Recall (phishing) | 0.99 |
| F1 score | 0.99 |
| 5-fold CV F1 | 0.987 ± 0.010 |
| Training samples | 10,000 (5,000 phishing + 5,000 legit) |
| Test samples | 2,000 |
| False positives | 5 / 1,000 |
| False negatives | 11 / 1,000 |

### Training data sources
- Phishing: [PhishTank](https://phishtank.org/) verified live feed
- Legitimate: [Tranco](https://tranco-list.eu/) top-1M domains

### Feature engineering (15 features)

| Feature | Why it matters |
|---|---|
| `url_length` | Phishing URLs are longer on average |
| `path_length` | Long paths used to obfuscate destination |
| `domain_length` | Suspicious domains tend to be longer |
| `subdomain_depth` | Chained subdomains are a common evasion tactic |
| `dot_count` | More dots = more subdomain nesting |
| `hyphen_count` | Hyphens used to mimic brands (pay-pal.com) |
| `at_symbol` | `@` in URL redirects to different host |
| `double_slash` | Path-based redirect obfuscation |
| `digit_count` | Digit-heavy domains are rarely legitimate |
| `special_char_count` | Encoded/special chars signal obfuscation |
| `url_entropy` | High Shannon entropy = randomised/generated URL |
| `suspicious_tld` | .tk, .ml, .xyz and similar high-abuse TLDs |
| `keyword_in_url` | login, verify, secure, update etc. |
| `brand_in_subdomain` | paypal.evil.com pattern |
| `is_ip_address` | Raw IP instead of domain = strong signal |

---

## Architecture

```
phishshield-extension/
├── manifest.json          # Chrome Manifest V3
├── content.js             # DOM scanner (debounced MutationObserver + cache)
├── background.js          # Service worker — routes to backend, local fallback
├── popup/
│   ├── popup.html         # Extension popup UI
│   ├── popup.css          # Styles (threat ring, severity states)
│   └── popup.js           # Drives ring animation + color tiers
├── test_env.html          # Local test page with password field
├── server.py              # FastAPI backend — ML + heuristic engine
├── train_model.py         # One-time model training script
├── phish_model.pkl        # Trained Random Forest (generated)
├── phish_scaler.pkl       # StandardScaler (generated)
└── phish_features.pkl     # Feature column order (generated)
```

---

## Setup

### 1. Install Python dependencies

```bash
pip install fastapi uvicorn scikit-learn pandas numpy requests joblib python-levenshtein flask-cloudflared
```

### 2. Train the model (one time only)

```bash
python train_model.py
```

Downloads ~10,000 URLs from PhishTank and Tranco, trains the Random Forest, and saves the model artifacts. Takes about 2 minutes. Outputs accuracy report to `phish_report.txt`.

### 3. Start the backend

```bash
python server.py
```

Prints a live Cloudflare tunnel URL. Copy it.

### 4. Set the API endpoint

In `background.js`, update:

```js
const CONFIG = {
  apiEndpoint: "https://your-tunnel-url.trycloudflare.com/api/v1/analyze-domain"
};
```

### 5. Load the extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `phishshield-extension` folder

---

## API

### `POST /api/v1/analyze-domain`

Request:
```json
{ "domain": "paypa1-secure-login.net" }
```

Response:
```json
{
  "status": "PROCESSED",
  "backendRiskScore": 87,
  "backendFlags": [
    "ML model flagged this URL (High confidence, 82.0% phishing probability)",
    "Typosquatting detected — closely matches 'PAYPAL'",
    "Suspicious keyword in domain: 'login'"
  ],
  "engineUsed": "ml+heuristic",
  "mlAvailable": true
}
```

### `GET /health`

```json
{ "status": "ok", "mlAvailable": true, "version": "2.0.0" }
```

---

## Tech stack

**Frontend:** Chrome Extension (Manifest V3), Vanilla JS, CSS  
**Backend:** Python, FastAPI, Uvicorn  
**ML:** scikit-learn (RandomForestClassifier), pandas, numpy  
**Deployment:** Cloudflare Tunnel  
**Data:** PhishTank, Tranco Top-1M  

---

## Design decisions

**Why Random Forest?** Interpretable, fast at inference, handles mixed feature types well, and doesn't require a GPU. For a browser extension backend where latency matters, it's the right tradeoff over deep learning.

**Why 15 features instead of raw text?** Feature engineering on URL structure generalises better than character-level models on unseen phishing patterns. The features capture structural intent (obfuscation, brand impersonation) rather than surface patterns.

**Why a heuristic layer on top of ML?** The ML model handles probabilistic scoring. The heuristic layer catches high-confidence explicit signals (typosquatting, IP addresses) with human-readable explanations — which is what users actually need to understand why a site was flagged.

**Why Manifest V3?** MV2 is deprecated. Building on V3 from the start means the extension won't break as Chrome phases out MV2 support.

---

## Known limitations

- The Cloudflare tunnel URL changes on every server restart — you need to update `CONFIG.apiEndpoint` in `background.js` each time. A permanent deployment would fix this.
- The ML model was trained on URL structure only. A page that looks legitimate by URL but has deceptive content would not be caught by the ML layer (the heuristic DOM scanner partially compensates for this).
- `content.js` cache TTL is 30 seconds — pages that dynamically inject password fields after the cache window could be missed on fast revisits.

---

## Roadmap

- [ ] Permanent backend deployment (Railway / Render)
- [ ] VirusTotal API integration for multi-engine URL reputation
- [ ] Screenshot-based visual similarity detection (CNN)
- [ ] Firefox port (WebExtensions API compatible)
- [ ] User whitelist / false-positive reporting
