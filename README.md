<div align="center">

# 🛡️ PhishShield AI

### Real-time phishing detection powered by a triple-layer ML engine

[![Version](https://img.shields.io/badge/version-2.0.0-blue?style=for-the-badge)](https://github.com/nayefsiddique-eng/PhishShield---AI-Guardian)
[![Accuracy](https://img.shields.io/badge/accuracy-99%25-brightgreen?style=for-the-badge)](#ml-model-performance)
[![F1 Score](https://img.shields.io/badge/F1%20Score-0.987-brightgreen?style=for-the-badge)](#ml-model-performance)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-orange?style=for-the-badge)](#)
[![Deployed on Railway](https://img.shields.io/badge/deployed-Railway-blueviolet?style=for-the-badge)](https://phishshield-ai-guardian-production.up.railway.app)
[![License](https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge)](#)

**PhishShield AI** is a Chrome extension that silently evaluates every website you visit using a three-layer detection engine — machine learning, heuristic analysis, and live WHOIS intelligence — and alerts you before you interact with a phishing page.

[🔗 Live Backend](https://phishshield-ai-guardian-production.up.railway.app/docs) · [📦 Installation](#setup) · [📊 Model Performance](#ml-model-performance) · [🔌 API Reference](#api-reference)

</div>

---

## 📋 Table of Contents

- [How It Works](#how-it-works)
- [Detection Layers](#detection-layers)
- [ML Model Performance](#ml-model-performance)
- [Feature Engineering](#feature-engineering)
- [Project Architecture](#project-architecture)
- [API Reference](#api-reference)
- [Setup](#setup)
- [Tech Stack](#tech-stack)
- [Design Decisions](#design-decisions)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)

---

## How It Works

When you load a page, PhishShield AI extracts the URL, sends it to a permanently deployed FastAPI backend on Railway, and receives a threat score from 0–100 within seconds. Three independent detection layers run in sequence and their scores are combined into a final verdict.

```
Browser visits a page
│
▼
┌───────────────────────────────┐
│  content.js                   │
│  MutationObserver (1500ms     │
│  debounce + 30s domain cache) │
└──────────────┬────────────────┘
               │ domain extracted
               ▼
┌───────────────────────────────┐
│  background.js                │
│  Service Worker               │
│  Dedup guard + POST /predict  │
└──────────────┬────────────────┘
               │ HTTPS request
               ▼
┌─────────────────────────────────────────────────┐
│  FastAPI Backend  (Railway — always on)          │
│                                                  │
│  ┌─────────────────────────────────────────┐    │
│  │ Layer 1 — Random Forest ML              │    │
│  │ 15 URL features → phishing probability  │    │
│  └──────────────────┬──────────────────────┘    │
│                     │ ml_score (0–100)           │
│  ┌──────────────────▼──────────────────────┐    │
│  │ Layer 2 — Heuristic Engine              │    │
│  │ Typosquatting · TLD risk · Keywords     │    │
│  └──────────────────┬──────────────────────┘    │
│                     │ heuristic_bonus (0–40)     │
│  ┌──────────────────▼──────────────────────┐    │
│  │ Layer 3 — WHOIS Domain Age              │    │
│  │ Live registration date lookup           │    │
│  └──────────────────┬──────────────────────┘    │
│                     │ age_bonus (0–25)           │
│            final_score = min(sum, 100)           │
└──────────────────────┬──────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │  Score ≥ 70  → DANGER   │
          │  Score 40–69 → MEDIUM   │
          │  Score < 40  → SAFE     │
          └─────────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
Warning banner injected        Popup ring + flags
into the page DOM              updated in storage
```

---

## Detection Layers

### Layer 1 — Random Forest ML

A `RandomForestClassifier` (200 trees) trained on 10,000 URLs from PhishTank and Tranco. Extracts 15 structural URL features and outputs a phishing probability score scaled to 0–100.

| Training Data | Count |
|---|---|
| Phishing URLs (PhishTank verified feed) | 5,000 |
| Legitimate domains (Tranco Top-1M) | 5,000 |
| **Total** | **10,000** |

### Layer 2 — Heuristic Engine

Rule-based checks that augment the ML score with explicit signals. Each rule fires independently and contributes a bonus capped at +40 total.

| Rule | Trigger | Bonus |
|---|---|---|
| Typosquatting | Levenshtein distance 1–2 from a protected brand | +30 |
| Suspicious TLD | .xyz, .tk, .ml, .cf, .ga, .gq, .pw, .cc, .su, .top, .click, .loan, .work | +15 |
| Phishing keyword | login, secure, verify, update, signin, account, banking in URL | +10 |
| IP-as-domain | Raw IPv4 address used instead of domain name | +20 |
| Excessive hyphens | 3 or more hyphens in the domain | +10 |

**Protected brands monitored for typosquatting:**

`google` · `amazon` · `netflix` · `paypal` · `microsoft` · `linkedin` · `apple` · `facebook` · `instagram` · `twitter` · `bankofamerica` · `chase` · `wellsfargo` · `dropbox` · `github`

### Layer 3 — WHOIS Domain Age

Live WHOIS lookup against the registrable domain on every request. The majority of phishing campaigns use freshly registered domains — this layer catches structurally clean URLs that the ML model and heuristics alone might score as safe.

| Domain Age | Bonus | Flag Message |
|---|---|---|
| < 30 days | +25 | "Domain registered N days ago — extremely new (high risk)" |
| 30 – 90 days | +10 | "Domain registered N days ago — recently created (moderate risk)" |
| > 90 days | 0 | No flag |
| Private / lookup failed | 0 | Fails silently — no false penalty |

---

## ML Model Performance

| Metric | Result |
|---|---|
| Accuracy | **99%** |
| Precision (phishing class) | 0.99 |
| Recall (phishing class) | 0.99 |
| F1 Score | **0.987** |
| 5-fold Cross-Validation F1 | 0.987 ± 0.010 |
| False Positives | 5 / 1,000 |
| False Negatives | 11 / 1,000 |
| Test set size | 2,000 URLs |
| Trees in forest | 200 |

---

## Feature Engineering

15 structural URL features were hand-engineered to capture attacker behaviour patterns rather than surface-level string matching.

| # | Feature | Signal |
|---|---|---|
| 1 | `url_length` | Phishing URLs are significantly longer on average |
| 2 | `domain_length` | Obfuscated domains tend to be longer |
| 3 | `subdomain_depth` | Chained subdomains used to bury the real domain |
| 4 | `dot_count` | More dots = deeper subdomain nesting |
| 5 | `hyphen_count` | Hyphens mimic brands: `pay-pal-secure.com` |
| 6 | `at_symbol` | `@` in URL silently redirects to a different host |
| 7 | `double_slash` | Path-based redirect obfuscation |
| 8 | `https_count` | Fake HTTPS strings embedded in path |
| 9 | `is_ip_address` | Raw IP instead of domain — strong phishing signal |
| 10 | `domain_entropy` | High Shannon entropy = randomly generated domain |
| 11 | `keyword_in_url` | login, verify, secure, update, banking etc. |
| 12 | `suspicious_tld` | High-abuse TLDs: .tk, .ml, .xyz, .cf, .ga |
| 13 | `path_length` | Long paths used to obscure the true destination |
| 14 | `path_depth` | Deep nesting signals redirect chains |
| 15 | `digit_sequence` | Long digit runs in domain are rarely legitimate |

---

## Project Architecture

```
phishshield-extension/
│
├── manifest.json          # Chrome Manifest V3 — permissions + service worker
├── content.js             # DOM scanner — MutationObserver (1500ms debounce, 30s cache)
├── background.js          # Service worker — dedup guard, Railway endpoint, .finally()
│
├── popup/
│   ├── popup.html         # Extension popup — clean semantic markup
│   ├── popup.css          # Full styles — ring animation, severity tiers, flag cards
│   └── popup.js           # Ring fill animation, color tiers, flag rendering
│
├── test_env.html          # Local test page with password field
│
├── server.py              # FastAPI backend — ML + heuristic + WHOIS engine
├── train_model.py         # One-time training script
│
├── phish_model.pkl        # Trained RandomForestClassifier (200 trees)
├── phish_scaler.pkl       # StandardScaler for feature normalisation
├── phish_features.pkl     # Feature column order for inference
│
├── requirements.txt       # Python dependencies (pinned versions)
├── railway.toml           # Railway deployment config + health check
└── .gitignore             # Excludes pycache, venv, logs, .DS_Store
```

---

## API Reference

**Base URL:** `https://phishshield-ai-guardian-production.up.railway.app`

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Service info and version |
| `/health` | GET | Railway health check — returns `{"status": "ok"}` |
| `/predict` | POST | Score a URL through all three detection layers |
| `/docs` | GET | Interactive Swagger UI for testing |

### `POST /predict`

**Request body:**

```json
{
  "url": "http://paypa1-secure-login.xyz"
}
```

**Response:**

```json
{
  "status": "DANGER",
  "score": 100,
  "ml_score": 97,
  "heuristic_bonus": 25,
  "age_bonus": 0,
  "flags": [
    "Suspicious TLD: .xyz",
    "Suspicious keyword: secure"
  ],
  "domain": "paypa1-secure-login.xyz"
}
```

**Status thresholds:**

| Score Range | Status | Meaning |
|---|---|---|
| 70 – 100 | `DANGER` | High confidence phishing — banner injected |
| 40 – 69 | `MEDIUM` | Suspicious — warning displayed |
| 0 – 39 | `SAFE` | Likely legitimate |

---

## Setup

### Prerequisites

- Python 3.10+
- Google Chrome
- Git

### 1. Clone the repository

```bash
git clone https://github.com/nayefsiddique-eng/PhishShield---AI-Guardian.git
cd PhishShield---AI-Guardian
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Train the model (one time only)

```bash
python train_model.py
```

Downloads ~10,000 URLs from PhishTank and Tranco, engineers features, trains the Random Forest, and saves `phish_model.pkl`, `phish_scaler.pkl`, `phish_features.pkl`. Takes approximately 2 minutes.

> **Note:** Pre-trained `.pkl` files are already committed to the repo — you only need to run this if you want to retrain from scratch.

### 4. Run the backend locally (optional)

The backend is permanently deployed on Railway and requires no local setup. To run locally:

```bash
uvicorn server:app --reload
```

### 5. Load the Chrome extension

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle, top right)
3. Click **Load unpacked**
4. Select the `PhishShield---AI-Guardian` folder
5. The extension icon appears in your toolbar — it's active immediately

---

## Tech Stack

| Layer | Technology |
|---|---|
| Chrome Extension | Manifest V3, Vanilla JS, CSS |
| Backend Framework | Python, FastAPI, Uvicorn |
| ML Model | scikit-learn `RandomForestClassifier` |
| Feature Processing | numpy, StandardScaler |
| Typosquatting Detection | python-Levenshtein |
| Domain Intelligence | python-whois |
| Deployment | Railway (always-on, auto-deploy from GitHub) |
| Training Data | PhishTank (phishing), Tranco Top-1M (legitimate) |

---

## Design Decisions

**Why Random Forest over deep learning?**
Inference is microseconds vs hundreds of milliseconds for a neural net. For a browser extension where every millisecond of latency is felt by the user, this tradeoff is clear. Random Forest is also highly interpretable — each feature's contribution to the score can be explained directly, which matters both for user trust and for interview questions.

**Why 15 engineered features instead of raw URL text?**
Character-level models (n-grams, transformers) memorise surface patterns from training data. Structural feature engineering captures *why* a URL is suspicious — obfuscation depth, brand impersonation pattern, TLD abuse — which generalises to unseen phishing campaigns that use new domain names.

**Why a separate heuristic layer on top of ML?**
The ML model outputs a probability. The heuristic layer outputs a human-readable reason. Users don't trust scores they can't interpret. The flags panel tells the user *exactly* what was wrong — typosquatting against PayPal, suspicious TLD, keyword in URL — which is both more trustworthy and more educational.

**Why WHOIS domain age?**
Phishing infrastructure has a characteristic lifecycle: domains are registered, used for an attack campaign, and abandoned within days or weeks. A domain registered 3 days ago that scores 55 on ML+heuristics is almost certainly more dangerous than a domain registered 5 years ago that scores 55. Age is a strong contextual signal that URL structure alone cannot capture.

**Why Manifest V3?**
Chrome is actively deprecating MV2. Building on V3 from the start means the extension works today and won't break as MV2 is phased out. The `return true` in the message listener is a known V3 gotcha for async responses — already handled correctly.

**Why commit `.pkl` files to GitHub?**
The alternative is re-training the model on every Railway deployment, which adds ~5 minutes to startup time and introduces nondeterminism. At ~4.5MB total the files are well within GitHub limits, and committing them gives a reproducible, instant cold start.

---

## Known Limitations

- **WHOIS latency:** Domain age lookups add 1–3 seconds per request. Domains with privacy protection (WHOIS guard) return no creation date — the system fails silently and applies no age penalty rather than false-flagging.
- **URL-only ML:** The model was trained on URL structure, not page content. A legitimate-looking URL serving a malicious page would not be caught by the ML layer. The heuristic DOM scanner partially compensates.
- **Cache TTL:** The 30-second domain cache in `content.js` means a URL added to threat intelligence mid-session won't be re-evaluated until the cache expires.
- **Rate limiting:** The free Railway tier has resource limits. Under heavy load the backend may respond slowly — this is a portfolio project, not production infrastructure.

---

<div align="center">

Built by [Nayef Siddique](https://github.com/nayefsiddique-eng) · Deployed on [Railway](https://railway.app)

</div>
