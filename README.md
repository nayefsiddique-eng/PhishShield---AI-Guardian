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

## Roadmap

- [ ] **Confidence explainability panel** — per-feature contribution breakdown showing which of the 15 features drove the ML score
- [ ] **Visual similarity detection** — headless screenshot + cosine similarity against login page fingerprints for Google, PayPal, etc.
- [ ] **Firefox port** — WebExtensions API is compatible; mostly a manifest and packaging change
- [ ] **User whitelist** — false-positive reporting and domain override
- [ ] **Threat feed sync** — daily PhishTank feed cached on Railway for zero-latency cross-reference

---

<div align="center">

Built by [Nayef Siddique](https://github.com/nayefsiddique-eng) · Deployed on [Railway](https://railway.app)

</div>
