| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Service info |
| `/health` | GET | Health check |
| `/predict` | POST | Score a URL |
| `/docs` | GET | Interactive API UI |

---

## API

### `POST /predict`

Request:
```json
{ "url": "http://paypa1-secure-login.xyz" }
```

Response:
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

---

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the model (one time only)

```bash
python train_model.py
```

Downloads ~10,000 URLs from PhishTank and Tranco, trains the Random Forest, saves model artifacts. Takes about 2 minutes.

### 3. Deploy backend

The backend is already live on Railway. To run locally:

```bash
uvicorn server:app --reload
```

### 4. Load the extension

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `phishshield-extension` folder

---

## Tech stack

**Frontend:** Chrome Extension (Manifest V3), Vanilla JS, CSS  
**Backend:** Python, FastAPI, Uvicorn  
**ML:** scikit-learn (RandomForestClassifier), numpy  
**Enrichment:** python-whois (domain age), python-Levenshtein (typosquatting)  
**Deployment:** Railway  
**Data:** PhishTank, Tranco Top-1M  

---

## Design decisions

**Why Random Forest over deep learning?** Inference is microseconds vs hundreds of milliseconds for a neural net. Latency matters for a browser extension backend. RF is also more explainable in an interview — you can point to specific features driving the score.

**Why 15 engineered features over raw text?** Structural features generalise better to unseen phishing patterns than character-level models. The features capture attacker intent — obfuscation, brand impersonation — rather than surface patterns that change with every campaign.

**Why a heuristic layer on top of ML?** The ML model outputs a probability. The heuristic layer provides human-readable explanations. Users need to know *why* a site was flagged, not just that it was. It also acts as a safety net for edge cases the model might miss.

**Why WHOIS domain age?** The majority of phishing infrastructure uses domains registered days or hours before the attack. This is a well-documented attacker behaviour (short TTL campaigns). Adding registration age as a signal catches campaigns that look structurally clean by URL alone.

**Why Manifest V3?** MV2 is deprecated by Chrome. Building on V3 from the start means the extension won't break as Chrome phases out MV2 support.

---

## Known limitations

- WHOIS lookups add 1–3 seconds of latency per request. Domains with private registration return no age data (fail silently, no penalty applied).
- The ML model was trained on URL structure only. A page that looks legitimate by URL but has deceptive content would not be caught by the ML layer.
- `content.js` cache TTL is 30 seconds — pages that dynamically inject content after the cache window could be missed on fast revisits.

---