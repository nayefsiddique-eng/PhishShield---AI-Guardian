"""
PhishShield AI - Live Core Engine (Cloudflare HTTPS Tunneling Deployment)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from flask_cloudflared import _run_cloudflared
import Levenshtein
import uvicorn
import threading
import time

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DomainPayload(BaseModel):
    domain: str

PROTECTED_BRANDS = ["google", "amazon", "netflix", "paypal", "microsoft", "linkedin", "apple", "facebook"]

@app.post("/api/v1/analyze-domain")
async def analyze_domain(payload: DomainPayload):
    target_domain = payload.domain.strip().lower()
    clean_name = target_domain.replace("www.", "")
    pure_domain_string = clean_name.split('.')[0]
    
    backend_risk_score = 0
    backend_flags = []

    print(f"[LIVE AUDIT] Analyzing: {target_domain} (Parsed as: {pure_domain_string})")

    for brand in PROTECTED_BRANDS:
        if pure_domain_string == brand:
            return {"status": "SAFE", "backendRiskScore": 0, "backendFlags": []}
            
        distance = Levenshtein.distance(pure_domain_string, brand)
        if 1 <= distance <= 2:
            backend_risk_score += 55
            backend_flags.append(f"Deceptive Typo-Squatting: Match closer to brand [{brand.upper()}]")
            break

    scam_keywords = ["verify", "secure", "update", "login", "signin"]
    for keyword in scam_keywords:
        if keyword in target_domain:
            backend_risk_score += 20
            backend_flags.append(f"Threat Phrase Detected: [{keyword}]")
            break

    return {
        "status": "PROCESSED",
        "backendRiskScore": backend_risk_score,
        "backendFlags": backend_flags
    }

def start_cloudflare_tunnel():
    """Spins up the Cloudflare binary loop on a parallel background thread"""
    time.sleep(1.5) # Give Uvicorn a moment to start up first
    print("\n[SYSTEM] Initializing Cloudflare Tunnel Cluster...")
    
    try:
        # Fixed positional argument signature by explicitly passing both ports
        metrics_url = _run_cloudflared(port=8000, metrics_port=8050)
        
        print("\n" + "="*60)
        print(f"🚀 PHISHSHIELD AI LIVE SECURE GLOBAL LINK:")
        print(f"👉 {metrics_url} 👈")
        print("="*60 + "\n")
    except Exception as e:
        print(f"\n[ERROR] Tunnel allocation failed: {e}\n")

if __name__ == "__main__":
    # Fire up the tunnel wrapper process asynchronously
    threading.Thread(target=start_cloudflare_tunnel, daemon=True).start()
    
    # Run our standard fast API listener core
    uvicorn.run(app, host="127.0.0.1", port=8000)