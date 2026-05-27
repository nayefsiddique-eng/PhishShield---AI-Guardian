/**
 * PhishShield AI - Real-Time Dynamic Telemetry Observer Engine
 * FIXED: Debounced MutationObserver, per-domain result caching
 */
(function initializeDynamicScanner() {
  console.log("[PhishShield AI] Initializing proactive telemetry system...");

  // ✅ FIX 1: Cache stores the last scanned domain + result
  //    so we don't hammer the backend every time the DOM sneezes
  const scanCache = {};
  const CACHE_TTL_MS = 30000; // Re-scan the same domain after 30 seconds max

  function scanAndReportDOM() {
    const sanitizedDomain = window.location.hostname;

    // ✅ FIX 2: Cache hit check — skip API call if we scanned this domain recently
    const cached = scanCache[sanitizedDomain];
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
      // We already have a fresh result — just re-apply the banner if needed
      if (cached.riskScore >= 40) {
        deployInterceptionBanner(cached.riskScore, cached.mitigations);
      }
      return;
    }

    const passwordField = document.querySelector('input[type="password"]');
    const hasPassword = passwordField !== null;

    const telemetryData = {
      domainName: sanitizedDomain,
      pageUrl: window.location.href,
      hasPasswordInput: hasPassword,
      paymentFieldsCount: document.querySelectorAll('input[name*="card"], input[id*="cvv"]').length,
      totalForms: document.forms.length
    };

    chrome.runtime.sendMessage(
      { action: "EVALUATE_SECURITY_TELEMETRY", telemetryData },
      (response) => {
        if (chrome.runtime.lastError) return;

        if (response) {
          // ✅ FIX 3: Store result in cache with a timestamp
          scanCache[sanitizedDomain] = {
            riskScore: response.riskScore,
            mitigations: response.triggeredMitigations,
            timestamp: Date.now()
          };

          if (response.riskScore >= 40) {
            deployInterceptionBanner(response.riskScore, response.triggeredMitigations);
          }
        }
      }
    );
  }

  // Run an immediate initial scan on page load
  scanAndReportDOM();

  // ✅ FIX 4: Debounced MutationObserver — waits 1.5s of DOM silence before re-scanning
  //    Previously fired scanAndReportDOM() on EVERY mutation (could be 100s/sec on dynamic pages)
  let debounceTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(scanAndReportDOM, 1500);
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
  });
})();

function deployInterceptionBanner(score, mitigations) {
  if (document.getElementById("phishshield-alert-banner")) return;
  console.log("[PhishShield AI] Threat threshold crossed. Deploying warning banner...");

  const banner = document.createElement('div');
  banner.id = "phishshield-alert-banner";
  banner.style.cssText = `
    position: fixed !important; top: 0 !important; left: 0 !important;
    width: 100% !important; z-index: 2147483647 !important;
    background-color: #7F1D1D !important; color: #FEE2E2 !important;
    text-align: center !important; font-family: monospace !important;
    font-weight: bold !important; padding: 16px !important;
    border-bottom: 4px solid #DC2626 !important; font-size: 14px !important;
  `;

  const safeFlags = Array.isArray(mitigations) ? mitigations.join(", ") : "";
  banner.textContent = `⚠️ PHISHSHIELD ALARM: Threat Score ${score}%. Flags: [${safeFlags}]`;

  const root = document.body || document.documentElement;
  if (!root) return;

  root.prepend(banner);
  if (document.body) {
    document.body.style.paddingTop = "60px";
  }
}