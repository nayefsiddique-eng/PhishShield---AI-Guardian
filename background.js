/**
 * PhishShield AI - Robust Manifest V3 Service Worker
 * FIXED: Externalized API URL via config, domain dedup guard
 */

// ✅ FIX 5: API URL lives here — change ONE line when your tunnel/deployment changes
//    Later we'll move this to a proper config.json, but this is already 10x better
//    than it being buried inside fetch() logic
const CONFIG = {
  apiEndpoint: "https://phishshield-ai-guardian-production.up.railway.app/predict",
  // 👆 Replace this with your live URL. When you deploy properly (Phase 3),
  //    this becomes your real domain e.g. https://api.phishshield.dev/...
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    lastCheckedDomain: "Initialization Node",
    lastThreatScore: 0,
    lastThreatFlags: ["System Ready"]
  });
  console.log("[PhishShield AI] Background service engine successfully mounted.");
});

// ✅ FIX 6: In-memory domain dedup guard
//    Prevents duplicate concurrent requests for the same domain
//    (e.g. content.js fires twice quickly before the first response is back)
const pendingRequests = new Set();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "EVALUATE_SECURITY_TELEMETRY") {
    const data = message.telemetryData;
    const tabUrl = sender.tab?.url || data.pageUrl || "";
    const requestUrl = tabUrl || data.domainName;

    // ✅ FIX 7: Skip if we're already processing this domain
    if (pendingRequests.has(data.domainName)) {
      sendResponse({ riskScore: 0, triggeredMitigations: ["Scan already in progress"] });
      return true;
    }
    pendingRequests.add(data.domainName);

    let computedRiskScore = 0;
    let activatedAlertFlags = [];

    // Local heuristic: password field over HTTP is always flagged immediately
    if (
      data.hasPasswordInput &&
      sender.tab &&
      sender.tab.url.startsWith("http://") &&
      !data.domainName.includes("127.0.0.1")
    ) {
      computedRiskScore += 35;
      activatedAlertFlags.push("Insecure Cleartext Transmission (HTTP + Password Field)");
    }

    fetch(CONFIG.apiEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: requestUrl })
    })
      .then((res) => {
        if (!res.ok) throw new Error(`Backend returned ${res.status}`);
        return res.json();
      })
      .then((backendResult) => {
        const backendScore =
          typeof backendResult.score === "number"
            ? backendResult.score
            : (backendResult.backendRiskScore || 0);
        const backendFlags = Array.isArray(backendResult.flags)
          ? backendResult.flags
          : (backendResult.backendFlags || []);

        computedRiskScore += backendScore;
        if (backendFlags.length > 0) {
          activatedAlertFlags = [...activatedAlertFlags, ...backendFlags];
        }

        if (computedRiskScore > 100) computedRiskScore = 100;

        chrome.storage.local.set({
          lastCheckedDomain: data.domainName,
          lastThreatScore: computedRiskScore,
          lastThreatFlags: activatedAlertFlags
        });

        sendResponse({ riskScore: computedRiskScore, triggeredMitigations: activatedAlertFlags });
      })
      .catch((err) => {
        console.warn("[PhishShield AI] Backend unreachable. Falling back to local rules.", err);

        chrome.storage.local.set({
          lastCheckedDomain: data.domainName,
          lastThreatScore: computedRiskScore,
          lastThreatFlags: [...activatedAlertFlags, "Offline Mode: Local Rules Only"]
        });

        sendResponse({ riskScore: computedRiskScore, triggeredMitigations: activatedAlertFlags });
      })
      .finally(() => {
        // ✅ Always release the domain lock after request completes or fails
        pendingRequests.delete(data.domainName);
      });

    return true; // Keep Chrome message channel alive for async response
  }
});
