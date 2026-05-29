/**
 * PhishShield AI - Manifest V3 Service Worker
 */

const CONFIG = {
  apiEndpoint: "https://phishshield-ai-guardian-production.up.railway.app/predict",
};

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    lastCheckedDomain: "Initialization Node",
    lastThreatScore: 0,
    lastThreatFlags: ["System Ready"]
  });
  console.log("[PhishShield AI] Background service engine successfully mounted.");
});

const pendingRequests = new Set();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "EVALUATE_SECURITY_TELEMETRY") {
    const data = message.telemetryData;

    // Build a clean scheme+domain URL — no path, no query string.
    // The model was trained on bare domain URLs so we must match that format.
    let requestUrl;
    try {
      const raw = sender.tab?.url || data.pageUrl || ("http://" + data.domainName);
      const parsed = new URL(raw);
      requestUrl = parsed.origin + "/";
    } catch (_) {
      requestUrl = "http://" + data.domainName + "/";
    }

    // Dedup guard — skip if already processing this domain
    if (pendingRequests.has(data.domainName)) {
      sendResponse({ riskScore: 0, triggeredMitigations: ["Scan already in progress"] });
      return true;
    }
    pendingRequests.add(data.domainName);

    let computedRiskScore = 0;
    let activatedAlertFlags = [];

    // Local heuristic: password field over HTTP is an immediate red flag
    if (
      data.hasPasswordInput &&
      sender.tab?.url?.startsWith("http://") &&
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

        // Backend score is authoritative. Local HTTP penalty is additive, capped at 100.
        computedRiskScore = Math.min(backendScore + computedRiskScore, 100);
        if (backendFlags.length > 0) {
          activatedAlertFlags = [...activatedAlertFlags, ...backendFlags];
        }

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
        pendingRequests.delete(data.domainName);
      });

    return true; // Keep Chrome message channel alive for async response
  }
});
