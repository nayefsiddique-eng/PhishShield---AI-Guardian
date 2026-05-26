/**
 * PhishShield AI - Popup Controller
 * Drives ring animation, color states, and flag rendering
 */
document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(["lastCheckedDomain", "lastThreatScore", "lastThreatFlags"], (data) => {

    const domainEl    = document.getElementById("target-domain");
    const scoreEl     = document.getElementById("threat-score");
    const ringFill    = document.getElementById("ring-fill");
    const ringLabel   = document.getElementById("ring-label");
    const flagsList   = document.getElementById("flags-list");
    const threatCard  = document.getElementById("threat-card");
    const severityBadge = document.getElementById("severity-badge");

    // ── No scan yet ──────────────────────────────────
    if (!data.lastCheckedDomain || data.lastCheckedDomain === "Initialization Node") {
      domainEl.textContent = "No active scan";
      return;
    }

    // ── Domain ───────────────────────────────────────
    domainEl.textContent = data.lastCheckedDomain;

    // ── Score + severity tier ─────────────────────────
    const score = data.lastThreatScore || 0;
    scoreEl.textContent = score;

    // Ring: circumference = 175.9, offset = circ * (1 - score/100)
    const offset = 175.9 * (1 - score / 100);
    ringFill.style.strokeDashoffset = offset;

    let tier = "safe";
    if (score >= 70)      tier = "danger";
    else if (score >= 40) tier = "medium";

    const tierLabels = { safe: "SAFE", medium: "WARN", danger: "HIGH" };

    // Apply color class to ring, score number, threat card
    if (tier !== "safe") {
      ringFill.classList.add(tier);
      ringLabel.classList.add(tier);
      scoreEl.parentElement.classList.add(tier);
    } else {
      ringFill.classList.add("safe");
      ringLabel.classList.add("safe");
      scoreEl.parentElement.classList.add("safe");
      threatCard.classList.add("safe");
    }

    if (tier === "medium") threatCard.classList.add("medium");

    ringLabel.textContent = tierLabels[tier];

    // ── Severity badge ────────────────────────────────
    severityBadge.textContent = tierLabels[tier];
    severityBadge.className = `severity-badge severity-${tier}`;

    // ── Flags ─────────────────────────────────────────
    const flags = (data.lastThreatFlags || []).filter(f => f !== "System Ready");

    if (flags.length > 0) {
      flagsList.innerHTML = "";
      flags.forEach((text) => {
        const item = document.createElement("div");
        item.className = "flag-item";
        item.innerHTML = `
          <svg class="flag-icon" width="14" height="14" viewBox="0 0 24 24"
            fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <span class="flag-text">${text}</span>
        `;
        flagsList.appendChild(item);
      });
    }
  });
});