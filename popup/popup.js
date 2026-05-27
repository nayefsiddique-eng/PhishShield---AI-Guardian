/**
 * PhishShield AI - Popup Controller
 * Drives ring animation, color states, and flag rendering
 */
document.addEventListener("DOMContentLoaded", () => {
  function createFlagIcon() {
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("class", "flag-icon");
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2.5");
    svg.setAttribute("stroke-linecap", "round");

    const circle = document.createElementNS(svgNS, "circle");
    circle.setAttribute("cx", "12");
    circle.setAttribute("cy", "12");
    circle.setAttribute("r", "10");

    const line1 = document.createElementNS(svgNS, "line");
    line1.setAttribute("x1", "12");
    line1.setAttribute("y1", "8");
    line1.setAttribute("x2", "12");
    line1.setAttribute("y2", "12");

    const line2 = document.createElementNS(svgNS, "line");
    line2.setAttribute("x1", "12");
    line2.setAttribute("y1", "16");
    line2.setAttribute("x2", "12.01");
    line2.setAttribute("y2", "16");

    svg.appendChild(circle);
    svg.appendChild(line1);
    svg.appendChild(line2);
    return svg;
  }

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
      flagsList.replaceChildren();
      flags.forEach((text) => {
        const item = document.createElement("div");
        item.className = "flag-item";
        item.appendChild(createFlagIcon());
        const label = document.createElement("span");
        label.className = "flag-text";
        label.textContent = text;
        item.appendChild(label);
        flagsList.appendChild(item);
      });
    }
  });
});