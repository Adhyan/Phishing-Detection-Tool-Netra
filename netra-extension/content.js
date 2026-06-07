// ===============================
// NETRA EXTENSION - FINAL VERSION
// ===============================
console.log("NETRA EXTENSION LOADED");
// Prevent duplicate scans
const scannedLinks = new Set();

// ===============================
// FLOATING PANEL UI
// ===============================
const panel = document.createElement("div");

panel.style.position = "fixed";
panel.style.bottom = "20px";
panel.style.right = "20px";
panel.style.background = "#0b1220";
panel.style.color = "white";
panel.style.padding = "12px";
panel.style.borderRadius = "10px";
panel.style.boxShadow = "0 0 15px rgba(0,0,0,0.5)";
panel.style.zIndex = "999999";
panel.style.fontSize = "12px";
panel.style.maxWidth = "250px";
panel.style.fontFamily = "Arial";

panel.innerHTML = `
<b>🛡 NETRA Scanner</b><br>
<span id="netra-safe">✔ Safe: 0</span><br>
<span id="netra-phish">⚠ Phishing: 0</span><br>
<span id="netra-invalid">❌ Invalid: 0</span>
`;

window.addEventListener("load", () => {
  document.body.appendChild(panel);
});

// Counters
let safeCount = 0;
let phishingCount = 0;
let invalidCount = 0;

function updatePanel() {
  document.getElementById("netra-safe").textContent = `✔ Safe: ${safeCount}`;
  document.getElementById("netra-phish").textContent = `⚠ Phishing: ${phishingCount}`;
  document.getElementById("netra-invalid").textContent = `❌ Invalid: ${invalidCount}`;
}

// ===============================
// STYLE LINKS (VISIBLE AF)
// ===============================
function styleLink(link, color, text) {
  // Avoid re-styling
  if (link.classList.contains("netra-scanned")) return;
  link.classList.add("netra-scanned");

  // Strong border
  link.style.border = `2px solid ${color}`;
  link.style.borderRadius = "4px";

  // Glow
  link.style.boxShadow = `0 0 8px ${color}`;

  // Background highlight
  if (color === "red") {
    link.style.backgroundColor = "rgba(255,0,0,0.15)";
  } else if (color === "green") {
    link.style.backgroundColor = "rgba(0,255,0,0.15)";
  } else if (color === "orange") {
    link.style.backgroundColor = "rgba(255,165,0,0.15)";
  } else {
    link.style.backgroundColor = "rgba(128,128,128,0.15)";
  }

  // Tooltip
  link.title = text;
  if (link.querySelector(".netra-badge")) return;
  // Badge
  const badge = document.createElement("span");
  badge.className = "netra-badge";
  badge.textContent =
    color === "red" ? " ⚠ PHISHING" :
    color === "green" ? " ✔ SAFE" :
    color === "orange" ? " ⚠ RISK" :
    " ❌ INVALID";

  badge.style.marginLeft = "6px";
  badge.style.fontSize = "10px";
  badge.style.padding = "2px 4px";
  badge.style.borderRadius = "3px";
  badge.style.color = "white";
  badge.style.background =
    color === "red" ? "red" :
    color === "green" ? "green" :
    color === "orange" ? "orange" :
    "gray";

    
  link.appendChild(badge);
}

// ===============================
// SCAN SINGLE LINK
// ===============================
async function scanLink(link) {
  const url = link.href;

  if (!url || scannedLinks.has(url) || url.startsWith("javascript")) return;

  scannedLinks.add(url);

  try {
    console.log("Scanning:", url);
    const res = await fetch("http://localhost:8000/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url })
    });

    const data = await res.json();
    console.log("Response:", data);
    // INVALID
    if (data.result === "Invalid") {
      styleLink(link, "gray", "Invalid domain");
      invalidCount++;
      updatePanel();
      return;
    }

    // UNREACHABLE
    if (data.result === "Unreachable") {
      styleLink(link, "orange", "Unreachable site");
      updatePanel();
      return;
    }

    // PHISHING
    if (data.result === "Phishing") {
      styleLink(link, "red", "⚠ Phishing detected");
      phishingCount++;
      updatePanel();
      return;
    }

    // SAFE
    styleLink(link, "green", "Safe link");
    safeCount++;
    updatePanel();

  } catch (err) {
  console.error("FULL ERROR:", err);
}
}

// ===============================
// SCAN ALL LINKS (WITH DELAY)
// ===============================
function scanAllLinks() {
  const links = document.querySelectorAll("a");

  console.log("Links found:", links.length);

  links.slice(0, 50).forEach((link, index) => {
    setTimeout(() => scanLink(link), index * 100);
  });
}

// ===============================
// INITIAL LOAD
// ===============================
window.addEventListener("load", () => {
  console.log("NETRA STARTED");
  scanAllLinks();
});

// ===============================
// DYNAMIC CONTENT (IMPORTANT)
// ===============================
const observer = new MutationObserver(() => {
  scanAllLinks();
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});