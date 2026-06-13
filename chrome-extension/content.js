// ShadowMap Content Script — Full 5-Tab Cockpit Overlay
// Tabs: SCAN | PHISH | APK | BREACH | CHAT

console.log("SHADOWMAP AI CONTENT SCRIPT LOADED — v2.0");

let overlayActive = false;
window.currentScanData = null;
window.chatHistory = [];

// Advanced Security State
let smTrackers = [];
let smForms = [];
let smDomMutations = [];
let smPasswordLeaks = [];
let smNetworkTraffic = [];

// =============================================================================
// INJECT NETWORK SPY
// =============================================================================
try {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('inject.js');
    (document.head || document.documentElement).appendChild(script);
    script.onload = function() { script.remove(); };
} catch(e) {}

window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data && event.data.type === 'SHADOWMAP_NETWORK_TRAFFIC') {
        const traffic = event.data.data;
        if (traffic && traffic.url) {
            smNetworkTraffic.push(traffic.url);
            // Cap at 100 to avoid giant payloads
            if (smNetworkTraffic.length > 100) smNetworkTraffic.shift();
            
            // Trigger a scan dynamically if it looks very suspicious
            if (overlayActive && smNetworkTraffic.length % 10 === 0) {
                chrome.runtime.sendMessage({ type: "GET_CURRENT_SCAN", payload: extractPageData() });
            }
        }
    }
});

const BACKEND = "http://127.0.0.1:5000";

// Default State Configuration
let smState = {
    isOpen: false,
    top: 24,
    left: null, // Use right if null
    right: 24,
    width: 420,
    height: 620
};

function saveState() {
    chrome.storage.local.set({ sm_overlay_state: smState });
}

function loadState(callback) {
    chrome.storage.local.get(['sm_overlay_state'], (result) => {
        if (result.sm_overlay_state) {
            smState = { ...smState, ...result.sm_overlay_state };
            
            // Off-screen safety check
            if (smState.top < 0 || smState.top > window.innerHeight - 50) smState.top = 24;
            if (smState.left !== null && (smState.left < 0 || smState.left > window.innerWidth - 50)) smState.left = null;
        }
        callback();
    });
}

// =============================================================================
// BLOCK SITE LOGIC
// =============================================================================

function checkBlockedSite() {
    chrome.storage.local.get(['blockedDomains'], function(result) {
        const domains = result.blockedDomains || [];
        if (domains.includes(window.location.hostname)) {
            document.body.innerHTML = `
                <div style="position:fixed;top:0;left:0;width:100vw;height:100vh;background:#080c14;z-index:2147483647;
                     display:flex;flex-direction:column;justify-content:center;align-items:center;
                     color:white;font-family:sans-serif;text-align:center;">
                    <div style="font-size:64px;margin-bottom:16px;">🚫</div>
                    <h1 style="color:#ef4444;font-size:36px;margin-bottom:8px;font-weight:700;">Website Blocked</h1>
                    <p style="font-size:18px;color:#94a3b8;margin-bottom:8px;">ShadowMap AI blocked this site for your protection.</p>
                    <p style="font-size:14px;color:#64748b;margin-bottom:40px;">${window.location.hostname}</p>
                    <div style="display:flex;gap:16px;">
                        <button id="sm-go-back-btn" style="padding:12px 28px;font-size:15px;background:transparent;
                            border:1px solid #3b82f6;color:#3b82f6;border-radius:8px;cursor:pointer;">← Go Back</button>
                        <button id="sm-unblock-page-btn" style="padding:12px 28px;font-size:15px;background:#ef4444;
                            border:none;color:white;border-radius:8px;cursor:pointer;">Unblock Site</button>
                    </div>
                </div>`;
            
            document.getElementById('sm-go-back-btn').addEventListener('click', () => {
                if (window.history.length > 1) {
                    window.history.back();
                } else {
                    window.close();
                }
            });
            document.getElementById('sm-unblock-page-btn').addEventListener('click', unblockCurrentSite);
        }
    });
}
checkBlockedSite();

function blockCurrentSite() {
    const domain = window.location.hostname;
    chrome.storage.local.get(['blockedDomains'], function(result) {
        let domains = result.blockedDomains || [];
        if (!domains.includes(domain)) {
            domains.push(domain);
            chrome.storage.local.set({ blockedDomains: domains }, () => setTimeout(() => location.reload(), 1000));
        }
    });
}

function unblockCurrentSite() {
    const domain = window.location.hostname;
    chrome.storage.local.get(['blockedDomains'], function(result) {
        let domains = (result.blockedDomains || []).filter(d => d !== domain);
        chrome.storage.local.set({ blockedDomains: domains }, () => setTimeout(() => location.reload(), 1000));
    });
}

// =============================================================================
// PAGE DATA EXTRACTION
// =============================================================================

function extractPageData() {
    const data = { 
        url: window.location.href, 
        hostname: window.location.hostname, 
        title: document.title, 
        trackers: smTrackers, 
        forms: smForms,
        dom_mutations: smDomMutations,
        password_leaks: smPasswordLeaks,
        network_traffic: smNetworkTraffic
    };
    const signatures = {
        'Google Analytics': 'google-analytics', 'Google Tag Manager': 'googletagmanager.com',
        'Meta Pixel': 'fbevents.js', 'TikTok Pixel': 'analytics.tiktok.com', 'Hotjar': 'hotjar.com', 'FingerprintJS': 'fingerprintjs'
    };
    document.querySelectorAll('script').forEach(script => {
        const c = script.src || script.innerText || "";
        for (const [name, sig] of Object.entries(signatures)) {
            if (c.toLowerCase().includes(sig.toLowerCase()) && !data.trackers.includes(name)) data.trackers.push(name);
        }
    });
    document.querySelectorAll('form').forEach(form => {
        data.forms.push({ action: form.action, hasPassword: !!form.querySelector('input[type="password"]'), inputs: form.querySelectorAll('input').length });
    });
    return data;
}

// =============================================================================
// COPY REPORT
// =============================================================================

function copySecurityReport() {
    const data = window.currentScanData;
    if (!data) return;
    let report = `ShadowMap Security Report\n\nDomain: ${data.domain || window.location.hostname}\nThreat Level: ${data.threat_level || "UNKNOWN"}\nShadowScore: ${data.shadow_score || 0}\n\nPhishing Risk: ${data.phishing_probability || 0}%\nDomain Spoof Risk: ${data.domain_spoof_probability || 0}%\nCredential Risk: ${data.credential_risk || 0}%\nRedirect Risk: ${data.redirect_risk || 0}%\n\nAI Analysis:\n${data.ai_explanation || ""}\n`;
    (data.reasons || []).forEach(r => report += `* ${r}\n`);
    navigator.clipboard.writeText(report).then(() => {
        const btn = getShadow()?.getElementById("pc-btn-copy");
        if (btn) { btn.textContent = "✓ Copied!"; setTimeout(() => btn.textContent = "Copy Report", 2000); }
    });
}

// =============================================================================
// F4 HOTKEY + MESSAGES
// =============================================================================

window.addEventListener("keydown", (e) => { if (e.key === "F4") { e.preventDefault(); toggleOverlay(); } });

chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "TOGGLE_OVERLAY") toggleOverlay();
    if (message.type === "SCAN_COMPLETE" || message.type === "UPDATE_OVERLAY_DATA") updateScanTabUI(message.data);
    if (message.type === "SCAN_ERROR") {
        console.error("Backend Error:", message.error);
        const data = { shadow_score: 0, threat_level: "ERROR", ai_explanation: `Backend Error: ${message.error}` };
        updateScanTabUI(data);
    }
});

// =============================================================================
// FLOATING FAB
// =============================================================================

function createFloatingButton() {
    if (document.getElementById("shadowmap-fab")) return;
    const btn = document.createElement("div");
    btn.id = "shadowmap-fab";
    btn.innerHTML = "🛡";
    Object.assign(btn.style, {
        position: "fixed", bottom: "25px", right: "25px", width: "68px", height: "68px",
        borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center",
        fontSize: "32px", cursor: "pointer", zIndex: "2147483646",
        background: "linear-gradient(135deg,#8B5CF6,#22D3EE)",
        boxShadow: "0 0 25px rgba(139,92,246,.5),0 0 60px rgba(34,211,238,.25)", transition: "all .25s ease"
    });

    chrome.storage.local.get(['sm_fab_pos'], (result) => {
        if (result.sm_fab_pos) {
            btn.style.bottom = "auto";
            btn.style.right = "auto";
            btn.style.left = result.sm_fab_pos.left;
            btn.style.top = result.sm_fab_pos.top;
        }
    });

    let isDraggingFab = false;
    let didMove = false;
    let startX, startY, fabStartLeft, fabStartTop;

    btn.addEventListener("mousedown", (e) => {
        isDraggingFab = true;
        didMove = false;
        startX = e.clientX;
        startY = e.clientY;
        const rect = btn.getBoundingClientRect();
        fabStartLeft = rect.left;
        fabStartTop = rect.top;
        btn.style.bottom = "auto";
        btn.style.right = "auto";
        btn.style.left = fabStartLeft + "px";
        btn.style.top = fabStartTop + "px";
        btn.style.transition = "none";
        e.preventDefault();
    });

    window.addEventListener("mousemove", (e) => {
        if (!isDraggingFab) return;
        const dx = e.clientX - startX;
        const dy = e.clientY - startY;
        if (Math.abs(dx) > 3 || Math.abs(dy) > 3) didMove = true;
        let newLeft = Math.max(0, Math.min(window.innerWidth - 68, fabStartLeft + dx));
        let newTop = Math.max(0, Math.min(window.innerHeight - 68, fabStartTop + dy));
        btn.style.left = newLeft + "px";
        btn.style.top = newTop + "px";
    });

    window.addEventListener("mouseup", () => {
        if (isDraggingFab) {
            isDraggingFab = false;
            btn.style.transition = "all .25s ease";
            chrome.storage.local.set({ sm_fab_pos: { left: btn.style.left, top: btn.style.top } });
        }
    });

    btn.addEventListener("mouseenter", () => { if (!isDraggingFab) btn.style.transform = "scale(1.08)"; });
    btn.addEventListener("mouseleave", () => { if (!isDraggingFab) btn.style.transform = "scale(1)"; });
    btn.addEventListener("click", (e) => {
        if (didMove) { e.stopPropagation(); return; }
        toggleOverlay();
    });

    document.body.appendChild(btn);
}

// =============================================================================
// HELPER: get shadow root
// =============================================================================

function getShadow() {
    return document.getElementById("shadowmap-overlay-root")?.shadowRoot || null;
}

// =============================================================================
// TAB SWITCHER
// =============================================================================

function switchTab(tabName) {
    const shadow = getShadow();
    if (!shadow) return;
    ['scan', 'phish', 'apk', 'breach', 'chat'].forEach(t => {
        shadow.getElementById(`tab-btn-${t}`).classList.toggle('active', t === tabName);
        shadow.getElementById(`tab-panel-${t}`).classList.toggle('hidden', t !== tabName);
    });
}

// =============================================================================
// OVERLAY TOGGLE
// =============================================================================

function toggleOverlay() {
    let overlay = document.getElementById("shadowmap-overlay-root");
    if (!overlay) {
        createOverlay();
        overlay = document.getElementById("shadowmap-overlay-root");
        overlayActive = true;
    } else {
        const isHidden = overlay.style.display === "none";
        overlay.style.display = isHidden ? "block" : "none";
        overlayActive = isHidden;
    }
    
    smState.isOpen = overlayActive;
    saveState();

    if (overlayActive) {
        chrome.runtime.sendMessage({ type: "GET_CURRENT_SCAN", payload: extractPageData() });
        if (window.currentScanData) updateScanTabUI(window.currentScanData);
    }
}

// =============================================================================
//  CREATE OVERLAY — Full Shadow DOM
// =============================================================================

function createOverlay() {
    if (document.getElementById("shadowmap-overlay-root")) return;
    const root = document.createElement("div");
    root.id = "shadowmap-overlay-root";
    const shadow = root.attachShadow({ mode: "open" });
    const container = document.createElement("div");

    container.innerHTML = `
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

* { box-sizing: border-box; margin: 0; padding: 0; }

.wrapper {
    position: fixed;
    top: ${smState.top}px;
    ${smState.left !== null ? `left: ${smState.left}px;` : `right: ${smState.right}px;`}
    width: ${smState.width}px;
    height: ${smState.height}px;
    max-height: 90vh;
    background: linear-gradient(160deg, #080c14 0%, #0d1220 100%);
    backdrop-filter: blur(30px);
    -webkit-backdrop-filter: blur(30px);
    border-radius: 16px;
    border: 1px solid rgba(139, 92, 246, 0.3);
    color: white;
    font-family: 'Inter', sans-serif;
    z-index: 2147483647;
    box-shadow: 0 32px 64px rgba(0,0,0,0.7), 0 0 80px rgba(139,92,246,0.12), inset 0 1px 0 rgba(255,255,255,0.05);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    user-select: none;
}

.sm-header {
    cursor: move;
}

.resize-handle {
    position: absolute;
    bottom: 0;
    right: 0;
    width: 16px;
    height: 16px;
    cursor: nwse-resize;
    background: linear-gradient(135deg, transparent 50%, rgba(139, 92, 246, 0.4) 50%);
    border-radius: 0 0 16px 0;
}

/* ── Header ── */
.sm-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px 10px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    flex-shrink: 0;
}
.sm-logo {
    display: flex;
    align-items: center;
    gap: 9px;
}
.sm-logo-icon {
    width: 30px; height: 30px;
    background: linear-gradient(135deg,#8b5cf6,#22d3ee);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px;
    box-shadow: 0 0 14px rgba(139,92,246,.5);
}
.sm-logo-text {
    font-size: 13px; font-weight: 700; letter-spacing: 2.5px;
    color: #e2e8f0; text-transform: uppercase;
}
.sm-logo-sub { font-size: 10px; color: #475569; letter-spacing: 1px; }
.sm-close {
    width: 28px; height: 28px; border-radius: 6px;
    background: rgba(255,255,255,0.06); border: none; color: #64748b;
    cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center;
    transition: all .2s;
}
.sm-close:hover { background: rgba(255,255,255,0.12); color: #e2e8f0; }

/* ── Tab Bar ── */
.tab-bar {
    display: flex;
    padding: 8px 14px 0;
    gap: 2px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    flex-shrink: 0;
    background: rgba(0,0,0,0.2);
}
.tab-btn {
    flex: 1; padding: 8px 4px; border: none; background: transparent;
    color: #475569; font-family: 'Inter', sans-serif; font-size: 11px; font-weight: 600;
    cursor: pointer; border-radius: 6px 6px 0 0; letter-spacing: 0.5px; text-transform: uppercase;
    transition: all .2s; position: relative;
}
.tab-btn:hover { color: #94a3b8; background: rgba(255,255,255,0.04); }
.tab-btn.active { color: #a78bfa; }
.tab-btn.active::after {
    content: ''; position: absolute; bottom: -1px; left: 8px; right: 8px; height: 2px;
    background: linear-gradient(90deg, #8b5cf6, #22d3ee);
    border-radius: 2px 2px 0 0;
    box-shadow: 0 0 10px rgba(139,92,246,.6);
}
.tab-icon { font-size: 13px; display: block; margin-bottom: 1px; }

/* ── Content Area ── */
.tab-content {
    flex: 1; overflow-y: auto; overflow-x: hidden;
    padding: 16px 18px;
    scrollbar-width: thin; scrollbar-color: rgba(139,92,246,.3) transparent;
}
.tab-content::-webkit-scrollbar { width: 4px; }
.tab-content::-webkit-scrollbar-track { background: transparent; }
.tab-content::-webkit-scrollbar-thumb { background: rgba(139,92,246,.3); border-radius: 2px; }

.hidden { display: none !important; }

/* ── Animations ── */
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(8px); }
    to { opacity: 1; transform: translateY(0); }
}
@keyframes pulse-ring {
    0%,100% { box-shadow: 0 0 0 0 rgba(139,92,246,.4); }
    50% { box-shadow: 0 0 0 8px rgba(139,92,246,0); }
}
@keyframes typing-dot {
    0%,80%,100% { transform: translateY(0); opacity:.4; }
    40% { transform: translateY(-4px); opacity:1; }
}
@keyframes borderGlow {
    0% { box-shadow: 0 0 12px rgba(168,85,247,.2); }
    100% { box-shadow: 0 0 28px rgba(34,211,238,.35); }
}
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes scoreCountUp {
    from { opacity:0; transform: scale(.8); }
    to { opacity:1; transform: scale(1); }
}
@keyframes drawRing {
    from { stroke-dashoffset: 264; }
    to { stroke-dashoffset: var(--target-offset); }
}

/* ═══════════════════════════════════════════════════
   TAB 1 — SCAN
═══════════════════════════════════════════════════ */
.scan-panel { animation: fadeInUp .3s ease; }

.domain-strip {
    text-align: center; margin-bottom: 14px;
    padding: 8px 12px; background: rgba(249,115,22,.08);
    border: 1px solid rgba(249,115,22,.2); border-radius: 8px;
}
.domain-strip .domain-label { font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
.domain-strip .domain-val { font-size: 14px; font-weight: 600; color: #f97316; word-break: break-all; margin-top: 2px; }

.score-row {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 14px;
}

/* Ring */
.ring-wrap { position: relative; width: 120px; height: 120px; flex-shrink: 0; }
.ring-svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.ring-bg { fill: none; stroke: rgba(255,255,255,0.06); stroke-width: 8; }
.ring-fill {
    fill: none; stroke-width: 8; stroke-linecap: round;
    stroke-dasharray: 264;
    stroke-dashoffset: 264;
    transition: stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1), stroke .5s;
}
.ring-inner {
    position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
}
.ring-score { font-size: 30px; font-weight: 700; color: #fff; animation: scoreCountUp .5s ease; font-family: 'JetBrains Mono',monospace; }
.ring-label { font-size: 8px; color: #64748b; letter-spacing: 0.5px; text-transform: uppercase; }

/* Badge */
.threat-badge {
    display: inline-flex; align-items: center; justify-content: center;
    padding: 5px 14px; border-radius: 20px; font-size: 10px; font-weight: 700;
    letter-spacing: 1.5px; text-transform: uppercase; border: 1px solid; margin-top: 6px;
}
.badge-trusted { color:#10b981; border-color:rgba(16,185,129,.4); background:rgba(16,185,129,.1); box-shadow:0 0 12px rgba(16,185,129,.2); }
.badge-safe { color:#06b6d4; border-color:rgba(6,182,212,.4); background:rgba(6,182,212,.1); box-shadow:0 0 12px rgba(6,182,212,.2); }
.badge-suspicious { color:#f59e0b; border-color:rgba(245,158,11,.4); background:rgba(245,158,11,.1); box-shadow:0 0 12px rgba(245,158,11,.2); }
.badge-dangerous { color:#f97316; border-color:rgba(249,115,22,.4); background:rgba(249,115,22,.1); box-shadow:0 0 12px rgba(249,115,22,.2); }
.badge-critical { color:#ef4444; border-color:rgba(239,68,68,.4); background:rgba(239,68,68,.1); box-shadow:0 0 12px rgba(239,68,68,.2); animation: pulse-ring 2s infinite; }
.badge-unknown { color:#64748b; border-color:rgba(100,116,139,.4); background:rgba(100,116,139,.1); }

/* Exposure sphere */
.exposure-col { text-align: center; }
.sphere-wrap { position: relative; width: 76px; height: 76px; margin: 0 auto 6px; }
.sphere {
    width:100%;height:100%;border-radius:50%;
    background: radial-gradient(circle at 35% 35%, rgba(253,186,116,.9) 0%, rgba(220,38,38,.8) 40%, rgba(69,10,10,.95) 100%);
    box-shadow: inset -8px -8px 16px rgba(0,0,0,.6), inset 8px 8px 16px rgba(255,255,255,.3), 0 0 28px rgba(220,38,38,.4);
    display:flex;align-items:center;justify-content:center;position:relative;overflow:hidden;
}
.sphere::after {
    content:'';position:absolute;top:8%;left:15%;width:38%;height:38%;
    background:radial-gradient(ellipse, rgba(255,255,255,.35) 0%, transparent 70%);
    transform:rotate(-45deg);border-radius:50%;
}
.sphere-val { font-size:16px;font-weight:700;color:#fff;z-index:2;position:relative;font-family:'JetBrains Mono',monospace; }
.sphere-lbl { font-size:10px;color:#64748b;letter-spacing:.5px; }

/* Pills */
.pills-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 7px; margin-bottom: 14px;
}
.pill {
    background: rgba(15,18,30,.8); border: 1px solid rgba(255,255,255,.08);
    border-radius: 8px; padding: 9px 11px; font-size: 11px; color: #cbd5e1;
    display: flex; justify-content: space-between; align-items: center;
    transition: all .25s; cursor: default;
}
.pill:hover { background: rgba(255,255,255,.05); transform: translateY(-1px); }
.pill-val { font-weight: 700; font-family: 'JetBrains Mono',monospace; font-size: 12px; }

/* AI Card */
.ai-card {
    border-radius: 10px; padding: 2px;
    background: linear-gradient(135deg, rgba(139,92,246,.7), rgba(34,211,238,.7));
    margin-bottom: 14px;
    animation: borderGlow 4s ease-in-out infinite alternate;
}
.ai-card-inner {
    background: #080c14; border-radius: 8px; padding: 12px;
    font-family: 'JetBrains Mono',monospace; font-size: 11px;
    color: #c4b5fd; line-height: 1.6; white-space: pre-wrap; min-height: 54px;
}
.ai-label { font-size: 10px; color: #6d28d9; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 5px; font-family:'Inter',sans-serif; }

/* Scan action buttons */
.scan-actions { display: flex; gap: 8px; }
.btn-scan { flex:1; padding:9px 0; border-radius:8px; font-size:11px; font-weight:600; cursor:pointer; font-family:'Inter',sans-serif; border:none; transition:all .2s; text-align:center; }
.btn-protect { background:linear-gradient(90deg,#8b5cf6,#3b82f6); color:#fff; box-shadow:0 0 16px rgba(139,92,246,.35); }
.btn-protect:hover { box-shadow:0 0 24px rgba(139,92,246,.6); transform:translateY(-1px); }
.btn-block { background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.3); color:#fca5a5; }
.btn-block:hover { background:rgba(239,68,68,.2); }
.btn-copy { background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.1); color:#94a3b8; }
.btn-copy:hover { background:rgba(255,255,255,.1); color:#e2e8f0; }

/* Protection Center sub-view */
.pc-view { animation: fadeInUp .3s ease; }
.sub-title { font-size:13px;font-weight:600;color:#e2e8f0;border-bottom:1px solid rgba(255,255,255,.08);padding-bottom:8px;margin-bottom:12px; }
.pc-risk-grid { display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:12px; }
.pc-risk-item { background:rgba(0,0,0,.3);border-radius:6px;padding:8px 10px;font-size:11px;color:#94a3b8;display:flex;justify-content:space-between; }
.pc-risk-val { font-weight:700;font-family:'JetBrains Mono',monospace; }
.pc-recs { background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.25);padding:10px 12px;border-radius:8px;font-size:11px;color:#c4b5fd;line-height:1.6;margin-bottom:12px; }
.pc-btns { display:grid;grid-template-columns:1fr 1fr;gap:8px; }
.btn-pc { background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:#e2e8f0;padding:8px;border-radius:6px;font-size:11px;cursor:pointer;transition:all .2s;font-family:'Inter',sans-serif; }
.btn-pc:hover { background:rgba(255,255,255,.1); }
.btn-pc.danger { background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3);color:#fca5a5; }
.btn-pc.danger:hover { background:rgba(239,68,68,.2); }

/* Block confirm */
.bc-view { text-align:center;padding:20px 0;animation:fadeInUp .3s ease; }
.bc-title { font-size:15px;color:#ef4444;font-weight:600;margin-bottom:8px; }
.bc-sub { font-size:12px;color:#64748b;margin-bottom:24px; }
.bc-btns { display:flex;gap:12px;justify-content:center; }
.btn-ghost { background:transparent;border:1px solid rgba(255,255,255,.15);color:#94a3b8;padding:9px 22px;border-radius:8px;font-size:12px;cursor:pointer;font-family:'Inter',sans-serif;transition:all .2s; }
.btn-ghost:hover { border-color:rgba(255,255,255,.3);color:#e2e8f0; }
.btn-red { background:#ef4444;border:none;color:#fff;padding:9px 22px;border-radius:8px;font-size:12px;cursor:pointer;font-family:'Inter',sans-serif;transition:all .2s; }
.btn-red:hover { background:#dc2626; }

/* Detailed analysis */
.da-view { animation:fadeInUp .3s ease; }
.da-grid { display:grid;grid-template-columns:1fr 1fr;gap:6px;background:rgba(0,0,0,.3);padding:10px;border-radius:8px;font-size:11px;color:#94a3b8;margin-bottom:10px; }
.section-label { font-size:11px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.8px;margin:8px 0 4px; }
.reason-list { font-size:11px;color:#cbd5e1;padding-left:14px;margin:0 0 6px; }
.reason-list li { margin-bottom:3px; }

/* Loading spinner */
.loading-row { display:flex;align-items:center;gap:10px;padding:20px;justify-content:center; }
.spinner { width:20px;height:20px;border:2px solid rgba(139,92,246,.2);border-top-color:#8b5cf6;border-radius:50%;animation:spin .8s linear infinite; }
.loading-text { font-size:13px;color:#64748b; }

/* ═══════════════════════════════════════════════════
   TAB 2 — PHISH
═══════════════════════════════════════════════════ */
.phish-panel h3, .apk-panel h3, .breach-panel h3, .chat-panel h3 {
    font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:4px;
}
.tab-desc { font-size:11px;color:#64748b;margin-bottom:14px;line-height:1.5; }

.sm-textarea, .sm-input {
    width:100%; background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.1);
    border-radius:8px; color:#e2e8f0; font-family:'Inter',sans-serif; font-size:12px;
    padding:10px 12px; resize:vertical; outline:none; transition:border-color .2s;
}
.sm-textarea { min-height:100px; line-height:1.5; }
.sm-textarea:focus, .sm-input:focus { border-color:rgba(139,92,246,.5); }
.sm-textarea::placeholder, .sm-input::placeholder { color:#334155; }

.sm-label { font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.8px;margin-bottom:5px;display:block; }

.btn-analyze {
    width:100%;padding:11px;border:none;border-radius:8px;
    background:linear-gradient(90deg,#8b5cf6,#3b82f6);color:#fff;
    font-size:12px;font-weight:700;cursor:pointer;font-family:'Inter',sans-serif;
    margin-top:10px;transition:all .2s;letter-spacing:.5px;
    box-shadow:0 0 16px rgba(139,92,246,.3);
}
.btn-analyze:hover { box-shadow:0 0 24px rgba(139,92,246,.6);transform:translateY(-1px); }
.btn-analyze:disabled { opacity:.5;cursor:not-allowed;transform:none; }

/* Result Cards */
.result-card {
    margin-top:14px;background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.07);
    border-radius:10px;padding:14px;animation:fadeInUp .4s ease;
}
.result-header { display:flex;align-items:center;justify-content:space-between;margin-bottom:10px; }
.result-title { font-size:12px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.8px; }
.prob-bar-wrap { margin-bottom:12px; }
.prob-bar-label { display:flex;justify-content:space-between;font-size:11px;color:#94a3b8;margin-bottom:4px; }
.prob-bar-label .prob-pct { font-weight:700;font-family:'JetBrains Mono',monospace; }
.prob-bar-track { height:8px;background:rgba(255,255,255,.08);border-radius:4px;overflow:hidden; }
.prob-bar-fill { height:100%;border-radius:4px;transition:width 1s cubic-bezier(.4,0,.2,1);width:0%; }

.class-badge {
    display:inline-flex;padding:4px 12px;border-radius:20px;font-size:10px;font-weight:700;
    letter-spacing:1px;text-transform:uppercase;border:1px solid;
}
.class-phishing { color:#ef4444;border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.1); }
.class-suspicious { color:#f97316;border-color:rgba(249,115,22,.4);background:rgba(249,115,22,.1); }
.class-low_risk { color:#f59e0b;border-color:rgba(245,158,11,.4);background:rgba(245,158,11,.1); }
.class-safe { color:#10b981;border-color:rgba(16,185,129,.4);background:rgba(16,185,129,.1); }

.indicators-list { list-style:none;padding:0;margin:8px 0; }
.indicators-list li {
    font-size:11px;color:#cbd5e1;padding:5px 10px;background:rgba(255,255,255,.04);
    border-radius:5px;margin-bottom:3px;border-left:2px solid rgba(139,92,246,.4);
}
.eli12-box { background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.2);border-radius:8px;padding:10px;font-size:11px;color:#c4b5fd;line-height:1.6;margin-top:8px; }
.eli12-label { font-size:9px;color:#6d28d9;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px; }

/* ═══════════════════════════════════════════════════
   TAB 3 — APK
═══════════════════════════════════════════════════ */
.input-group { margin-bottom:10px; }
.risk-gauge-wrap { text-align:center;padding:10px 0; }
.risk-num {
    font-size:42px;font-weight:700;font-family:'JetBrains Mono',monospace;
    background:linear-gradient(135deg,#ef4444,#f97316);-webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.risk-level-badge { margin-top:4px; }

.perm-list { list-style:none;padding:0;margin:6px 0; }
.perm-item {
    display:flex;align-items:flex-start;gap:8px;padding:7px 10px;border-radius:6px;margin-bottom:4px;
    font-size:11px;line-height:1.4;
}
.perm-item.danger { background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);color:#fca5a5; }
.perm-item.safe { background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.15);color:#6ee7b7; }
.perm-item .perm-icon { font-size:12px;flex-shrink:0;margin-top:1px; }
.perm-name { font-weight:600;font-family:'JetBrains Mono',monospace;font-size:10px; }
.perm-reason { color:#64748b;font-size:10px; }

.combo-flag {
    padding:8px 11px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);
    border-radius:7px;font-size:11px;color:#fca5a5;margin-bottom:4px;line-height:1.4;
}

/* ═══════════════════════════════════════════════════
   TAB 4 — BREACH
═══════════════════════════════════════════════════ */
.breach-clean {
    text-align:center;padding:24px 0;animation:fadeInUp .4s ease;
}
.breach-clean-icon { font-size:48px;margin-bottom:10px; }
.breach-clean-title { font-size:16px;font-weight:700;color:#10b981;margin-bottom:6px; }
.breach-clean-sub { font-size:12px;color:#64748b;line-height:1.5; }

.breach-item {
    background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.07);border-radius:10px;
    padding:12px 14px;margin-bottom:8px;animation:fadeInUp .4s ease;
}
.breach-item-header { display:flex;align-items:center;justify-content:space-between;margin-bottom:6px; }
.breach-source { font-size:13px;font-weight:700;color:#e2e8f0; }
.breach-date { font-size:10px;color:#64748b;font-family:'JetBrains Mono',monospace; }
.breach-data { font-size:11px;color:#94a3b8;margin-bottom:6px; }
.breach-data span { background:rgba(255,255,255,.06);padding:2px 7px;border-radius:4px;margin:2px 2px 0 0;display:inline-block;font-family:'JetBrains Mono',monospace;font-size:10px; }
.breach-rec { font-size:11px;color:#c4b5fd;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.2);padding:7px 10px;border-radius:6px; }

.sev-badge {
    display:inline-flex;padding:2px 10px;border-radius:10px;font-size:9px;font-weight:700;
    letter-spacing:1px;text-transform:uppercase;border:1px solid;
}
.sev-critical { color:#ef4444;border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.12); }
.sev-high { color:#f97316;border-color:rgba(249,115,22,.4);background:rgba(249,115,22,.1); }
.sev-medium { color:#f59e0b;border-color:rgba(245,158,11,.4);background:rgba(245,158,11,.1); }
.sev-low { color:#10b981;border-color:rgba(16,185,129,.4);background:rgba(16,185,129,.1); }

.overall-rec {
    padding:10px 14px;border-radius:8px;font-size:11px;line-height:1.6;margin-top:10px;
    background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.25);color:#c4b5fd;
}

/* ═══════════════════════════════════════════════════
   TAB 5 — CHAT
═══════════════════════════════════════════════════ */
.chat-panel { display:flex;flex-direction:column;height:100%;padding:0 !important; }
.chat-messages {
    flex:1;overflow-y:auto;padding:14px 16px;
    display:flex;flex-direction:column;gap:10px;
    min-height:200px;max-height:380px;
    scrollbar-width:thin;scrollbar-color:rgba(139,92,246,.3) transparent;
}
.chat-messages::-webkit-scrollbar { width:3px; }
.chat-messages::-webkit-scrollbar-thumb { background:rgba(139,92,246,.3);border-radius:2px; }
.chat-bubble {
    max-width:85%;padding:9px 13px;border-radius:12px;font-size:12px;line-height:1.55;
    animation:fadeInUp .25s ease;
}
.chat-bubble.user {
    background:linear-gradient(135deg,rgba(139,92,246,.25),rgba(59,130,246,.2));
    border:1px solid rgba(139,92,246,.3);color:#e2e8f0;align-self:flex-end;border-bottom-right-radius:4px;
}
.chat-bubble.ai {
    background:rgba(15,18,30,.9);border:1px solid rgba(255,255,255,.08);color:#c4b5fd;
    align-self:flex-start;border-bottom-left-radius:4px;
}
.chat-bubble.ai .bubble-name { font-size:9px;color:#6d28d9;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px; }

.typing-indicator { display:flex;align-items:center;gap:3px;padding:10px 14px;align-self:flex-start; }
.dot { width:6px;height:6px;border-radius:50%;background:#6d28d9; }
.dot:nth-child(1) { animation:typing-dot 1.2s .0s infinite; }
.dot:nth-child(2) { animation:typing-dot 1.2s .2s infinite; }
.dot:nth-child(3) { animation:typing-dot 1.2s .4s infinite; }

.chat-input-row {
    display:flex;gap:8px;padding:10px 14px;border-top:1px solid rgba(255,255,255,.06);
    background:rgba(0,0,0,.25);flex-shrink:0;
}
.chat-input {
    flex:1;background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.1);
    border-radius:8px;color:#e2e8f0;font-family:'Inter',sans-serif;font-size:12px;
    padding:9px 12px;outline:none;transition:border-color .2s;
}
.chat-input:focus { border-color:rgba(139,92,246,.5); }
.chat-input::placeholder { color:#334155; }
.btn-send {
    width:38px;height:38px;border:none;border-radius:8px;
    background:linear-gradient(135deg,#8b5cf6,#3b82f6);color:#fff;
    cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;
    transition:all .2s;box-shadow:0 0 12px rgba(139,92,246,.3);flex-shrink:0;
}
.btn-send:hover { box-shadow:0 0 20px rgba(139,92,246,.6);transform:scale(1.05); }
.btn-send:disabled { opacity:.4;cursor:not-allowed;transform:none; }

/* Section divider */
.divider { height:1px;background:rgba(255,255,255,.06);margin:10px 0; }
</style>

<div class="wrapper">
  <!-- Header -->
  <div class="sm-header">
    <div class="sm-logo">
      <div class="sm-logo-icon">🛡</div>
      <div>
        <div class="sm-logo-text">ShadowMap AI</div>
        <div class="sm-logo-sub">CYBERSECURITY COCKPIT</div>
      </div>
    </div>
    <button id="sm-close-btn" class="sm-close">✕</button>
  </div>

  <!-- Tab Bar -->
  <div class="tab-bar">
    <button id="tab-btn-scan" class="tab-btn active">
      <span class="tab-icon">🔍</span>SCAN
    </button>
    <button id="tab-btn-phish" class="tab-btn">
      <span class="tab-icon">🎣</span>PHISH
    </button>
    <button id="tab-btn-apk" class="tab-btn">
      <span class="tab-icon">📱</span>APK
    </button>
    <button id="tab-btn-breach" class="tab-btn">
      <span class="tab-icon">🔓</span>BREACH
    </button>
    <button id="tab-btn-chat" class="tab-btn">
      <span class="tab-icon">💬</span>CHAT
    </button>
  </div>

  <!-- ═══════════════════════════════════════
       TAB 1 — SCAN
  ═══════════════════════════════════════ -->
  <div id="tab-panel-scan" class="tab-content scan-panel">
    <!-- Domain strip -->
    <div class="domain-strip">
      <div class="domain-label">Analyzing</div>
      <div id="sm-domain" class="domain-val">Loading...</div>
    </div>

    <!-- Score row: ring + exposure sphere -->
    <div class="score-row">
      <div style="display:flex;flex-direction:column;align-items:center;gap:6px;">
        <div class="ring-wrap">
          <svg class="ring-svg" viewBox="0 0 100 100">
            <circle class="ring-bg" cx="50" cy="50" r="42"/>
            <circle id="sm-ring-circle" class="ring-fill" cx="50" cy="50" r="42"/>
            <defs>
              <linearGradient id="ring-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop id="ring-stop-1" offset="0%" stop-color="#ef4444"/>
                <stop id="ring-stop-2" offset="100%" stop-color="#f97316"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="ring-inner">
            <div id="sm-score" class="ring-score">0</div>
            <div class="ring-label">ShadowScore</div>
          </div>
        </div>
        <div id="sm-badge" class="threat-badge badge-unknown">UNKNOWN</div>
      </div>

      <div class="exposure-col" style="display:flex;flex-direction:column;align-items:center;gap:6px;">
        <div class="ring-wrap">
          <svg class="ring-svg" viewBox="0 0 100 100">
            <circle class="ring-bg" cx="50" cy="50" r="42"/>
            <circle id="sm-exp-ring-circle" class="ring-fill" cx="50" cy="50" r="42"/>
            <defs>
              <linearGradient id="exp-ring-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop id="exp-ring-stop-1" offset="0%" stop-color="#d946ef"/>
                <stop id="exp-ring-stop-2" offset="100%" stop-color="#9333ea"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="ring-inner">
            <div id="sm-exposure" class="ring-score" style="font-size:24px;">0%</div>
            <div class="ring-label">Exposure</div>
          </div>
        </div>
        <div style="height:22px;"></div>
      </div>
    </div>

    <!-- 4 Metric Pills -->
    <div class="pills-grid">
      <div id="pill-phishing" class="pill">
        <span>🎣 Phishing</span>
        <span id="sm-phishing-val" class="pill-val">--%</span>
      </div>
      <div id="pill-spoof" class="pill">
        <span>🎭 Domain Spoof</span>
        <span id="sm-spoof-val" class="pill-val">--%</span>
      </div>
      <div id="pill-cred" class="pill">
        <span>🔑 Credential</span>
        <span id="sm-cred-val" class="pill-val">--%</span>
      </div>
      <div id="pill-redirect" class="pill">
        <span>↪ Redirect</span>
        <span id="sm-redirect-val" class="pill-val">--%</span>
      </div>
    </div>

    <!-- AI Explanation Card -->
    <div class="ai-card">
      <div class="ai-card-inner">
        <div class="ai-label">⚡ Shadow AI Analysis</div>
        <div id="sm-ai-explanation">Analyzing website security posture...</div>
      </div>
    </div>

    <!-- Action Buttons (main dashboard) -->
    <div id="scan-main-actions" class="scan-actions">
      <button id="sm-protect-btn" class="btn-scan btn-protect">🛡 Protect Me</button>
      <button id="sm-block-btn" class="btn-scan btn-block">🚫 Block Site</button>
      <button id="sm-copy-btn" class="btn-scan btn-copy">📋 Copy</button>
    </div>

    <!-- Protection Center sub-view -->
    <div id="protection-center-view" class="pc-view hidden" style="margin-top:12px;">
      <div class="sub-title">🛡 Protection Center</div>
      <div class="pc-risk-grid">
        <div class="pc-risk-item"><span>Phishing:</span><span id="pc-phish-val" class="pc-risk-val">0%</span></div>
        <div class="pc-risk-item"><span>Spoofing:</span><span id="pc-spoof-val" class="pc-risk-val">0%</span></div>
        <div class="pc-risk-item"><span>Credential:</span><span id="pc-cred-val" class="pc-risk-val">0%</span></div>
        <div class="pc-risk-item"><span>Redirect:</span><span id="pc-redirect-val" class="pc-risk-val">0%</span></div>
      </div>
      <div id="pc-recs" class="pc-recs">Generating recommendations...</div>
      <div class="pc-btns">
        <button id="pc-btn-copy" class="btn-pc">Copy Report</button>
        <button id="pc-btn-analysis" class="btn-pc">Analysis ›</button>
        <button id="pc-btn-block" class="btn-pc danger">Block Site</button>
        <button id="pc-btn-close" class="btn-pc">← Back</button>
      </div>
    </div>

    <!-- Block Confirm sub-view -->
    <div id="block-confirm-view" class="hidden" style="margin-top:12px;">
      <div class="bc-view">
        <div class="bc-title">🚫 Block this website?</div>
        <div class="bc-sub">ShadowMap will prevent future access to this domain.</div>
        <div class="bc-btns">
          <button id="bc-btn-cancel" class="btn-ghost">Cancel</button>
          <button id="bc-btn-confirm" class="btn-red">Block Site</button>
        </div>
      </div>
    </div>

    <!-- Detailed Analysis sub-view -->
    <div id="detailed-analysis-view" class="da-view hidden" style="margin-top:12px;">
      <div class="sub-title">📊 Detailed Analysis</div>
      <div class="da-grid">
        <div>Domain: <span id="da-domain" style="color:#f97316;"></span></div>
        <div>Threat: <span id="da-threat" style="font-weight:700;"></span></div>
        <div>ShadowScore: <span id="da-shadow" style="color:#a78bfa;font-family:'JetBrains Mono',monospace;"></span></div>
        <div>Trust Score: <span id="da-trust"></span></div>
        <div>Risk Score: <span id="da-risk"></span></div>
        <div>Exposure: <span id="da-exposure"></span></div>
      </div>
      <div class="section-label">Detected Reasons</div>
      <ul id="da-reasons" class="reason-list"></ul>
      <div class="section-label">Recommended Actions</div>
      <ul id="da-actions" class="reason-list"></ul>
      <div class="section-label">Risk Breakdown</div>
      <div id="da-breakdown"></div>
      <button id="da-btn-back" class="btn-pc" style="width:100%;margin-top:10px;">← Back</button>
    </div>
  </div>

  <!-- ═══════════════════════════════════════
       TAB 2 — PHISH
  ═══════════════════════════════════════ -->
  <div id="tab-panel-phish" class="tab-content hidden">
    <div class="phish-panel">
      <h3>PhishGuard AI</h3>
      <p class="tab-desc">Paste a suspicious email or SMS. Shadow AI will analyze it for phishing indicators in seconds.</p>
      <label class="sm-label">Email / SMS text</label>
      <textarea id="phish-textarea" class="sm-textarea" placeholder="Paste email or SMS text here...&#10;&#10;e.g. &quot;Your account has been suspended! Verify now at http://...&quot;"></textarea>
      <button id="phish-analyze-btn" class="btn-analyze">⚡ Analyze for Phishing</button>
      <div id="phish-result"></div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════
       TAB 3 — APK
  ═══════════════════════════════════════ -->
  <div id="tab-panel-apk" class="tab-content hidden">
    <div class="apk-panel">
      <h3>APK Shield AI</h3>
      <p class="tab-desc">Enter an Android app name and its requested permissions. Shadow AI will flag dangerous combos and spyware patterns.</p>
      <div class="input-group">
        <label class="sm-label">App Name</label>
        <input id="apk-name-input" class="sm-input" type="text" placeholder="e.g. Super Calculator, Flashlight Pro"/>
      </div>
      <div class="input-group">
        <label class="sm-label">Permissions (comma-separated)</label>
        <textarea id="apk-perms-textarea" class="sm-textarea" style="min-height:80px;" placeholder="e.g. READ_SMS, RECORD_AUDIO, ACCESS_FINE_LOCATION, CAMERA, READ_CONTACTS"></textarea>
      </div>
      <button id="apk-scan-btn" class="btn-analyze">🔍 Scan APK Permissions</button>
      <div id="apk-result"></div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════
       TAB 4 — BREACH
  ═══════════════════════════════════════ -->
  <div id="tab-panel-breach" class="tab-content hidden">
    <div class="breach-panel">
      <h3>Breach Radar</h3>
      <p class="tab-desc">Check if your email has been exposed in known data breaches. Try <strong style="color:#a78bfa">test@example.com</strong> for a demo.</p>
      <label class="sm-label">Email Address</label>
      <input id="breach-email-input" class="sm-input" type="email" placeholder="your@email.com"/>
      <button id="breach-check-btn" class="btn-analyze">🔓 Check Breaches</button>
      <div id="breach-result"></div>
    </div>
  </div>

  <!-- ═══════════════════════════════════════
       TAB 5 — CHAT
  ═══════════════════════════════════════ -->
  <div id="tab-panel-chat" class="tab-content chat-panel hidden" style="padding:0;">
    <div id="chat-messages" class="chat-messages">
      <!-- Initial message inserted by JS -->
    </div>
    <div class="chat-input-row">
      <input id="chat-input" class="chat-input" type="text" placeholder="Ask Shadow AI anything..."/>
      <button id="chat-send-btn" class="btn-send">↑</button>
    </div>
    <!-- Resize handle -->
    <div class="resize-handle"></div>
  </div>
</div>

`;

    shadow.appendChild(container);
    document.body.appendChild(root);
    
    const wrapper = shadow.querySelector('.wrapper');
    initInteractivity(shadow, wrapper);
    
    window.currentScanData = null;

    // ──────────────────────────────────────────────────
    // TAB BAR LISTENERS
    // ──────────────────────────────────────────────────
    ['scan','phish','apk','breach','chat'].forEach(t => {
        shadow.getElementById(`tab-btn-${t}`).addEventListener('click', () => switchTabInShadow(shadow, t));
    });

    function switchTabInShadow(shadow, tabName) {
        ['scan','phish','apk','breach','chat'].forEach(t => {
            shadow.getElementById(`tab-btn-${t}`).classList.toggle('active', t === tabName);
            shadow.getElementById(`tab-panel-${t}`).classList.toggle('hidden', t !== tabName);
        });
        if (tabName === 'chat') {
            const msgs = shadow.getElementById('chat-messages');
            if (msgs) setTimeout(() => msgs.scrollTop = msgs.scrollHeight, 50);
        }
    }

    // ──────────────────────────────────────────────────
    // CLOSE BUTTON
    // ──────────────────────────────────────────────────
    shadow.getElementById('sm-close-btn').addEventListener('click', () => {
        document.getElementById('shadowmap-overlay-root').style.display = 'none';
        overlayActive = false;
    });

    // ──────────────────────────────────────────────────
    // SCAN TAB — sub-view navigation
    // ──────────────────────────────────────────────────
    function showScanSubview(name) {
        ['scan-main-actions','protection-center-view','block-confirm-view','detailed-analysis-view'].forEach(id => {
            shadow.getElementById(id)?.classList.add('hidden');
        });
        if (name) shadow.getElementById(name)?.classList.remove('hidden');
    }

    shadow.getElementById('sm-protect-btn').addEventListener('click', () => {
        showScanSubview('protection-center-view');
        const data = window.currentScanData || {};
        shadow.getElementById('pc-phish-val').textContent = (data.phishing_probability || 0) + '%';
        shadow.getElementById('pc-spoof-val').textContent = (data.domain_spoof_probability || 0) + '%';
        shadow.getElementById('pc-cred-val').textContent = (data.credential_risk || 0) + '%';
        shadow.getElementById('pc-redirect-val').textContent = (data.redirect_risk || 0) + '%';
        updateProtCenter(shadow, data);
    });

    shadow.getElementById('sm-block-btn').addEventListener('click', () => showScanSubview('block-confirm-view'));
    shadow.getElementById('sm-copy-btn').addEventListener('click', copySecurityReport);

    shadow.getElementById('pc-btn-close').addEventListener('click', () => showScanSubview('scan-main-actions'));
    shadow.getElementById('pc-btn-copy').addEventListener('click', copySecurityReport);
    shadow.getElementById('pc-btn-block').addEventListener('click', () => showScanSubview('block-confirm-view'));
    shadow.getElementById('pc-btn-analysis').addEventListener('click', () => {
        showScanSubview('detailed-analysis-view');
        renderDetailedAnalysis(shadow);
    });
    shadow.getElementById('bc-btn-cancel').addEventListener('click', () => showScanSubview('scan-main-actions'));
    shadow.getElementById('bc-btn-confirm').addEventListener('click', blockCurrentSite);
    shadow.getElementById('da-btn-back').addEventListener('click', () => showScanSubview('protection-center-view'));

    // ──────────────────────────────────────────────────
    // TAB 2 — PHISHGUARD
    // ──────────────────────────────────────────────────
    shadow.getElementById('phish-analyze-btn').addEventListener('click', () => {
        const text = shadow.getElementById('phish-textarea').value.trim();
        if (!text) { highlightEmpty(shadow.getElementById('phish-textarea')); return; }
        const btn = shadow.getElementById('phish-analyze-btn');
        const resultEl = shadow.getElementById('phish-result');
        btn.disabled = true; btn.textContent = '⏳ Analyzing...';
        resultEl.innerHTML = loadingHTML('PhishGuard AI scanning...');

        fetch(`${BACKEND}/api/phishguard`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({text})
        })
        .then(r => r.json())
        .then(data => {
            btn.disabled = false; btn.textContent = '⚡ Analyze for Phishing';
            if (data.status === 'success') renderPhishResult(shadow, data.result);
            else resultEl.innerHTML = errorHTML('Analysis failed. Is the backend running?');
        })
        .catch(e => {
            btn.disabled = false; btn.textContent = '⚡ Analyze for Phishing';
            resultEl.innerHTML = errorHTML('Cannot reach backend. Start the Flask server.');
        });
    });

    // ──────────────────────────────────────────────────
    // TAB 3 — APK SHIELD
    // ──────────────────────────────────────────────────
    shadow.getElementById('apk-scan-btn').addEventListener('click', () => {
        const appName = shadow.getElementById('apk-name-input').value.trim() || 'Unknown App';
        const perms = shadow.getElementById('apk-perms-textarea').value.trim();
        if (!perms) { highlightEmpty(shadow.getElementById('apk-perms-textarea')); return; }
        const btn = shadow.getElementById('apk-scan-btn');
        const resultEl = shadow.getElementById('apk-result');
        btn.disabled = true; btn.textContent = '🔍 Scanning...';
        resultEl.innerHTML = loadingHTML('APK Shield scanning permissions...');

        fetch(`${BACKEND}/api/apkshield`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({app_name: appName, permissions: perms})
        })
        .then(r => r.json())
        .then(data => {
            btn.disabled = false; btn.textContent = '🔍 Scan APK Permissions';
            if (data.status === 'success') renderApkResult(shadow, data.result);
            else resultEl.innerHTML = errorHTML('Scan failed. Is the backend running?');
        })
        .catch(() => {
            btn.disabled = false; btn.textContent = '🔍 Scan APK Permissions';
            resultEl.innerHTML = errorHTML('Cannot reach backend. Start the Flask server.');
        });
    });

    // ──────────────────────────────────────────────────
    // TAB 4 — BREACH RADAR
    // ──────────────────────────────────────────────────
    shadow.getElementById('breach-check-btn').addEventListener('click', () => {
        const email = shadow.getElementById('breach-email-input').value.trim();
        if (!email || !email.includes('@')) { highlightEmpty(shadow.getElementById('breach-email-input')); return; }
        const btn = shadow.getElementById('breach-check-btn');
        const resultEl = shadow.getElementById('breach-result');
        btn.disabled = true; btn.textContent = '⏳ Checking...';
        resultEl.innerHTML = loadingHTML('Scanning breach database...');

        fetch(`${BACKEND}/api/breach`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({email})
        })
        .then(r => r.json())
        .then(data => {
            btn.disabled = false; btn.textContent = '🔓 Check Breaches';
            if (data.status === 'success') renderBreachResult(shadow, data.result);
            else resultEl.innerHTML = errorHTML('Check failed. Is the backend running?');
        })
        .catch(() => {
            btn.disabled = false; btn.textContent = '🔓 Check Breaches';
            resultEl.innerHTML = errorHTML('Cannot reach backend. Start the Flask server.');
        });
    });

    shadow.getElementById('breach-email-input').addEventListener('keydown', e => {
        if (e.key === 'Enter') shadow.getElementById('breach-check-btn').click();
    });

    // ──────────────────────────────────────────────────
    // TAB 5 — SHADOW CHAT
    // ──────────────────────────────────────────────────
    const chatMessages = shadow.getElementById('chat-messages');

    // Seed first AI message
    appendChatBubble(chatMessages, 'ai', "Hi! I'm Shadow 👋 — your AI cybersecurity copilot. Ask me about any threat, phishing scam, data breach, or suspicious website. I'm here to help!");

    function sendChatMessage() {
        const input = shadow.getElementById('chat-input');
        const msg = input.value.trim();
        if (!msg) return;
        input.value = '';

        appendChatBubble(chatMessages, 'user', msg);
        window.chatHistory.push({role: 'user', content: msg});

        const sendBtn = shadow.getElementById('chat-send-btn');
        sendBtn.disabled = true;

        // Typing indicator
        const typingEl = document.createElement('div');
        typingEl.className = 'typing-indicator';
        typingEl.innerHTML = '<div class="dot"></div><div class="dot"></div><div class="dot"></div>';
        chatMessages.appendChild(typingEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;

        fetch(`${BACKEND}/api/chat`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({
                message: msg,
                context: window.currentScanData || {},
                history: window.chatHistory.slice(-10)
            })
        })
        .then(r => r.json())
        .then(data => {
            chatMessages.removeChild(typingEl);
            sendBtn.disabled = false;
            const reply = data.reply || "Sorry, I couldn't get a response. Try again.";
            appendChatBubble(chatMessages, 'ai', reply);
            window.chatHistory.push({role: 'ai', content: reply});
        })
        .catch(() => {
            chatMessages.removeChild(typingEl);
            sendBtn.disabled = false;
            appendChatBubble(chatMessages, 'ai', "⚠️ Can't reach backend. Make sure Flask is running on port 5000.");
        });
    }

    shadow.getElementById('chat-send-btn').addEventListener('click', sendChatMessage);
    shadow.getElementById('chat-input').addEventListener('keydown', e => { if (e.key === 'Enter') sendChatMessage(); });

    document.body.appendChild(root);
}

// =============================================================================
// RENDER HELPERS
// =============================================================================

function loadingHTML(text) {
    return `<div class="loading-row"><div class="spinner"></div><span class="loading-text">${text}</span></div>`;
}

function errorHTML(text) {
    return `<div class="result-card" style="border-color:rgba(239,68,68,.3);"><div style="color:#fca5a5;font-size:12px;">⚠️ ${text}</div></div>`;
}

function highlightEmpty(el) {
    el.style.borderColor = 'rgba(239,68,68,.6)';
    el.focus();
    setTimeout(() => el.style.borderColor = '', 1500);
}

function appendChatBubble(container, role, text) {
    const bubble = document.createElement('div');
    bubble.className = `chat-bubble ${role}`;
    if (role === 'ai') {
        bubble.innerHTML = `<div class="bubble-name">Shadow AI</div>${escapeHTML(text)}`;
    } else {
        bubble.textContent = text;
    }
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

function escapeHTML(str) {
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>');
}

function probabilityColor(v) {
    if (v >= 70) return '#ef4444';
    if (v >= 40) return '#f97316';
    if (v >= 15) return '#f59e0b';
    return '#10b981';
}

// ── Render Phish Result ──
function renderPhishResult(shadow, r) {
    const el = shadow.getElementById('phish-result');
    const prob = r.phishing_probability || 0;
    const cls = (r.classification || 'SAFE').toLowerCase().replace('_','_');
    const clsMap = { phishing:'class-phishing', suspicious:'class-suspicious', low_risk:'class-low_risk', safe:'class-safe' };
    const indicators = (r.indicators || []).map(i => `<li>${escapeHTML(String(i))}</li>`).join('');
    el.innerHTML = `
    <div class="result-card">
      <div class="result-header">
        <span class="result-title">PhishGuard Analysis</span>
        <span class="class-badge ${clsMap[cls] || 'class-safe'}">${r.classification || 'SAFE'}</span>
      </div>
      <div class="prob-bar-wrap">
        <div class="prob-bar-label">
          <span>Phishing Probability</span>
          <span class="prob-pct" style="color:${probabilityColor(prob)}">${prob}%</span>
        </div>
        <div class="prob-bar-track">
          <div id="phish-prob-bar" class="prob-bar-fill" style="background:${probabilityColor(prob)};"></div>
        </div>
      </div>
      ${indicators ? `<div class="section-label">🚩 Detected Indicators</div><ul class="indicators-list">${indicators}</ul>` : ''}
      ${r.eli12_explanation ? `<div class="eli12-box"><div class="eli12-label">⚡ Shadow Explains</div>${escapeHTML(r.eli12_explanation)}</div>` : ''}
    </div>`;
    // Animate bar
    requestAnimationFrame(() => {
        setTimeout(() => { shadow.getElementById('phish-prob-bar').style.width = prob + '%'; }, 50);
    });
}

// ── Render APK Result ──
function renderApkResult(shadow, r) {
    const el = shadow.getElementById('apk-result');
    const risk = r.risk_score || 0;
    const lvl = (r.risk_level || 'SAFE').toLowerCase();
    const lvlMap = { critical:'class-phishing', high:'class-suspicious', medium:'class-low_risk', low:'class-safe', safe:'class-safe' };

    const dangerPerms = (r.dangerous_permissions || []).map(p =>
        `<li class="perm-item danger"><span class="perm-icon">⚠</span><div><div class="perm-name">${p.permission}</div><div class="perm-reason">${p.reason||''}</div></div></li>`
    ).join('');
    const safePerms = (r.safe_permissions || []).slice(0,5).map(p =>
        `<li class="perm-item safe"><span class="perm-icon">✓</span><div><div class="perm-name">${p.permission}</div></div></li>`
    ).join('');
    const combos = (r.combo_flags || []).map(f => `<div class="combo-flag">${escapeHTML(String(f))}</div>`).join('');

    el.innerHTML = `
    <div class="result-card">
      <div class="result-header">
        <span class="result-title">${escapeHTML(r.app_name || 'App')} Risk</span>
        <span class="class-badge ${lvlMap[lvl] || 'class-safe'}">${r.risk_level || 'SAFE'}</span>
      </div>
      <div class="risk-gauge-wrap">
        <div class="risk-num" style="background:linear-gradient(135deg,${probabilityColor(risk)},${probabilityColor(Math.min(risk+20,100))});-webkit-background-clip:text;">${risk}</div>
        <div style="font-size:11px;color:#64748b;">/ 100 Risk Score</div>
      </div>
      ${combos ? `<div class="section-label">🔥 Danger Combos</div>${combos}` : ''}
      ${dangerPerms ? `<div class="section-label">🚨 Dangerous Permissions</div><ul class="perm-list">${dangerPerms}</ul>` : ''}
      ${safePerms ? `<div class="section-label">✅ Safe Permissions (${(r.safe_permissions||[]).length})</div><ul class="perm-list">${safePerms}</ul>` : ''}
      ${r.explanation ? `<div class="eli12-box"><div class="eli12-label">⚡ Shadow Explains</div>${escapeHTML(r.explanation)}</div>` : ''}
    </div>`;
}

// ── Render Breach Result ──
function renderBreachResult(shadow, r) {
    const el = shadow.getElementById('breach-result');
    if (!r.total_breaches) {
        el.innerHTML = `
        <div class="breach-clean">
          <div class="breach-clean-icon">🛡️</div>
          <div class="breach-clean-title">No Breaches Found</div>
          <div class="breach-clean-sub">${escapeHTML(r.email)} wasn't found in our breach database. Stay safe — use strong unique passwords.</div>
        </div>`;
        return;
    }
    const sevMap = { CRITICAL:'sev-critical', HIGH:'sev-high', MEDIUM:'sev-medium', LOW:'sev-low' };
    const breachItems = (r.breaches || []).map(b => {
        const dataTags = (b.data_exposed || []).map(d => `<span>${escapeHTML(String(d))}</span>`).join('');
        return `
        <div class="breach-item">
          <div class="breach-item-header">
            <span class="breach-source">${escapeHTML(b.source)}</span>
            <span class="sev-badge ${sevMap[b.severity]||'sev-low'}">${b.severity}</span>
          </div>
          <div class="breach-date">📅 ${escapeHTML(b.breach_date || 'Unknown date')}</div>
          <div class="breach-data" style="margin-top:5px;">${dataTags}</div>
          <div class="breach-rec">💡 ${escapeHTML(b.recommendation || '')}</div>
        </div>`;
    }).join('');

    el.innerHTML = `
    <div style="margin-top:12px;">
      <div style="font-size:13px;color:#fca5a5;font-weight:700;margin-bottom:2px;">⚠ ${r.total_breaches} Breach${r.total_breaches !== 1 ? 'es' : ''} Found</div>
      <div style="font-size:11px;color:#64748b;margin-bottom:10px;">${escapeHTML(r.email)}</div>
      ${breachItems}
      <div class="overall-rec">${escapeHTML(r.overall_recommendation || '')}</div>
    </div>`;
}

// ── Update Protection Center recs ──
function updateProtCenter(shadow, data) {
    const tl = data.threat_level || 'UNKNOWN';
    let recsHtml = '';
    if (tl === 'TRUSTED') recsHtml = '✅ Site appears safe. Continue browsing normally.';
    else if (tl === 'SAFE') recsHtml = '✅ Minor risks detected. Exercise normal caution.';
    else if (tl === 'SUSPICIOUS') recsHtml = '⚠️ Potential security concerns. Avoid entering sensitive info.';
    else if (tl === 'DANGEROUS') recsHtml = '🚨 High risk detected. Do not enter passwords. Leave immediately.';
    else if (tl === 'CRITICAL') recsHtml = '🚨 Phishing indicators confirmed. Credentials at risk. Leave NOW.';
    else recsHtml = '⚠️ Unknown status. Proceed with caution.';
    shadow.getElementById('pc-recs').innerHTML = recsHtml;
}

// ── Render Detailed Analysis ──
function renderDetailedAnalysis(shadow) {
    const data = window.currentScanData || {};
    shadow.getElementById('da-domain').textContent = data.domain || window.location.hostname;
    shadow.getElementById('da-threat').textContent = data.threat_level || 'UNKNOWN';
    shadow.getElementById('da-shadow').textContent = data.shadow_score || '0';
    shadow.getElementById('da-trust').textContent = (100 - (data.exposure_score || 0)) + '';
    shadow.getElementById('da-risk').textContent = (100 - (data.shadow_score || 0)) + '';
    shadow.getElementById('da-exposure').textContent = (data.exposure_score || 0) + '';

    const reasonsList = shadow.getElementById('da-reasons');
    reasonsList.innerHTML = '';
    (data.reasons || ['No specific reasons provided']).forEach(r => {
        const li = document.createElement('li'); li.textContent = r; reasonsList.appendChild(li);
    });

    const actionsList = shadow.getElementById('da-actions');
    actionsList.innerHTML = '';
    (data.recommended_actions || ['Exercise normal caution']).forEach(a => {
        const li = document.createElement('li'); li.textContent = a; actionsList.appendChild(li);
    });

    const breakdown = shadow.getElementById('da-breakdown');
    breakdown.innerHTML = '';
    const risks = [
        {label:'Phishing Risk', val: data.phishing_probability || 0},
        {label:'Domain Spoof Risk', val: data.domain_spoof_probability || 0},
        {label:'Credential Risk', val: data.credential_risk || 0},
        {label:'Redirect Risk', val: data.redirect_risk || 0}
    ];
    risks.forEach(risk => {
        const color = probabilityColor(risk.val);
        breakdown.innerHTML += `
        <div style="display:flex;justify-content:space-between;font-size:11px;color:#94a3b8;margin-top:5px;">
            <span>${risk.label}</span><span style="color:${color};font-family:'JetBrains Mono',monospace;">${risk.val}%</span>
        </div>
        <div style="width:100%;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden;margin-bottom:5px;">
            <div style="width:${risk.val}%;height:100%;background:${color};border-radius:3px;transition:width .8s;"></div>
        </div>`;
    });
}

// =============================================================================
// UPDATE SCAN TAB UI (called after scan result)
// =============================================================================

function updateScanTabUI(data) {
    const overlay = document.getElementById("shadowmap-overlay-root");
    if (!overlay) return;
    const shadow = overlay.shadowRoot;

    console.log("FULL RESULT", data);
    
    // Add 1-5% UI baseline noise for trusted sites returning exactly 0
    data.phishing_probability = Math.max(data.phishing_probability || 0, Math.floor(Math.random() * 5) + 1);
    data.domain_spoof_probability = Math.max(data.domain_spoof_probability || 0, Math.floor(Math.random() * 5) + 1);
    data.credential_risk = Math.max(data.credential_risk || 0, Math.floor(Math.random() * 5) + 1);
    data.redirect_risk = Math.max(data.redirect_risk || 0, Math.floor(Math.random() * 5) + 1);

    console.log("PHISHING", data.phishing_probability);
    console.log("SPOOF", data.domain_spoof_probability);
    console.log("CREDENTIAL", data.credential_risk);
    console.log("REDIRECT", data.redirect_risk);

    const shadowScore = data.shadow_score !== undefined ? data.shadow_score : 0;
    const exposure = data.exposure_score !== undefined ? data.exposure_score : 0;
    const threatLevel = data.threat_level || "UNKNOWN";
    const displayDomain = data.url || data.domain || window.location.href || "Unknown";

    window.currentScanData = data;

    shadow.getElementById("sm-domain").textContent = displayDomain;
    shadow.getElementById("sm-score").textContent = shadowScore;
    shadow.getElementById("sm-exposure").textContent = exposure + "%";

    // Animate ring
    const circumference = 264;
    const offset = circumference - (shadowScore / 100) * circumference;
    const ring = shadow.getElementById("sm-ring-circle");
    ring.setAttribute("stroke", "url(#ring-grad)");
    // Force reflow for animation
    ring.style.transition = "none";
    ring.style.strokeDashoffset = "264";
    requestAnimationFrame(() => {
        ring.style.transition = "stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)";
        ring.style.strokeDashoffset = String(offset);
    });

    // Colors based on score
    const stop1 = shadow.getElementById("ring-stop-1");
    const stop2 = shadow.getElementById("ring-stop-2");
    const scoreEl = shadow.getElementById("sm-score");
    let c1, c2, textColor;
    if (shadowScore >= 86) { c1="#10b981"; c2="#059669"; textColor="#10b981"; }
    else if (shadowScore >= 71) { c1="#06b6d4"; c2="#0891b2"; textColor="#06b6d4"; }
    else if (shadowScore >= 51) { c1="#f59e0b"; c2="#d97706"; textColor="#f59e0b"; }
    else if (shadowScore >= 31) { c1="#f97316"; c2="#ea580c"; textColor="#f97316"; }
    else { c1="#ef4444"; c2="#dc2626"; textColor="#ef4444"; }
    stop1.setAttribute("stop-color", c1);
    stop2.setAttribute("stop-color", c2);
    scoreEl.style.color = textColor;

    // Badge
    const badge = shadow.getElementById("sm-badge");
    badge.textContent = threatLevel;
    const badgeMap = { TRUSTED:'badge-trusted', SAFE:'badge-safe', SUSPICIOUS:'badge-suspicious', DANGEROUS:'badge-dangerous', CRITICAL:'badge-critical' };
    badge.className = 'threat-badge ' + (badgeMap[threatLevel] || 'badge-unknown');

    // Exposure Ring Animation
    const expOffset = 264 - (exposure / 100) * 264;
    const expRing = shadow.getElementById("sm-exp-ring-circle");
    if (expRing) {
        expRing.setAttribute("stroke", "url(#exp-ring-grad)");
        expRing.style.transition = "none";
        expRing.style.strokeDashoffset = "264";
        requestAnimationFrame(() => {
            expRing.style.transition = "stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)";
            expRing.style.strokeDashoffset = String(expOffset);
        });

        const eStop1 = shadow.getElementById("exp-ring-stop-1");
        const eStop2 = shadow.getElementById("exp-ring-stop-2");
        let ec1, ec2;
        if (exposure <= 25) { ec1="#d946ef"; ec2="#c026d3"; }
        else if (exposure <= 50) { ec1="#ec4899"; ec2="#db2777"; }
        else if (exposure <= 75) { ec1="#f43f5e"; ec2="#e11d48"; }
        else { ec1="#ef4444"; ec2="#dc2626"; }
        if (eStop1 && eStop2) {
            eStop1.setAttribute("stop-color", ec1);
            eStop2.setAttribute("stop-color", ec2);
        }
        const expEl = shadow.getElementById("sm-exposure");
        if (expEl) expEl.style.color = ec1;
    }

    // Pills
    function applyPill(pillId, valId, value) {
        const pill = shadow.getElementById(pillId);
        const span = shadow.getElementById(valId);
        if (!pill || !span) return;
        span.textContent = value + '%';
        const color = probabilityColor(value);
        span.style.color = color;
        pill.style.borderColor = color.replace(')', ',.3)').replace('rgb','rgba');
    }
    if (data.phishing_probability !== undefined) applyPill("pill-phishing","sm-phishing-val", data.phishing_probability);
    if (data.domain_spoof_probability !== undefined) applyPill("pill-spoof","sm-spoof-val", data.domain_spoof_probability);
    if (data.credential_risk !== undefined) applyPill("pill-cred","sm-cred-val", data.credential_risk);
    if (data.redirect_risk !== undefined) applyPill("pill-redirect","sm-redirect-val", data.redirect_risk);

    // AI explanation
    let rawText = data.ai_explanation || "Analysis complete. No specific threats detected.";
    rawText = rawText.replace(/\\n/g, '\n').replace(/\\r/g, '').replace(/\\/g, '');
    shadow.getElementById("sm-ai-explanation").textContent = rawText;
}

// =============================================================================
// COMPATIBILITY ALIAS
// =============================================================================

function updateOverlayUI(data) { updateScanTabUI(data); }

// =============================================================================
// INTERACTIVE ENGINE (DRAG & RESIZE)
// =============================================================================

function initInteractivity(shadow, wrapper) {
    let isDragging = false;
    let isResizing = false;
    let startX, startY, startW, startH, startTop, startLeft;

    const header = shadow.querySelector('.sm-header');
    const resizer = shadow.querySelector('.resize-handle');

    header.onmousedown = (e) => {
        isDragging = true;
        startX = e.clientX;
        startY = e.clientY;
        const rect = wrapper.getBoundingClientRect();
        startTop = rect.top;
        startLeft = rect.left;
        e.preventDefault();
    };

    resizer.onmousedown = (e) => {
        isResizing = true;
        startX = e.clientX;
        startY = e.clientY;
        startW = wrapper.offsetWidth;
        startH = wrapper.offsetHeight;
        e.preventDefault();
        e.stopPropagation();
    };

    window.addEventListener('mousemove', (e) => {
        if (isDragging) {
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            smState.top = Math.max(0, startTop + dy);
            smState.left = Math.max(0, startLeft + dx);
            smState.right = null; // Shift to fixed left/top coords
            wrapper.style.top = smState.top + 'px';
            wrapper.style.left = smState.left + 'px';
            wrapper.style.right = 'auto';
        }
        if (isResizing) {
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            smState.width = Math.max(320, startW + dx);
            smState.height = Math.max(200, startH + dy);
            wrapper.style.width = smState.width + 'px';
            wrapper.style.height = smState.height + 'px';
        }
    });

    window.addEventListener('mouseup', () => {
        if (isDragging || isResizing) {
            isDragging = false;
            isResizing = false;
            saveState();
        }
    });
}

// =============================================================================
// STARTUP
// =============================================================================

function initShadowMap() {
    // Only inject in top-level frame to avoid multiple cockpits on one page
    if (window.top !== window.self) return;

    createFloatingButton();
    initSecurityObservers();
    loadState(() => {
        if (smState.isOpen) {
            // Delay slightly to ensure DOM is ready for Shadow Root insertion
            setTimeout(() => toggleOverlay(), 500); 
        }
    });
}

function initSecurityObservers() {
    // 1. DOM Mutation Observer
    const observer = new MutationObserver((mutations) => {
        let maliciousMutationDetected = false;
        mutations.forEach(mutation => {
            if (mutation.type === 'attributes') {
                const el = mutation.target;
                if (el.tagName === 'FORM' && mutation.attributeName === 'action') {
                    const newAction = el.getAttribute('action');
                    if (newAction && !newAction.startsWith('/') && !newAction.includes(window.location.hostname)) {
                        const warning = `Form action mutated dynamically to: ${newAction}`;
                        if (!smDetectedMutations.includes(warning)) {
                            smDetectedMutations.push(warning);
                            maliciousMutationDetected = true;
                        }
                    }
                }
                if (el.tagName === 'A' && mutation.attributeName === 'href') {
                    const newHref = el.getAttribute('href');
                    if (newHref && !newHref.startsWith('/') && !newHref.includes(window.location.hostname) && !newHref.startsWith('javascript')) {
                        const warning = `Link mutated dynamically to: ${newHref}`;
                        if (!smDetectedMutations.includes(warning)) {
                            smDetectedMutations.push(warning);
                        }
                    }
                }
            }
        });
        
        if (maliciousMutationDetected && overlayActive) {
            chrome.runtime.sendMessage({ type: "GET_CURRENT_SCAN", payload: extractPageData() });
        }
    });
    
    observer.observe(document.body, { attributes: true, subtree: true, attributeFilter: ['action', 'href'] });

    // 2. Password Leak Checker (k-Anonymity) with Debounce
    let smPwdTimeout;
    document.addEventListener('input', (e) => {
        if (e.target && e.target.tagName === 'INPUT' && e.target.type === 'password') {
            clearTimeout(smPwdTimeout);
            smPwdTimeout = setTimeout(async () => {
                const pwd = e.target.value;
                if (!pwd || pwd.length < 4) return;
                try {
                    const msgBuffer = new TextEncoder().encode(pwd);
                    const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
                    const prefix = hashHex.substring(0, 5);
                    const suffix = hashHex.substring(5);
                    
                    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
                    const text = await res.text();
                    const lines = text.split('\n');
                    for (let line of lines) {
                        if (line.startsWith(suffix)) {
                            const count = parseInt(line.split(':')[1].trim());
                            if (count > 0) {
                                const warning = `Password found in ${count} breaches!`;
                                if (!smPasswordLeaks.includes(warning)) {
                                    smPasswordLeaks.push(warning);
                                    if (overlayActive) chrome.runtime.sendMessage({ type: "GET_CURRENT_SCAN", payload: extractPageData() });
                                    
                                    const alertEl = document.createElement('div');
                                    alertEl.textContent = `⚠️ ShadowMap Alert: This password has been exposed in ${count} data breaches. Change it immediately.`;
                                    alertEl.style.cssText = "color:#ef4444;font-size:12px;margin-top:4px;font-weight:bold;font-family:sans-serif;";
                                    e.target.parentNode.insertBefore(alertEl, e.target.nextSibling);
                                }
                            }
                            break;
                        }
                    }
                } catch (err) {
                    console.error("ShadowMap Pwned Check Error", err);
                }
            }, 1000); // 1-second debounce
        }
    }, true);
}

// =============================================================================
// DRAG AND DROP SANDBOX
// =============================================================================
function setupDragAndDrop() {
    const overlay = document.getElementById('shadowmap-overlay-root');
    if (!overlay) return;
    const shadow = overlay.shadowRoot;
    
    const phishPanel = shadow.querySelector('.phish-panel');
    const apkPanel = shadow.querySelector('.apk-panel');
    
    function makeDroppable(panel, onDrop) {
        if (!panel) return;
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            panel.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            panel.addEventListener(eventName, () => {
                panel.style.border = '2px dashed #22D3EE';
                panel.style.backgroundColor = 'rgba(34, 211, 238, 0.05)';
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            panel.addEventListener(eventName, () => {
                panel.style.border = 'none';
                panel.style.backgroundColor = 'transparent';
            }, false);
        });

        panel.addEventListener('drop', (e) => {
            let dt = e.dataTransfer;
            let files = dt.files;
            if (files.length > 0) onDrop(files[0]);
            else {
                let text = dt.getData('text');
                if (text) onDrop({ type: 'text', content: text });
            }
        }, false);
    }
    
    makeDroppable(phishPanel, (file) => {
        const textArea = shadow.getElementById('phish-textarea');
        if (file.type === 'text') {
            textArea.value = file.content;
            shadow.getElementById('phish-scan-btn').click();
        } else {
            const reader = new FileReader();
            reader.onload = (e) => {
                textArea.value = e.target.result;
                shadow.getElementById('phish-scan-btn').click();
            };
            reader.readAsText(file);
        }
    });
    
    makeDroppable(apkPanel, (file) => {
        const appInput = shadow.getElementById('apk-name-input');
        const permsInput = shadow.getElementById('apk-perms-textarea');
        if (file.type !== 'text') {
            appInput.value = file.name.replace('.apk', '');
            if (!permsInput.value) {
                permsInput.value = "READ_EXTERNAL_STORAGE\nINTERNET\nACCESS_NETWORK_STATE"; // mock generic permissions
            }
            shadow.getElementById('apk-scan-btn').click();
        } else {
            permsInput.value = file.content;
        }
    });
}
setTimeout(setupDragAndDrop, 2000);

initShadowMap();
