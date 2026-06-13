// ShadowMap Content Script

console.log("SHADOWMAP CONTENT SCRIPT LOADED");

let overlayActive = false;

// =========================
// BLOCKING LOGIC
// =========================

function checkBlockedSite() {
    chrome.storage.local.get(['blockedDomains'], function(result) {
        const domains = result.blockedDomains || [];
        if (domains.includes(window.location.hostname)) {
            document.body.innerHTML = `
                <div style="position:fixed;top:0;left:0;width:100vw;height:100vh;background:#0f1219;z-index:2147483647;display:flex;flex-direction:column;justify-content:center;align-items:center;color:white;font-family:sans-serif;text-align:center;">
                    <h1 style="color:#ef4444;font-size:48px;margin-bottom:10px;">🚫 Website Blocked</h1>
                    <p style="font-size:24px;margin-bottom:20px;">This site was blocked by ShadowMap.</p>
                    <p style="font-size:18px;color:#cbd5e1;margin-bottom:40px;">Domain: ${window.location.hostname}<br>Reason: User blocked this site.</p>
                    <div style="display:flex;gap:20px;">
                        <button onclick="window.history.back()" style="padding:15px 30px;font-size:18px;background:transparent;border:2px solid #3b82f6;color:#3b82f6;border-radius:8px;cursor:pointer;">Go Back</button>
                        <button id="sm-unblock-page-btn" style="padding:15px 30px;font-size:18px;background:#ef4444;border:none;color:white;border-radius:8px;cursor:pointer;">Unblock Site</button>
                    </div>
                </div>
            `;
            document.getElementById('sm-unblock-page-btn').addEventListener('click', unblockCurrentSite);
        }
    });
}
checkBlockedSite();

// =========================
// HELPER FUNCTIONS
// =========================

function blockCurrentSite() {
    const domain = window.location.hostname;
    chrome.storage.local.get(['blockedDomains'], function(result) {
        let domains = result.blockedDomains || [];
        if (!domains.includes(domain)) {
            domains.push(domain);
            chrome.storage.local.set({ blockedDomains: domains }, function() {
                const root = document.getElementById("shadowmap-overlay-root");
                if (root) {
                    const btn = root.shadowRoot.getElementById("bc-btn-confirm");
                    if (btn) btn.textContent = "✓ Site blocked";
                }
                setTimeout(() => {
                    location.reload();
                }, 1000);
            });
        }
    });
}

function unblockCurrentSite() {
    const domain = window.location.hostname;
    chrome.storage.local.get(['blockedDomains'], function(result) {
        let domains = result.blockedDomains || [];
        domains = domains.filter(d => d !== domain);
        chrome.storage.local.set({ blockedDomains: domains }, function() {
            const btn = document.getElementById('sm-unblock-page-btn');
            if (btn) btn.textContent = "✓ Site unblocked";
            setTimeout(() => {
                location.reload();
            }, 1000);
        });
    });
}

function copySecurityReport() {
    const data = window.currentScanData;
    if (!data) return;
    
    let report = `ShadowMap Security Report\n\n`;
    report += `Domain: ${data.domain || window.location.hostname}\n`;
    report += `Threat Level: ${data.threat_level || "UNKNOWN"}\n`;
    report += `ShadowScore: ${data.shadow_score || 0}\n\n`;
    report += `Phishing Risk: ${data.phishing_probability || 0}%\n`;
    report += `Domain Spoof Risk: ${data.domain_spoof_probability || 0}%\n`;
    report += `Credential Risk: ${data.credential_risk || 0}%\n`;
    report += `Redirect Risk: ${data.redirect_risk || 0}%\n\n`;
    report += `Reasons:\n`;
    (data.reasons || []).forEach(r => report += `* ${r}\n`);
    report += `\nRecommended Actions:\n`;
    (data.recommended_actions || []).forEach(a => report += `* ${a}\n`);
    
    navigator.clipboard.writeText(report).then(() => {
        const root = document.getElementById("shadowmap-overlay-root");
        if (root) {
            const btn = root.shadowRoot.getElementById("pc-btn-copy");
            if (btn) {
                btn.textContent = "✓ Report copied";
                setTimeout(() => btn.textContent = "Copy Report", 2000);
            }
        }
    });
}

function renderDetailedAnalysis() {
    const shadow = document.getElementById("shadowmap-overlay-root").shadowRoot;
    shadow.getElementById("protection-center-view").classList.add("hidden");
    
    const btn = shadow.getElementById("pc-btn-analysis");
    btn.textContent = "Loading...";
    
    setTimeout(() => {
        btn.textContent = "Detailed Analysis";
        shadow.getElementById("detailed-analysis-view").classList.remove("hidden");
        
        const data = window.currentScanData || {};
        shadow.getElementById("da-domain").textContent = data.domain || window.location.hostname;
        shadow.getElementById("da-threat").textContent = data.threat_level || "UNKNOWN";
        shadow.getElementById("da-shadow").textContent = data.shadow_score || "0";
        shadow.getElementById("da-trust").textContent = (100 - (data.exposure_score || 0)) || "0";
        shadow.getElementById("da-risk").textContent = (100 - (data.shadow_score || 0)) || "0";
        shadow.getElementById("da-exposure").textContent = (data.exposure_score !== undefined ? data.exposure_score : "0");
        
        const reasonsList = shadow.getElementById("da-reasons");
        reasonsList.innerHTML = "";
        (data.reasons || ["No specific reasons provided"]).forEach(r => {
            const li = document.createElement("li");
            li.textContent = r;
            reasonsList.appendChild(li);
        });
        
        const actionsList = shadow.getElementById("da-actions");
        actionsList.innerHTML = "";
        (data.recommended_actions || ["Exercise normal caution"]).forEach(a => {
            const li = document.createElement("li");
            li.textContent = a;
            actionsList.appendChild(li);
        });

        const breakdown = shadow.getElementById("da-breakdown");
        breakdown.innerHTML = "";
        const risks = [
            { label: "Phishing Risk", val: data.phishing_probability || 0 },
            { label: "Domain Spoof Risk", val: data.domain_spoof_probability || 0 },
            { label: "Credential Risk", val: data.credential_risk || 0 },
            { label: "Redirect Risk", val: data.redirect_risk || 0 }
        ];
        
        risks.forEach(risk => {
            let color = "#22c55e"; // low green
            if (risk.val > 25) color = "#eab308"; // medium yellow
            if (risk.val > 75) color = "#ef4444"; // high red
            
            breakdown.innerHTML += `
                <div style="display:flex;align-items:center;justify-content:space-between;font-size:12px;margin-top:4px;">
                    <span>${risk.label}</span>
                    <span>${risk.val}%</span>
                </div>
                <div style="width:100%;height:6px;background:rgba(255,255,255,0.1);border-radius:3px;overflow:hidden;margin-bottom:6px;">
                    <div style="width:${risk.val}%;height:100%;background:${color};"></div>
                </div>
            `;
        });
    }, 400); // Simulate loading time for UX
}

function updateProtectionCenter(data) {
    const shadow = document.getElementById("shadowmap-overlay-root").shadowRoot;
    const tl = data.threat_level || "UNKNOWN";
    let recsHtml = "";
    
    if (tl === "TRUSTED") {
        recsHtml = "✓ Site appears safe<br>✓ Continue browsing normally";
    } else if (tl === "SAFE") {
        recsHtml = "✓ Minor risks detected<br>✓ Exercise normal caution";
    } else if (tl === "WARNING") {
        recsHtml = "⚠ Potential security concerns detected<br>⚠ Avoid entering sensitive information";
    } else if (tl === "DANGEROUS") {
        recsHtml = "🚨 High risk detected<br>🚨 Do not enter passwords<br>🚨 Leave immediately";
    } else if (tl === "CRITICAL") {
        recsHtml = "🚨 Phishing indicators detected<br>🚨 Credentials may be at risk<br>🚨 Leave site immediately";
    } else {
        recsHtml = "⚠ Unknown status. Proceed with caution.";
    }
    
    shadow.getElementById("pc-recs").innerHTML = recsHtml;
}

// =========================
// F4 HOTKEY
// =========================

window.addEventListener("keydown", (e) => {
    if (e.key === "F4") {
        e.preventDefault();
        toggleOverlay();
    }
});

// =========================
// MESSAGE LISTENER
// =========================
chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "TOGGLE_OVERLAY") {
        toggleOverlay();
    }
    if (message.type === "UPDATE_OVERLAY_DATA") {
        updateOverlayUI(message.data);
    }
});

// =========================
// FLOATING BUTTON
// =========================

function createFloatingButton() {
    if (document.getElementById("shadowmap-fab")) return;
    const btn = document.createElement("div");
    btn.id = "shadowmap-fab";
    btn.innerHTML = "🛡";
    btn.style.position = "fixed";
    btn.style.bottom = "25px";
    btn.style.right = "25px";
    btn.style.width = "68px";
    btn.style.height = "68px";
    btn.style.borderRadius = "50%";
    btn.style.display = "flex";
    btn.style.alignItems = "center";
    btn.style.justifyContent = "center";
    btn.style.fontSize = "32px";
    btn.style.cursor = "pointer";
    btn.style.zIndex = "2147483646";
    btn.style.background = "linear-gradient(135deg,#8B5CF6,#22D3EE)";
    btn.style.boxShadow = "0 0 25px rgba(139,92,246,.5),0 0 60px rgba(34,211,238,.25)";
    btn.style.transition = "all .25s ease";
    btn.addEventListener("mouseenter", () => btn.style.transform = "scale(1.08)");
    btn.addEventListener("mouseleave", () => btn.style.transform = "scale(1)");
    btn.addEventListener("click", toggleOverlay);
    document.body.appendChild(btn);
}

// =========================
// OVERLAY TOGGLE
// =========================

function toggleOverlay() {
    let overlay = document.getElementById("shadowmap-overlay-root");
    if (!overlay) {
        createOverlay();
        overlay = document.getElementById("shadowmap-overlay-root");
        overlayActive = true;
    } else {
        overlay.style.display = overlay.style.display === "none" ? "block" : "none";
        overlayActive = overlay.style.display === "block";
        // Reset view to dashboard whenever overlay is toggled
        if(overlayActive) {
            overlay.shadowRoot.getElementById("dashboard-view").classList.remove("hidden");
            overlay.shadowRoot.getElementById("protection-center-view").classList.add("hidden");
            overlay.shadowRoot.getElementById("detailed-analysis-view").classList.add("hidden");
            overlay.shadowRoot.getElementById("block-confirm-view").classList.add("hidden");
        }
    }
    if (overlayActive) {
        chrome.runtime.sendMessage({ type: "GET_CURRENT_SCAN", payload: extractPageData() });
    }
}

// =========================
// PAGE EXTRACTION
// =========================

function extractPageData() {
    const data = {
        url: window.location.href,
        hostname: window.location.hostname,
        title: document.title,
        trackers: [],
        forms: []
    };
    const scripts = document.querySelectorAll('script');
    const signatures = {
        'Google Analytics': 'google-analytics',
        'Google Tag Manager': 'googletagmanager.com',
        'Meta Pixel': 'fbevents.js',
        'TikTok Pixel': 'analytics.tiktok.com',
        'Hotjar': 'hotjar.com',
        'FingerprintJS': 'fingerprintjs'
    };
    scripts.forEach(script => {
        const content = script.src || script.innerText || "";
        for (const [name, sig] of Object.entries(signatures)) {
            if (content.toLowerCase().includes(sig.toLowerCase()) && !data.trackers.includes(name)) {
                data.trackers.push(name);
            }
        }
    });
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        data.forms.push({
            action: form.action,
            hasPassword: form.querySelector('input[type="password"]') !== null,
            inputs: form.querySelectorAll('input').length
        });
    });
    return data;
}

// =========================
// CREATE OVERLAY
// =========================

function createOverlay() {
    if (document.getElementById("shadowmap-overlay-root")) return;
    const root = document.createElement("div");
    root.id = "shadowmap-overlay-root";
    const shadow = root.attachShadow({ mode: "open" });
    const container = document.createElement("div");

    container.innerHTML = `
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400&display=swap');

.wrapper {
    position: fixed;
    top: 30px;
    right: 30px;
    width: 380px;
    background: linear-gradient(180deg, rgba(17,21,32,0.95) 0%, rgba(13,17,26,0.95) 100%);
    backdrop-filter: blur(25px);
    -webkit-backdrop-filter: blur(25px);
    border-radius: 16px;
    color: white;
    font-family: 'Inter', sans-serif;
    z-index: 2147483647;
    box-shadow: 0 30px 60px rgba(0,0,0,0.6), 0 0 100px rgba(99, 102, 241, 0.15), inset 0 1px 1px rgba(255,255,255,0.05);
    padding: 16px 20px;
    box-sizing: border-box;
}

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
}

.title {
    font-size: 15px;
    font-weight: 500;
    letter-spacing: 3px;
    color: #94a3b8;
    text-transform: uppercase;
}

.badge {
    margin-top: 10px;
    padding: 6px 16px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    transition: all 0.3s ease;
}
.badge-trusted {
    color: #22c55e;
    border: 1px solid rgba(34,197,94,.5);
    box-shadow: 0 0 15px rgba(34,197,94,.3);
    background: rgba(34,197,94,.1);
}
.badge-safe {
    color: #06b6d4;
    border: 1px solid rgba(6,182,212,.5);
    box-shadow: 0 0 15px rgba(6,182,212,.3);
    background: rgba(6,182,212,.1);
}
.badge-warning {
    color: #eab308;
    border: 1px solid rgba(234,179,8,.5);
    box-shadow: 0 0 15px rgba(234,179,8,.3);
    background: rgba(234,179,8,.1);
}
.badge-dangerous {
    color: #f97316;
    border: 1px solid rgba(249,115,22,.5);
    box-shadow: 0 0 15px rgba(249,115,22,.3);
    background: rgba(249,115,22,.1);
}
.badge-critical {
    color: #ef4444;
    border: 1px solid rgba(239,68,68,.5);
    box-shadow: 0 0 15px rgba(239,68,68,.3);
    background: rgba(239,68,68,.1);
}

.logo {
    width: 32px;
    height: 32px;
    position: relative;
    display: flex;
    justify-content: center;
    align-items: center;
}

.logo::before {
    content: '';
    position: absolute;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle, #8b5cf6 0%, #3b82f6 100%);
    opacity: 0.5;
    filter: blur(10px);
    border-radius: 50%;
}

.logo svg {
    position: relative;
    width: 20px;
    height: 20px;
    z-index: 2;
    filter: drop-shadow(0 0 5px rgba(139, 92, 246, 0.8));
}

.domain-container {
    text-align: center;
    margin-top: -5px;
    margin-bottom: 16px;
    width: 100%;
    display: block;
}

.domain {
    color: #f97316;
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-shadow: 0 0 12px rgba(249, 115, 22, 0.6);
    word-break: break-all;
    display: inline-block;
}

.dashboard-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    padding: 0 5px;
}

.score-column {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.score-ring-container {
    position: relative;
    width: 110px;
    height: 110px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.ring-svg {
    position: absolute;
    width: 100%;
    height: 100%;
    filter: drop-shadow(0 0 15px rgba(239, 68, 68, 0.4));
    transform: rotate(-90deg);
}

.score-content {
    position: relative;
    z-index: 2;
    text-align: center;
}

.score {
    font-size: 34px;
    font-weight: 600;
    color: #ffffff;
    line-height: 1.1;
}

.scoreLabel {
    font-size: 11px;
    color: #94a3b8;
}

.exposure-container {
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
}

.sphere-container {
    position: relative;
    width: 75px;
    height: 75px;
    margin-bottom: 12px;
}

.sphere {
    width: 100%;
    height: 100%;
    border-radius: 50%;
    background: radial-gradient(circle at 35% 35%, rgba(253, 186, 116, 0.9) 0%, rgba(220, 38, 38, 0.8) 40%, rgba(69, 10, 10, 0.95) 100%);
    box-shadow: inset -10px -10px 20px rgba(0,0,0,0.6), inset 10px 10px 20px rgba(255,255,255,0.3), 0 0 30px rgba(220, 38, 38, 0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
}

.sphere::after {
    content: '';
    position: absolute;
    top: 5%;
    left: 15%;
    width: 40%;
    height: 40%;
    background: radial-gradient(ellipse at center, rgba(255,255,255,0.4) 0%, transparent 70%);
    transform: rotate(-45deg);
    border-radius: 50%;
}

.exposure-value {
    font-size: 18px;
    font-weight: 600;
    color: white;
    text-shadow: 0 2px 4px rgba(0,0,0,0.5);
    z-index: 2;
    position: relative;
}

.exposure-label {
    font-size: 11px;
    color: #cbd5e1;
}

.pills-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    margin-bottom: 16px;
}

.pill {
    background: rgba(20, 15, 20, 0.7);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 6px;
    padding: 8px 10px;
    font-size: 11px;
    color: #e2e8f0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: all 0.3s ease;
    cursor: default;
}

.pill-icon {
    font-size: 12px;
    font-weight: 600;
    transition: all 0.3s ease;
}

.ai-card {
    position: relative;
    border-radius: 8px;
    padding: 2px;
    background: linear-gradient(135deg, rgba(168, 85, 247, 0.8), rgba(6, 182, 212, 0.8));
    margin-bottom: 16px;
    box-shadow: 0 0 25px rgba(168, 85, 247, 0.25);
    animation: borderGlow 4s ease-in-out infinite alternate;
}

@keyframes borderGlow {
    0% { box-shadow: 0 0 15px rgba(168, 85, 247, 0.2); }
    100% { box-shadow: 0 0 35px rgba(6, 182, 212, 0.4); }
}

.ai-card-inner {
    background: #0f1219;
    border-radius: 6px;
    padding: 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #e2e8f0;
    line-height: 1.5;
    white-space: pre-wrap;
    min-height: 60px;
}

.actions {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 12px;
}

.btn-primary, .btn-secondary {
    border: none;
    padding: 10px 16px;
    border-radius: 6px;
    font-size: 12px;
    cursor: pointer;
    font-family: 'Inter', sans-serif;
    transition: all 0.3s ease;
}

.btn-primary {
    background: linear-gradient(90deg, #8b5cf6, #3b82f6);
    color: white;
    font-weight: 500;
    box-shadow: 0 0 20px rgba(139, 92, 246, 0.4);
}

.btn-primary:hover {
    box-shadow: 0 0 30px rgba(139, 92, 246, 0.7);
    transform: scale(1.02);
}

.btn-secondary {
    background: transparent;
    color: #64748b;
}

.btn-secondary:hover {
    color: #cbd5e1;
}

.hidden {
    display: none !important;
}

.protection-center, .detailed-analysis, .block-confirm {
    display: flex;
    flex-direction: column;
    gap: 14px;
    animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.pc-title {
    font-size: 15px;
    font-weight: 600;
    color: #e2e8f0;
    text-align: center;
    margin-bottom: 0px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
    padding-bottom: 8px;
}

.pc-risks {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    background: rgba(0,0,0,0.3);
    padding: 10px;
    border-radius: 8px;
}

.pc-risk-item {
    font-size: 11px;
    color: #cbd5e1;
    display: flex;
    justify-content: space-between;
}

.pc-risk-val {
    font-weight: 600;
}

.pc-recs {
    background: rgba(139,92,246,0.1);
    border: 1px solid rgba(139,92,246,0.3);
    padding: 10px;
    border-radius: 8px;
    font-size: 11px;
    color: #e2e8f0;
    line-height: 1.5;
}

.pc-actions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
}

.btn-pc {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    color: #e2e8f0;
    padding: 8px;
    border-radius: 6px;
    font-size: 11px;
    cursor: pointer;
    transition: all 0.2s;
    font-family: 'Inter', sans-serif;
    text-align: center;
}
.btn-pc:hover {
    background: rgba(255,255,255,0.1);
}
.btn-pc.danger {
    background: rgba(239,68,68,0.1);
    border-color: rgba(239,68,68,0.3);
    color: #fca5a5;
}
.btn-pc.danger:hover {
    background: rgba(239,68,68,0.2);
}

.da-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    font-size: 11px;
    color: #cbd5e1;
    background: rgba(0,0,0,0.3);
    padding: 10px;
    border-radius: 8px;
}

</style>

<div class="wrapper">
    <div class="header">
        <div class="title">SHADOWMAP AI</div>
        <div class="logo">
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="url(#shield-grad)"/>
                <defs>
                    <linearGradient id="shield-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stop-color="#a78bfa" />
                        <stop offset="100%" stop-color="#3b82f6" />
                    </linearGradient>
                </defs>
            </svg>
        </div>
    </div>

    <div class="domain-container">
        <div id="sm-domain" class="domain">${window.location.hostname || "Unknown"}</div>
    </div>

    <!-- MAIN DASHBOARD VIEW -->
    <div id="dashboard-view">
        <div class="dashboard-row">
            <div class="score-column">
                <div class="score-ring-container">
                    <svg viewBox="0 0 100 100" class="ring-svg">
                        <circle cx="50" cy="50" r="42" fill="none" stroke="#2a1a1a" stroke-width="8" />
                        <circle id="sm-ring-circle" cx="50" cy="50" r="42" fill="none" stroke="url(#ring-grad)" stroke-width="8" stroke-dasharray="210 264" stroke-linecap="round" />
                        <defs>
                            <linearGradient id="ring-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop id="ring-stop-1" offset="0%" stop-color="#ef4444" />
                                <stop id="ring-stop-2" offset="100%" stop-color="#f97316" />
                            </linearGradient>
                        </defs>
                    </svg>
                    <div class="score-content">
                        <div id="sm-score" class="score">0</div>
                        <div class="scoreLabel">ShadowScore</div>
                    </div>
                </div>
                <div id="sm-badge" class="badge badge-danger">UNKNOWN</div>
            </div>

            <div class="exposure-container">
                <div class="sphere-container">
                    <div id="sm-sphere" class="sphere">
                        <div id="sm-exposure" class="exposure-value">0%</div>
                    </div>
                </div>
                <div class="exposure-label">Critical Exposure</div>
            </div>
        </div>

        <div class="pills-grid">
            <div id="pill-phishing" class="pill">
                <span>Phishing</span>
                <span id="sm-phishing-val" class="pill-icon">--%</span>
            </div>
            <div id="pill-spoof" class="pill">
                <span>Domain Spoof</span>
                <span id="sm-spoof-val" class="pill-icon">--%</span>
            </div>
            <div id="pill-cred" class="pill">
                <span>Credential Risk</span>
                <span id="sm-cred-val" class="pill-icon">--%</span>
            </div>
            <div id="pill-redirect" class="pill">
                <span>Malicious Redirect</span>
                <span id="sm-redirect-val" class="pill-icon">--%</span>
            </div>
        </div>

        <div class="ai-card">
            <div id="sm-ai-explanation" class="ai-card-inner">Analyzing website...</div>
        </div>

        <div class="actions">
            <button id="sm-protect-btn" class="btn-primary">Protect Me Now</button>
            <button id="sm-ignore-btn" class="btn-secondary">Ignore</button>
        </div>
    </div>

    <!-- PROTECTION CENTER VIEW -->
    <div id="protection-center-view" class="protection-center hidden">
        <div class="pc-title">ShadowMap Protection Center</div>
        <div class="pc-risks">
            <div class="pc-risk-item"><span>Phishing:</span> <span id="pc-phish-val" class="pc-risk-val">0%</span></div>
            <div class="pc-risk-item"><span>Spoofing:</span> <span id="pc-spoof-val" class="pc-risk-val">0%</span></div>
            <div class="pc-risk-item"><span>Credential:</span> <span id="pc-cred-val" class="pc-risk-val">0%</span></div>
            <div class="pc-risk-item"><span>Redirect:</span> <span id="pc-redirect-val" class="pc-risk-val">0%</span></div>
        </div>
        <div id="pc-recs" class="pc-recs">Generating recommendations...</div>
        <div class="pc-actions">
            <button id="pc-btn-copy" class="btn-pc">Copy Report</button>
            <button id="pc-btn-analysis" class="btn-pc">Detailed Analysis</button>
            <button id="pc-btn-block" class="btn-pc danger">Block Site</button>
            <button id="pc-btn-close" class="btn-pc">Close</button>
        </div>
    </div>

    <!-- BLOCK CONFIRMATION VIEW -->
    <div id="block-confirm-view" class="block-confirm hidden" style="text-align:center;">
        <h2 style="color:#ef4444;font-size:16px;margin:20px 0;">Block this website in ShadowMap?</h2>
        <div class="actions" style="margin-top:20px;">
            <button id="bc-btn-cancel" class="btn-secondary">Cancel</button>
            <button id="bc-btn-confirm" class="btn-primary" style="background:#ef4444;">Block Site</button>
        </div>
    </div>

    <!-- DETAILED ANALYSIS VIEW -->
    <div id="detailed-analysis-view" class="detailed-analysis hidden">
        <div class="pc-title">Detailed Analysis</div>
        <div class="da-grid">
            <div>Domain: <span id="da-domain" style="color:#f97316;"></span></div>
            <div>Threat Level: <span id="da-threat" style="font-weight:bold;"></span></div>
            <div>ShadowScore: <span id="da-shadow"></span></div>
            <div>Trust Score: <span id="da-trust"></span></div>
            <div>Risk Score: <span id="da-risk"></span></div>
            <div>Exposure Score: <span id="da-exposure"></span></div>
        </div>
        
        <div style="font-size:12px;font-weight:600;margin-top:2px;">Reasons:</div>
        <ul id="da-reasons" style="font-size:11px;color:#cbd5e1;padding-left:16px;margin:0;"></ul>
        
        <div style="font-size:12px;font-weight:600;margin-top:2px;">Recommended Actions:</div>
        <ul id="da-actions" style="font-size:11px;color:#cbd5e1;padding-left:16px;margin:0;"></ul>
        
        <div style="font-size:12px;font-weight:600;margin-top:2px;">Security Breakdown:</div>
        <div id="da-breakdown" style="display:flex;flex-direction:column;gap:4px;"></div>
        
        <button id="da-btn-back" class="btn-secondary" style="width:100%;border:1px solid rgba(255,255,255,0.1);margin-top:5px;">Back</button>
    </div>

    <div id="sm-progress-fill" class="hidden"></div>
</div>
`;
    shadow.appendChild(container);
    window.currentScanData = null;

    // EVENT LISTENERS
    shadow.getElementById("sm-protect-btn").addEventListener("click", () => {
        shadow.getElementById("dashboard-view").classList.add("hidden");
        shadow.getElementById("protection-center-view").classList.remove("hidden");
        const data = window.currentScanData || {};
        shadow.getElementById("pc-phish-val").textContent = (data.phishing_probability || 0) + "%";
        shadow.getElementById("pc-spoof-val").textContent = (data.domain_spoof_probability || 0) + "%";
        shadow.getElementById("pc-cred-val").textContent = (data.credential_risk || 0) + "%";
        shadow.getElementById("pc-redirect-val").textContent = (data.redirect_risk || 0) + "%";
        updateProtectionCenter(data);
    });

    shadow.getElementById("pc-btn-close").addEventListener("click", () => {
        shadow.getElementById("protection-center-view").classList.add("hidden");
        shadow.getElementById("dashboard-view").classList.remove("hidden");
    });
    
    shadow.getElementById("pc-btn-copy").addEventListener("click", copySecurityReport);
    
    shadow.getElementById("pc-btn-analysis").addEventListener("click", renderDetailedAnalysis);
    
    shadow.getElementById("pc-btn-block").addEventListener("click", () => {
        shadow.getElementById("protection-center-view").classList.add("hidden");
        shadow.getElementById("block-confirm-view").classList.remove("hidden");
    });
    
    shadow.getElementById("bc-btn-cancel").addEventListener("click", () => {
        shadow.getElementById("block-confirm-view").classList.add("hidden");
        shadow.getElementById("protection-center-view").classList.remove("hidden");
    });
    
    shadow.getElementById("bc-btn-confirm").addEventListener("click", blockCurrentSite);
    
    shadow.getElementById("da-btn-back").addEventListener("click", () => {
        shadow.getElementById("detailed-analysis-view").classList.add("hidden");
        shadow.getElementById("protection-center-view").classList.remove("hidden");
    });
    
    shadow.getElementById("sm-ignore-btn").addEventListener("click", toggleOverlay);

    document.body.appendChild(root);
}

// =========================
// UPDATE UI
// =========================

function updateOverlayUI(data) {
    const overlay = document.getElementById("shadowmap-overlay-root");
    if (!overlay) return;
    const shadow = overlay.shadowRoot;

    const shadowScore = data.shadow_score !== undefined ? data.shadow_score : 0;
    const exposure = data.exposure_score !== undefined ? data.exposure_score : 0;
    const threatLevel = data.threat_level || "UNKNOWN";
    const displayDomain = data.domain || data.url || window.location.hostname || "Unknown";
    
    shadow.getElementById("sm-domain").textContent = displayDomain;
    shadow.getElementById("sm-score").textContent = shadowScore;
    shadow.getElementById("sm-exposure").textContent = exposure + "%";
    
    window.currentScanData = data;

    // Update Badge
    const badge = shadow.getElementById("sm-badge");
    badge.textContent = threatLevel;
    badge.className = "badge"; 
    if (threatLevel === "TRUSTED") badge.classList.add("badge-trusted");
    else if (threatLevel === "SAFE") badge.classList.add("badge-safe");
    else if (threatLevel === "WARNING") badge.classList.add("badge-warning");
    else if (threatLevel === "DANGEROUS") badge.classList.add("badge-dangerous");
    else badge.classList.add("badge-critical");

    // Update Ring Gradient & Score Color
    const stop1 = shadow.getElementById("ring-stop-1");
    const stop2 = shadow.getElementById("ring-stop-2");
    const scoreEl = shadow.getElementById("sm-score");
    if (shadowScore >= 95) { 
        stop1.setAttribute("stop-color", "#22c55e"); stop2.setAttribute("stop-color", "#16a34a"); 
        scoreEl.style.color = "#22c55e";
    } else if (shadowScore >= 80) { 
        stop1.setAttribute("stop-color", "#06b6d4"); stop2.setAttribute("stop-color", "#0891b2"); 
        scoreEl.style.color = "#06b6d4";
    } else if (shadowScore >= 60) { 
        stop1.setAttribute("stop-color", "#eab308"); stop2.setAttribute("stop-color", "#ca8a04"); 
        scoreEl.style.color = "#eab308";
    } else if (shadowScore >= 40) { 
        stop1.setAttribute("stop-color", "#f97316"); stop2.setAttribute("stop-color", "#ea580c"); 
        scoreEl.style.color = "#f97316";
    } else { 
        stop1.setAttribute("stop-color", "#ef4444"); stop2.setAttribute("stop-color", "#dc2626"); 
        scoreEl.style.color = "#ef4444";
    }

    // Update Sphere Gradient based on Exposure
    const sphere = shadow.getElementById("sm-sphere");
    let sphereGradient = "";
    let sphereGlow = "";
    if (exposure <= 20) { // Green
        sphereGradient = "radial-gradient(circle at 35% 35%, rgba(134, 239, 172, 0.9) 0%, rgba(34, 197, 94, 0.8) 40%, rgba(5, 46, 22, 0.95) 100%)";
        sphereGlow = "0 0 30px rgba(34, 197, 94, 0.4)";
    } else if (exposure <= 50) { // Yellow
        sphereGradient = "radial-gradient(circle at 35% 35%, rgba(253, 224, 71, 0.9) 0%, rgba(234, 179, 8, 0.8) 40%, rgba(66, 32, 6, 0.95) 100%)";
        sphereGlow = "0 0 30px rgba(234, 179, 8, 0.4)";
    } else if (exposure <= 75) { // Orange
        sphereGradient = "radial-gradient(circle at 35% 35%, rgba(253, 186, 116, 0.9) 0%, rgba(249, 115, 22, 0.8) 40%, rgba(67, 20, 7, 0.95) 100%)";
        sphereGlow = "0 0 30px rgba(249, 115, 22, 0.4)";
    } else { // Red
        sphereGradient = "radial-gradient(circle at 35% 35%, rgba(252, 165, 165, 0.9) 0%, rgba(239, 68, 68, 0.8) 40%, rgba(69, 10, 10, 0.95) 100%)";
        sphereGlow = "0 0 30px rgba(239, 68, 68, 0.4)";
    }
    sphere.style.background = sphereGradient;
    sphere.style.boxShadow = `inset -10px -10px 20px rgba(0,0,0,0.6), inset 10px 10px 20px rgba(255,255,255,0.3), ${sphereGlow}`;

    // Helper for Pill colors
    function applyPillColor(pillId, valId, value) {
        const pill = shadow.getElementById(pillId);
        const valSpan = shadow.getElementById(valId);
        if (!pill || !valSpan) return;
        valSpan.textContent = value + "%";
        let color, border, bgHover;
        if (value <= 25) { color = "#22c55e"; border = "rgba(34,197,94,.5)"; bgHover = "rgba(34,197,94,.1)"; } 
        else if (value <= 50) { color = "#eab308"; border = "rgba(234,179,8,.5)"; bgHover = "rgba(234,179,8,.1)"; } 
        else if (value <= 75) { color = "#f97316"; border = "rgba(249,115,22,.5)"; bgHover = "rgba(249,115,22,.1)"; } 
        else { color = "#ef4444"; border = "rgba(239,68,68,.6)"; bgHover = "rgba(239,68,68,.1)"; }

        valSpan.style.color = color;
        pill.style.borderColor = border;
        pill.onmouseenter = () => {
            pill.style.background = bgHover;
            pill.style.transform = "translateY(-1px)";
            pill.style.boxShadow = `0 4px 12px ${color}26`;
        };
        pill.onmouseleave = () => {
            pill.style.background = "rgba(20, 15, 20, 0.7)";
            pill.style.transform = "translateY(0)";
            pill.style.boxShadow = "none";
        };
    }

    if (data.phishing_probability !== undefined) applyPillColor("pill-phishing", "sm-phishing-val", data.phishing_probability);
    if (data.domain_spoof_probability !== undefined) applyPillColor("pill-spoof", "sm-spoof-val", data.domain_spoof_probability);
    if (data.credential_risk !== undefined) applyPillColor("pill-cred", "sm-cred-val", data.credential_risk);
    if (data.redirect_risk !== undefined) applyPillColor("pill-redirect", "sm-redirect-val", data.redirect_risk);

    shadow.getElementById("sm-progress-fill").style.width = (data.risk_score || 0) + "%";
    
    // Fix escaping issues in AI explanation
    let rawText = data.ai_explanation || "No threats detected.";
    rawText = rawText.replace(/\\n/g, '\n').replace(/\\r/g, '').replace(/\\/g, '');
    shadow.getElementById("sm-ai-explanation").textContent = rawText;
}

// =========================
// STARTUP
// =========================

createFloatingButton();
