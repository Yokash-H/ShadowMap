// ShadowMap Electron Renderer — v2.0
// Upgraded: category scores, AI explanation, new color system

const loadingState = document.getElementById('loading-state');
const resultView   = document.getElementById('result-view');
const scoreNumber  = document.getElementById('score-number');
const scoreFill    = document.getElementById('score-fill');
const riskBadge    = document.getElementById('risk-level-badge');
const domainName   = document.getElementById('domain-name');
const trustBadge   = document.getElementById('trust-badge');
const sslStatus    = document.getElementById('ssl-status');
const reasonsContainer = document.getElementById('reasons-container');
const aiExplanation    = document.getElementById('ai-explanation');
const footerShadowScore = document.getElementById('footer-shadow-score');
const closeBtn    = document.getElementById('close-btn');
const minimizeBtn = document.getElementById('minimize-btn');
const blockBtn    = document.getElementById('block-btn');
const continueBtn = document.getElementById('continue-btn');

// Inject SVG gradient + category score markup on first load
function injectUI() {
    // Add SVG defs gradient to the score circle
    const svg = document.querySelector('.score-circle svg');
    if (svg && !svg.querySelector('defs')) {
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        defs.innerHTML = `
        <linearGradient id="electron-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop id="egrad-1" offset="0%" stop-color="#ef4444"/>
            <stop id="egrad-2" offset="100%" stop-color="#f97316"/>
        </linearGradient>`;
        svg.prepend(defs);
    }

    // Inject category scores section between info-section and threats-section
    const threatsSection = document.querySelector('.threats-section');
    if (threatsSection && !document.getElementById('category-scores-section')) {
        const catSection = document.createElement('section');
        catSection.className = 'category-scores';
        catSection.id = 'category-scores-section';
        catSection.innerHTML = `
        <h3>Category Breakdown</h3>
        ${['trust','authenticity','privacy','threat'].map(cat => `
        <div class="cat-row" id="cat-row-${cat}">
            <div class="cat-header">
                <span>${cat.charAt(0).toUpperCase() + cat.slice(1)}</span>
                <span class="cat-score" id="cat-val-${cat}">--</span>
            </div>
            <div class="cat-bar-track">
                <div class="cat-bar-fill" id="cat-bar-${cat}" style="width:0%;background:#8b5cf6;"></div>
            </div>
        </div>`).join('')}`;
        threatsSection.parentNode.insertBefore(catSection, threatsSection);
    }
}

console.log("ShadowMap Electron Renderer v2.0 initialized");
injectUI();

// ── Score → color mapping ──────────────────────────────────────────────────
function scoreColors(score) {
    if (score >= 86) return { c1: '#10b981', c2: '#059669', cls: 'risk-trusted',    label: 'TRUSTED'    };
    if (score >= 71) return { c1: '#22d3ee', c2: '#0891b2', cls: 'risk-safe',       label: 'SAFE'       };
    if (score >= 51) return { c1: '#f59e0b', c2: '#d97706', cls: 'risk-suspicious', label: 'SUSPICIOUS' };
    if (score >= 31) return { c1: '#f97316', c2: '#ea580c', cls: 'risk-dangerous',  label: 'DANGEROUS'  };
    return              { c1: '#ef4444', c2: '#dc2626', cls: 'risk-critical',   label: 'CRITICAL'   };
}

function catBarColor(score) {
    if (score >= 75) return '#10b981';
    if (score >= 50) return '#f59e0b';
    if (score >= 25) return '#f97316';
    return '#ef4444';
}

// ── Socket / IPC Events ────────────────────────────────────────────────────
window.shadowmap.onContextUpdate((context) => {
    console.log("Context update:", context);
    try {
        const host = new URL(context.url).hostname;
        domainName.textContent = host;
        document.getElementById('scanning-url').textContent = host;
    } catch(e) {}
});

window.shadowmap.onTriggerScan(() => {
    console.log("F4 triggered — showing loader");
    loadingState.classList.remove('hidden');
    resultView.classList.add('hidden');
    document.getElementById('scanning-url').textContent = "Performing AI Security Analysis...";
});

window.shadowmap.onScanResult((data) => {
    console.log("Scan result received");
    updateUI(data, false);
});

// ── Main UI Update ─────────────────────────────────────────────────────────
function updateUI(data, isCached) {
    loadingState.classList.add('hidden');
    resultView.classList.remove('hidden');

    const shadowScore = data.shadow_score || 0;
    const exposure    = data.exposure_score || (100 - shadowScore);
    const tl          = data.threat_level || 'UNKNOWN';

    // Domain + meta
    domainName.textContent = data.domain || (data.url ? new URL(data.url).hostname : 'Unknown');
    trustBadge.textContent = isCached ? 'INSTINCT' : 'AI ANALYZED';
    sslStatus.textContent  = data.ssl_valid ? 'SSL VALID' : 'HTTP';

    // Animated score ring
    animateScore(shadowScore);

    // Colors
    const { c1, c2, cls, label } = scoreColors(shadowScore);
    const grad1 = document.getElementById('egrad-1');
    const grad2 = document.getElementById('egrad-2');
    if (grad1) grad1.setAttribute('stop-color', c1);
    if (grad2) grad2.setAttribute('stop-color', c2);
    scoreNumber.style.color = c1;

    // Risk badge
    riskBadge.className = 'risk-badge ' + cls;
    riskBadge.textContent = label;

    // Footer
    footerShadowScore.textContent = shadowScore;

    // ── Category scores ──
    const cats = data.category_scores || {};
    ['trust','authenticity','privacy','threat'].forEach(cat => {
        const score = cats[cat] !== undefined ? cats[cat] : '--';
        const valEl = document.getElementById(`cat-val-${cat}`);
        const barEl = document.getElementById(`cat-bar-${cat}`);
        if (valEl) valEl.textContent = score !== '--' ? score : '--';
        if (barEl && score !== '--') {
            barEl.style.background = catBarColor(score);
            setTimeout(() => { barEl.style.width = score + '%'; }, 100);
        }
    });

    // ── Reasons pills ──
    reasonsContainer.innerHTML = '';
    const reasons = data.reasons || ['Analysis complete'];
    reasons.forEach(reason => {
        const pill = document.createElement('span');
        const isSafe = reason.toLowerCase().includes('safe') || reason.toLowerCase().includes('initial');
        pill.className = 'threat-pill' + (isSafe ? ' safe' : '');
        pill.textContent = reason;
        reasonsContainer.appendChild(pill);
    });

    // ── AI Explanation ──
    let rawText = data.ai_explanation || (isCached ? 'Press F4 for full AI analysis.' : 'No immediate threats detected.');
    rawText = rawText.replace(/\\n/g, '\n').replace(/\\r/g, '').replace(/\\/g, '');
    aiExplanation.textContent = rawText;
}

// ── Animated counter + ring ────────────────────────────────────────────────
function animateScore(target) {
    let current   = parseInt(scoreNumber.textContent) || 0;
    const circ    = 283;
    const start   = performance.now();
    const from    = current;

    (function tick(now) {
        const t = Math.min((now - start) / 800, 1);
        const ease = t < .5 ? 2*t*t : -1+(4-2*t)*t;
        const val  = Math.round(from + (target - from) * ease);
        scoreNumber.textContent = val;
        scoreFill.style.strokeDashoffset = String(circ - (val / 100) * circ);
        if (t < 1) requestAnimationFrame(tick);
    })(start);
}

// ── Window Controls ────────────────────────────────────────────────────────
closeBtn.onclick    = () => window.shadowmap.closeWindow();
minimizeBtn.onclick = () => window.shadowmap.minimizeWindow();
continueBtn.onclick = () => window.shadowmap.closeWindow();
blockBtn.onclick    = () => console.log("[Block] Not implemented in Electron overlay.");
