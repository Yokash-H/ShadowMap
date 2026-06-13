const loadingState = document.getElementById('loading-state');
const resultView = document.getElementById('result-view');
const scoreNumber = document.getElementById('score-number');
const scoreFill = document.getElementById('score-fill');
const riskBadge = document.getElementById('risk-level-badge');
const domainName = document.getElementById('domain-name');
const trustBadge = document.getElementById('trust-badge');
const sslStatus = document.getElementById('ssl-status');
const reasonsContainer = document.getElementById('reasons-container');
const aiExplanation = document.getElementById('ai-explanation');
const footerShadowScore = document.getElementById('footer-shadow-score');

const closeBtn = document.getElementById('close-btn');
const minimizeBtn = document.getElementById('minimize-btn');
const blockBtn = document.getElementById('block-btn');
const continueBtn = document.getElementById('continue-btn');

console.log("Renderer initialized and waiting for events...");

// --- Event Listeners ---

window.shadowmap.onContextUpdate((context) => {
    console.log("UI: Context Update Received", context);

    // update domain immediately
    const host = new URL(context.url).hostname;
    domainName.textContent = host;

    if (context.risk_cache) {
        updateUI(context.risk_cache, true);
    }
});

// Listener for F4 trigger (to show loading state)
window.shadowmap.onTriggerScan(() => {
    console.log("UI: F4 Triggered - Showing Loading State");
    loadingState.classList.remove('hidden');
    resultView.classList.add('hidden');
    document.getElementById('scanning-url').textContent = "Performing AI Security Analysis...";
});

window.shadowmap.onScanResult((data) => {
    console.log("UI: Full Scan Result Received", data);
    updateUI(data, false);
});

function updateUI(data, isCached) {
    loadingState.classList.add('hidden');
    resultView.classList.remove('hidden');

    domainName.textContent = data.domain || new URL(data.url).hostname;
    trustBadge.textContent = isCached ? "INSTINCT" : "AI ANALYZED";
    sslStatus.textContent = data.ssl_valid ? 'SSL VALID' : 'INSECURE';

    const score = data.risk_score || 0;
    animateScore(score);

    let color = '#2EE59D';
    if (score > 75) color = '#FF4D4D';
    else if (score > 50) color = '#FFB020';
    else if (score > 25) color = '#4DA3FF';

    scoreFill.style.stroke = color;
    scoreFill.style.filter = `drop-shadow(0 0 5px ${color})`;
    riskBadge.style.backgroundColor = color;
    riskBadge.textContent = data.risk_level || "LOW";

    reasonsContainer.innerHTML = '';
    const reasons = data.reasons || ["Analyzing..."];
    reasons.forEach(reason => {
        const pill = document.createElement('span');
        pill.className = 'pill';
        pill.textContent = reason;
        reasonsContainer.appendChild(pill);
    });

    aiExplanation.textContent = data.ai_explanation || (isCached ? "Press F4 for deep AI analysis." : "No threats detected.");
}

function animateScore(target) {
    let current = parseInt(scoreNumber.textContent) || 0;
    const duration = 600;
    const startTime = performance.now();
    const startValue = current;
    const circumference = 282.7;

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easedProgress = progress * (2 - progress);

        current = Math.floor(startValue + (target - startValue) * easedProgress);
        scoreNumber.textContent = current;
        const offset = circumference - (current / 100) * circumference;
        scoreFill.style.strokeDashoffset = offset;

        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

// UI Controls
closeBtn.onclick = () => window.shadowmap.closeWindow();
minimizeBtn.onclick = () => window.shadowmap.minimizeWindow();
continueBtn.onclick = () => window.shadowmap.closeWindow();
