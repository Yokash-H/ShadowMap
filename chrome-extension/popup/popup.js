chrome.storage.local.get("last_scan", (data) => {
    if (data.last_scan) {
        const scan = data.last_scan;
        document.getElementById('domain').textContent = scan.domain;
        const badge = document.getElementById('risk-badge');
        badge.textContent = `${scan.risk_level} RISK (${scan.risk_score})`;

        let color = '#2EE59D';
        if (scan.risk_score > 75) color = '#FF4D4D';
        else if (scan.risk_score > 50) color = '#FFB020';
        else if (scan.risk_score > 25) color = '#4DA3FF';
        badge.style.backgroundColor = color;

        const reasonsList = document.getElementById('reasons');
        reasonsList.innerHTML = '';
        scan.reasons.slice(0, 2).forEach(r => {
            const li = document.createElement('li');
            li.innerHTML = `<span>•</span> ${r}`;
            reasonsList.appendChild(li);
        });
    }
});
