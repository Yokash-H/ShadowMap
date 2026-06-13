// ShadowMap Telemetry Relay

async function syncTab(tab) {
    if (!tab || !tab.url || !tab.url.startsWith('http')) return;

    console.log("Sending telemetry for:", tab.url);
    try {
        // Use explicit 127.0.0.1
        await fetch('http://127.0.0.1:5000/api/cache/url', {
            method: 'POST',
            mode: 'cors',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: tab.url,
                title: tab.title || "Unknown"
            })
        });
    } catch (e) {
        console.error("Telemetry failed. Is backend running at 127.0.0.1:5000?");
    }
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    try {
        const tab = await chrome.tabs.get(tabId);
        syncTab(tab);
    } catch(e) {}
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.active) {
        syncTab(tab);
    }
});

// F4 Command Relay
chrome.commands.onCommand.addListener(async (command) => {
    if (command === "trigger-analysis") {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab) {
            // F4 triggers overlay natively by injecting toggle message
            chrome.tabs.sendMessage(tab.id, { type: "TOGGLE_OVERLAY" });
        }
    }
});

// UI Data Request Loop
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "GET_CURRENT_SCAN") {
        fetch('http://127.0.0.1:5000/api/trigger_scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                url: sender.tab ? sender.tab.url : "",
                payload: message.payload 
            })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                chrome.tabs.sendMessage(sender.tab.id, { type: "SCAN_COMPLETE", data: data.result })
            } else {
                chrome.tabs.sendMessage(sender.tab.id, { type: "SCAN_ERROR", error: data.traceback || data.message || "Unknown Error" })
            }
        })
        .catch(err => {
            console.error(err);
            chrome.tabs.sendMessage(sender.tab.id, { type: "SCAN_ERROR", error: err.toString() })
        });
    }
});
