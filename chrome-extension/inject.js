// =============================================================================
// ShadowMap AI - Network Interceptor Script
// Injected into the page context to spy on fetch/XHR
// =============================================================================

(function() {
    if (window._shadowMapInjected) return;
    window._shadowMapInjected = true;

    // Send data back to the content script
    function reportTraffic(url, method, type) {
        // Filter out same-origin requests to reduce noise, only report cross-origin
        try {
            const destUrl = new URL(url, window.location.origin);
            if (destUrl.origin !== window.location.origin) {
                window.postMessage({
                    type: "SHADOWMAP_NETWORK_TRAFFIC",
                    data: { url: destUrl.href, method, type }
                }, "*");
            }
        } catch (e) {
            // Invalid URL
        }
    }

    // 1. Hook Fetch
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        try {
            const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || 'unknown';
            const method = (args[1] && args[1].method) || (args[0] && args[0].method) || 'GET';
            reportTraffic(url, method, 'fetch');
        } catch (e) {}
        return originalFetch.apply(this, args);
    };

    // 2. Hook XHR
    const originalXhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        try {
            reportTraffic(url, method, 'xhr');
        } catch (e) {}
        return originalXhrOpen.call(this, method, url, ...rest);
    };
})();
