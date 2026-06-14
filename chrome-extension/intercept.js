// ShadowMap Firewall: MAIN world API Interception Hook
console.log("SHADOWMAP FIREWALL: Main-world hook initialized.");

(function() {
    function isSensitiveData(dataStr) {
        if (!dataStr) return false;
        const sensitiveKeywords = [
            'password', 'passwd', 'password_hash', 'pass', 'pwd',
            'creditcard', 'cardnumber', 'cvv', 'cvc', 'card_number', 'cc_number',
            'otp', '2fa', 'mfa', 'verification_code', 'sec_code', 'pin'
        ];
        const dataLower = dataStr.toLowerCase();
        return sensitiveKeywords.some(keyword => dataLower.includes(keyword));
    }

    function triggerFirewallIntercept(type, url, payloadStr) {
        return new Promise((resolve) => {
            const requestId = Math.random().toString(36).substr(2, 9);
            
            const onResponse = (e) => {
                if (e.detail.requestId === requestId) {
                    window.removeEventListener('shadowmap-firewall-response-' + requestId, onResponse);
                    resolve(e.detail);
                }
            };
            window.addEventListener('shadowmap-firewall-response-' + requestId, onResponse);

            const event = new CustomEvent('shadowmap-firewall-intercept', {
                detail: {
                    requestId: requestId,
                    type: type,
                    url: url,
                    payload: payloadStr
                }
            });
            window.dispatchEvent(event);
        });
    }

    // --- INTERCEPT FETCH ---
    const originalFetch = window.fetch;
    window.fetch = async function(resource, init) {
        const url = typeof resource === 'string' ? resource : (resource && resource.url ? resource.url : '');
        let bodyStr = '';
        if (init && init.body) {
            if (typeof init.body === 'string') {
                bodyStr = init.body;
            } else if (init.body instanceof URLSearchParams) {
                bodyStr = init.body.toString();
            } else if (init.body instanceof FormData) {
                const entries = [];
                for (var pair of init.body.entries()) {
                    entries.push(pair[0] + '=' + pair[1]);
                }
                bodyStr = entries.join('&');
            }
        }

        if (isSensitiveData(url) || isSensitiveData(bodyStr)) {
            console.warn("SHADOWMAP FIREWALL: Intercepted sensitive fetch to: " + url);
            const decision = await triggerFirewallIntercept('fetch', url, bodyStr);
            if (decision.action === 'block') {
                console.error("SHADOWMAP FIREWALL: Fetch submission BLOCKED by user.");
                return new Response(JSON.stringify({ error: "Interception by ShadowMap Firewall" }), { status: 403, statusText: "Forbidden" });
            } else if (decision.action === 'decoy') {
                console.warn("SHADOWMAP FIREWALL: Fetch submission replaced with DECOY data.");
                const fakeData = decision.decoyData;
                if (init && init.body) {
                    if (typeof init.body === 'string') {
                        try {
                            const parsed = JSON.parse(init.body);
                            for (let k in parsed) {
                                if (isSensitiveData(k) || isSensitiveData(parsed[k])) {
                                    if (k.includes('password') || k.includes('pass')) parsed[k] = fakeData.password;
                                    else if (k.includes('email') || k.includes('user')) parsed[k] = fakeData.email;
                                    else if (k.includes('phone') || k.includes('tel')) parsed[k] = fakeData.phone;
                                    else if (k.includes('card') || k.includes('cvv') || k.includes('number')) parsed[k] = fakeData.cardNumber;
                                }
                            }
                            init.body = JSON.stringify(parsed);
                        } catch(e) {
                            init.body = init.body.replace(/(password|passwd|pwd|pass)=[^&]*/g, '$1=' + encodeURIComponent(fakeData.password))
                                                 .replace(/(email|user|username)=[^&]*/g, '$1=' + encodeURIComponent(fakeData.email));
                        }
                    }
                }
            }
        }
        return originalFetch.apply(this, arguments);
    };

    // --- INTERCEPT XMLHttpRequest ---
    const originalSend = XMLHttpRequest.prototype.send;
    const originalOpen = XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open = function(method, url) {
        this._url = url;
        return originalOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function(body) {
        const xhr = this;
        const url = xhr._url || '';
        let bodyStr = '';
        if (typeof body === 'string') {
            bodyStr = body;
        } else if (body instanceof Document) {
            bodyStr = body.documentElement.outerHTML;
        } else if (body instanceof URLSearchParams) {
            bodyStr = body.toString();
        } else if (body instanceof FormData) {
            const entries = [];
            for (var pair of body.entries()) {
                entries.push(pair[0] + '=' + pair[1]);
            }
            bodyStr = entries.join('&');
        }

        if (isSensitiveData(url) || isSensitiveData(bodyStr)) {
            console.warn("SHADOWMAP FIREWALL: Intercepted sensitive XHR to: " + url);
            
            triggerFirewallIntercept('xhr', url, bodyStr).then(decision => {
                if (decision.action === 'block') {
                    console.error("SHADOWMAP FIREWALL: XHR submission BLOCKED by user.");
                    Object.defineProperty(xhr, 'status', { writable: true, value: 403 });
                    Object.defineProperty(xhr, 'statusText', { writable: true, value: "Forbidden (Blocked by ShadowMap Firewall)" });
                    Object.defineProperty(xhr, 'readyState', { writable: true, value: 4 });
                    if (xhr.onerror) xhr.onerror();
                } else if (decision.action === 'decoy') {
                    console.warn("SHADOWMAP FIREWALL: XHR submission replaced with DECOY data.");
                    let updatedBody = body;
                    const fakeData = decision.decoyData;
                    if (typeof body === 'string') {
                        try {
                            const parsed = JSON.parse(body);
                            for (let k in parsed) {
                                if (isSensitiveData(k) || isSensitiveData(parsed[k])) {
                                    if (k.includes('password') || k.includes('pass')) parsed[k] = fakeData.password;
                                    else if (k.includes('email') || k.includes('user')) parsed[k] = fakeData.email;
                                    else if (k.includes('phone') || k.includes('tel')) parsed[k] = fakeData.phone;
                                    else if (k.includes('card') || k.includes('cvv') || k.includes('number')) parsed[k] = fakeData.cardNumber;
                                }
                            }
                            updatedBody = JSON.stringify(parsed);
                        } catch(e) {
                            updatedBody = body.replace(/(password|passwd|pwd|pass)=[^&]*/g, '$1=' + encodeURIComponent(fakeData.password))
                                              .replace(/(email|user|username)=[^&]*/g, '$1=' + encodeURIComponent(fakeData.email));
                        }
                    }
                    originalSend.call(xhr, updatedBody);
                } else {
                    originalSend.call(xhr, body);
                }
            });
        } else {
            originalSend.apply(xhr, arguments);
        }
    };
})();
