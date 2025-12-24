/**
 * Security Research Content Script
 * FOR AUTHORIZED TESTING ON YOUR OWN SYSTEMS ONLY
 *
 * This script monitors browser data handling for security research purposes
 */

console.warn('🔬 0DIN Sidekick Security Research Tool Active');

class AuraSecurityMonitor {
    constructor() {
        this.findings = [];
        this.initializeMonitoring();
    }

    initializeMonitoring() {
        // Monitor localStorage
        this.monitorStorage();

        // Monitor fetch requests
        this.monitorNetworkRequests();

        // Monitor postMessage
        this.monitorPostMessages();

        // Monitor DOM for sensitive data
        this.monitorDOM();

        // Monitor WebSocket connections
        this.monitorWebSockets();

        // Monitor cookies
        this.monitorCookies();

        // Inject page-level monitoring
        this.injectPageMonitor();
    }

    monitorStorage() {
        // Monitor localStorage
        const self = this;
        const originalSetItem = Storage.prototype.setItem;
        Storage.prototype.setItem = function(key, value) {
            console.log('🔍 localStorage.setItem:', key, value.substring(0, 50) + '...');

            // Check for sensitive patterns
            if (self.checkSensitiveData(value)) {
                self.logFinding('localStorage', key, value);
            }

            return originalSetItem.call(this, key, value);
        };

        // Monitor sessionStorage
        const originalSessionSetItem = sessionStorage.setItem;
        sessionStorage.setItem = function(key, value) {
            console.log('🔍 sessionStorage.setItem:', key, value.substring(0, 50) + '...');

            if (self.checkSensitiveData(value)) {
                self.logFinding('sessionStorage', key, value);
            }

            return originalSessionSetItem.call(sessionStorage, key, value);
        };

        // Check existing storage
        this.auditExistingStorage();
    }

    monitorNetworkRequests() {
        // Override fetch
        const self = this;
        const originalFetch = window.fetch;
        window.fetch = async function(...args) {
            const [url, config] = args;

            console.log('🌐 Fetch request:', url);

            // Check headers for sensitive data
            if (config?.headers) {
                const headers = config.headers;
                if (headers.Authorization) {
                    self.logFinding('fetch-header', 'Authorization', headers.Authorization);
                }
                if (headers.Cookie) {
                    self.logFinding('fetch-header', 'Cookie', headers.Cookie);
                }
            }

            // Monitor response
            const response = await originalFetch.apply(this, args);
            const clonedResponse = response.clone();

            try {
                const responseText = await clonedResponse.text();
                if (self.checkSensitiveData(responseText)) {
                    self.logFinding('fetch-response', url, responseText.substring(0, 200));
                }
            } catch (e) {
                console.log('Could not read response body');
            }

            return response;
        };

        // Override XMLHttpRequest
        const originalXHROpen = XMLHttpRequest.prototype.open;
        const originalXHRSend = XMLHttpRequest.prototype.send;
        const originalXHRSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            this._url = url;
            this._method = method;
            console.log('🌐 XHR request:', method, url);
            return originalXHROpen.call(this, method, url, ...args);
        };

        XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
            if (header === 'Authorization' || header === 'Cookie') {
                window.postMessage({
                    type: 'SECURITY_RESEARCH_XHR_HEADER',
                    header: header,
                    value: value
                }, '*');
            }
            return originalXHRSetRequestHeader.call(this, header, value);
        };

        XMLHttpRequest.prototype.send = function(data) {
            if (data && self.checkSensitiveData(String(data))) {
                self.logFinding('xhr-body', this._url, String(data).substring(0, 200));
            }
            return originalXHRSend.call(this, data);
        };
    }

    monitorPostMessages() {
        window.addEventListener('message', (event) => {
            console.log('📨 PostMessage received:', event.origin, event.data);

            if (typeof event.data === 'string' && this.checkSensitiveData(event.data)) {
                this.logFinding('postMessage', event.origin, event.data);
            } else if (typeof event.data === 'object') {
                const dataStr = JSON.stringify(event.data);
                if (this.checkSensitiveData(dataStr)) {
                    this.logFinding('postMessage', event.origin, dataStr);
                }
            }
        });
    }

    monitorDOM() {
        // Monitor for dynamically added sensitive elements
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            this.scanElementForData(node);
                        }
                    });
                }
            });
        });

        observer.observe(document.body || document.documentElement, {
            childList: true,
            subtree: true
        });

        // Initial scan
        document.addEventListener('DOMContentLoaded', () => {
            this.scanElementForData(document.body);
        });
    }

    monitorWebSockets() {
        const self = this;
        const originalWebSocket = window.WebSocket;

        window.WebSocket = function(url, protocols) {
            console.log('🔌 WebSocket connection:', url);

            const ws = new originalWebSocket(url, protocols);

            // Monitor messages sent
            const originalSend = ws.send;
            ws.send = function(data) {
                console.log('🔌 WebSocket send:', data);

                if (self.checkSensitiveData(String(data))) {
                    self.logFinding('websocket-send', url, String(data).substring(0, 200));
                }

                return originalSend.call(this, data);
            };

            // Monitor messages received
            ws.addEventListener('message', (event) => {
                console.log('🔌 WebSocket receive:', event.data);

                if (self.checkSensitiveData(String(event.data))) {
                    self.logFinding('websocket-receive', url, String(event.data).substring(0, 200));
                }
            });

            return ws;
        };

        // Preserve WebSocket properties
        Object.setPrototypeOf(window.WebSocket, originalWebSocket);
        Object.setPrototypeOf(window.WebSocket.prototype, originalWebSocket.prototype);
    }

    monitorCookies() {
        // Monitor document.cookie access
        const self = this;
        let cookieValue = document.cookie;
        Object.defineProperty(document, 'cookie', {
            get: function() {
                console.log('🍪 Cookie accessed:', cookieValue);
                return cookieValue;
            },
            set: function(value) {
                console.log('🍪 Cookie set:', value);

                if (self.checkSensitiveData(value)) {
                    self.logFinding('cookie', 'set', value);
                }

                cookieValue = value;
                return true;
            }
        });
    }

    scanElementForData(element) {
        if (!element) return;

        const self = this;

        // Check for input fields with sensitive data
        const inputs = element.querySelectorAll('input, textarea');
        inputs.forEach(input => {
            if (input.type === 'password' || input.name?.includes('token') || input.name?.includes('key')) {
                console.log('🔍 Sensitive input detected:', input.name || input.type);

                input.addEventListener('change', () => {
                    if (input.value) {
                        self.logFinding('input-field', input.name || input.type, '[REDACTED]');
                    }
                });
            }
        });

        // Check for data attributes
        const elementsWithData = element.querySelectorAll('[data-token], [data-key], [data-session], [data-auth]');
        elementsWithData.forEach(el => {
            Array.from(el.attributes).forEach(attr => {
                if (attr.name.startsWith('data-') && self.checkSensitiveData(attr.value)) {
                    self.logFinding('data-attribute', attr.name, attr.value);
                }
            });
        });
    }

    injectPageMonitor() {
        const script = document.createElement('script');
        script.textContent = `
      (function() {
        console.log('🔬 Page-level monitoring active');

        // Monitor global variables
        const sensitiveGlobals = ['__AUTH__', '__TOKEN__', '__SESSION__', 'credentials', 'apiKey'];
        sensitiveGlobals.forEach(globalName => {
          if (window[globalName]) {
            window.postMessage({
              type: 'SECURITY_RESEARCH_GLOBAL',
              name: globalName,
              value: JSON.stringify(window[globalName])
            }, '*');
          }
        });

        // Monitor prototype modifications
        const monitorPrototype = (obj, name) => {
          const props = Object.getOwnPropertyNames(obj.prototype);
          props.forEach(prop => {
            const descriptor = Object.getOwnPropertyDescriptor(obj.prototype, prop);
            if (descriptor && descriptor.value && typeof descriptor.value === 'function') {
              const original = descriptor.value;
              obj.prototype[prop] = function(...args) {
                if (prop === 'setItem' || prop === 'send' || prop === 'fetch') {
                  window.postMessage({
                    type: 'SECURITY_RESEARCH_PROTO',
                    object: name,
                    method: prop,
                    args: args.map(a => String(a).substring(0, 100))
                  }, '*');
                }
                return original.apply(this, args);
              };
            }
          });
        };

        // Monitor IndexedDB
        if (window.indexedDB) {
          const originalOpen = indexedDB.open;
          indexedDB.open = function(...args) {
            console.log('🗄️ IndexedDB open:', args);
            window.postMessage({
              type: 'SECURITY_RESEARCH_IDB',
              action: 'open',
              name: args[0]
            }, '*');
            return originalOpen.apply(this, args);
          };
        }
      })();
    `;
        (document.head || document.documentElement).appendChild(script);
        script.remove();
    }

    checkSensitiveData(data) {
        if (!data || typeof data !== 'string') return false;

        const patterns = [
            /Bearer\s+[\w-]+/i,
            /sk-[\w]+/i,
            /sess_[\w]+/i,
            /eyJ[\w]+/, // JWT
            /token["\s:=]+["']?[\w-]+/i,
            /api[_-]?key["\s:=]+["']?[\w-]+/i,
            /session[_-]?id["\s:=]+["']?[\w-]+/i,
            /auth["\s:=]+["']?[\w-]+/i,
            /credentials["\s:=]+/i,
            /password["\s:=]+["']?\w+/i
        ];

        return patterns.some(pattern => pattern.test(data));
    }

    logFinding(type, key, value) {
        const finding = {
            type: type,
            key: key,
            value: value.substring(0, 200), // Truncate for logging
            timestamp: new Date().toISOString(),
            url: window.location.href
        };

        this.findings.push(finding);

        // Send to background script
        chrome.runtime.sendMessage({
            type: 'SECURITY_FINDING',
            finding: finding
        });

        console.warn('⚠️ SECURITY RESEARCH FINDING:', finding);
    }

    auditExistingStorage() {
        // Audit localStorage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);

            if (this.checkSensitiveData(value)) {
                this.logFinding('localStorage-existing', key, value);
            }
        }

        // Audit sessionStorage
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            const value = sessionStorage.getItem(key);

            if (this.checkSensitiveData(value)) {
                this.logFinding('sessionStorage-existing', key, value);
            }
        }

        // Audit cookies
        if (document.cookie && this.checkSensitiveData(document.cookie)) {
            this.logFinding('cookie-existing', 'document.cookie', document.cookie);
        }
    }
}

// Initialize monitor
const monitor = new AuraSecurityMonitor();

// Listen for messages from injected script
window.addEventListener('message', (event) => {
    if (event.source !== window) return;

    if (event.data.type && event.data.type.startsWith('SECURITY_RESEARCH_')) {
        monitor.logFinding(event.data.type, event.data.name || event.data.action, JSON.stringify(event.data));
    }
});

console.log('✅ Security research monitoring initialized');