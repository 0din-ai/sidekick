/**
 * Enhanced Security Research Content Script
 * 0DIN Sidekick v1.0 - Complete Implementation
 */

console.warn('🚀 0DIN Sidekick Enhanced Mode Active');

class EnhancedSecurityMonitor {
    constructor() {
        // Core data structures
        this.dataFlows = new Map();
        this.permissions = new Set();
        this.storageSnapshot = {};
        this.networkPatterns = [];
        this.crossOriginRequests = [];
        this.cspViolations = [];
        this.thirdPartyScripts = new Set();
        this.timingPatterns = [];
        this.fingerprintingAttempts = [];
        this.eventListeners = new Map();
        this.iframes = [];
        this.apiCalls = [];
        this.domMutations = [];
        this.classifiedData = [];
        this.websocketConnections = [];
        this.privacyBudget = { geolocation: 0, camera: 0, microphone: 0, clipboard: 0 };

        // Initialize all features
        this.initializeEnhancedMonitoring();
        this.setupMessageHandlers();
    }

    initializeEnhancedMonitoring() {
        console.log('[0DIN Sidekick] Initializing all 18 enhanced features...');

        // 1. Data Flow Visualization
        this.trackDataFlow();

        // 2. Permission Audit System
        this.auditPermissions();

        // 3. Storage Analysis
        this.analyzeStorage();

        // 4. Network Request Analyzer
        this.enhancedNetworkAnalysis();

        // 5. Cross-Origin Monitoring
        this.monitorCrossOrigin();

        // 6. CSP Analyzer
        this.analyzeCSP();

        // 7. WebSocket/WebRTC Inspector
        this.inspectRealtimeConnections();

        // 8. Third-Party Script Auditor
        this.auditThirdPartyScripts();

        // 9. Timing Attack Detector
        this.detectTimingPatterns();

        // 10. Data Classification
        this.classifyData();

        // 11. Fingerprinting Detection
        this.detectFingerprinting();

        // 12. Event Listener Auditor
        this.auditEventListeners();

        // 13. iframe Security Monitor
        this.monitorIframes();

        // 15. Pattern Learning System
        this.initPatternLearning();

        // 16. API Call Interceptor
        this.interceptAPICalls();

        // 17. DOM Mutation Tracker
        this.trackDOMMutations();

        // 18. Privacy Budget Monitor
        this.monitorPrivacyBudget();
    }

    // Feature 1: Data Flow Visualization
    trackDataFlow() {
        const trackFlow = (source, destination, dataType, data) => {
            const flow = {
                source,
                destination,
                dataType,
                timestamp: Date.now(),
                dataPreview: this.truncateData(data)
            };

            if (!this.dataFlows.has(source)) {
                this.dataFlows.set(source, []);
            }
            this.dataFlows.get(source).push(flow);

            this.reportFinding('data-flow', `${source} → ${destination}`, flow);
        };

        // Track localStorage flow
        const originalSetItem = Storage.prototype.setItem;
        Storage.prototype.setItem = function(key, value) {
            trackFlow('script', 'localStorage', 'storage', { key, value });
            return originalSetItem.call(this, key, value);
        };

        // Track fetch flow
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const [url] = args;
            trackFlow('script', new URL(url, location.href).origin, 'network', { url });
            return originalFetch.apply(this, args);
        };
    }

    // Feature 2: Permission Audit System
    auditPermissions() {
        const permissions = [
            'geolocation', 'notifications', 'camera', 'microphone',
            'clipboard-read', 'clipboard-write', 'payment', 'usb',
            'bluetooth', 'persistent-storage', 'ambient-light-sensor',
            'accelerometer', 'gyroscope', 'magnetometer', 'midi'
        ];

        permissions.forEach(permission => {
            if (permission in navigator.permissions) {
                navigator.permissions.query({ name: permission }).then(result => {
                    if (result.state !== 'denied') {
                        this.permissions.add(permission);
                        this.reportFinding('permission-available', permission, result.state);
                    }
                }).catch(() => {});
            }
        });

        // Monitor permission requests
        if (navigator.permissions && navigator.permissions.query) {
            const originalQuery = navigator.permissions.query;
            navigator.permissions.query = function(...args) {
                const [descriptor] = args;
                this.reportFinding('permission-query', descriptor.name, descriptor);
                return originalQuery.apply(navigator.permissions, args);
            }.bind(this);
        }
    }

    // Feature 3: Storage Analysis Dashboard
    analyzeStorage() {
        const analysis = {
            localStorage: {},
            sessionStorage: {},
            indexedDB: [],
            cookies: document.cookie.split(';').length,
            cacheStorage: null,
            webSQL: null
        };

        // Analyze localStorage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            const value = localStorage.getItem(key);
            analysis.localStorage[key] = {
                size: value.length,
                type: this.detectDataType(value),
                sensitive: this.isSensitive(value)
            };
        }

        // Analyze sessionStorage
        for (let i = 0; i < sessionStorage.length; i++) {
            const key = sessionStorage.key(i);
            const value = sessionStorage.getItem(key);
            analysis.sessionStorage[key] = {
                size: value.length,
                type: this.detectDataType(value),
                sensitive: this.isSensitive(value)
            };
        }

        // Check IndexedDB
        if (window.indexedDB) {
            indexedDB.databases().then(databases => {
                analysis.indexedDB = databases.map(db => ({
                    name: db.name,
                    version: db.version
                }));
                this.reportFinding('storage-analysis', 'complete', analysis);
            }).catch(() => {});
        }

        this.storageSnapshot = analysis;
    }

    // Feature 4: Network Request Analyzer
    enhancedNetworkAnalysis() {
        const analyzeRequest = (url, method, headers, body) => {
            const analysis = {
                url,
                method,
                timestamp: Date.now(),
                headers: headers || {},
                bodySize: body ? body.length : 0,
                suspicious: false,
                reasons: []
            };

            // Check for data exfiltration patterns
            if (body && body.length > 10000) {
                analysis.suspicious = true;
                analysis.reasons.push('Large POST body');
            }

            if (url.includes('base64')) {
                analysis.suspicious = true;
                analysis.reasons.push('Base64 in URL');
            }

            const suspiciousDomains = ['pastebin.com', 'webhook.site', 'requestbin.com'];
            if (suspiciousDomains.some(domain => url.includes(domain))) {
                analysis.suspicious = true;
                analysis.reasons.push('Suspicious domain');
            }

            if (analysis.suspicious) {
                this.reportFinding('suspicious-network', url, analysis);
            }

            this.networkPatterns.push(analysis);
        };

        // Enhanced fetch monitoring
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const [url, config] = args;
            analyzeRequest(url, config ? .method || 'GET', config ? .headers, config ? .body);
            return originalFetch.apply(this, args);
        }.bind(this);

        // Enhanced XHR monitoring
        const originalSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            analyzeRequest(this._url, this._method, this._headers, body);
            return originalSend.call(this, body);
        };
    }

    // Feature 5: Cross-Origin Resource Monitoring
    monitorCrossOrigin() {
        // Monitor CORS requests
        const checkCrossOrigin = (url) => {
            try {
                const urlObj = new URL(url, location.href);
                if (urlObj.origin !== location.origin) {
                    this.crossOriginRequests.push({
                        from: location.origin,
                        to: urlObj.origin,
                        url: url,
                        timestamp: Date.now()
                    });
                    this.reportFinding('cross-origin', urlObj.origin, url);
                }
            } catch (e) {}
        };

        // Monitor fetch
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            checkCrossOrigin(args[0]);
            return originalFetch.apply(this, args);
        };

        // Monitor postMessage
        window.addEventListener('message', (event) => {
            if (event.origin !== location.origin) {
                this.reportFinding('cross-origin-message', event.origin, {
                    data: this.truncateData(event.data)
                });
            }
        });
    }

    // Feature 6: CSP Analyzer
    analyzeCSP() {
        // Listen for CSP violations
        document.addEventListener('securitypolicyviolation', (e) => {
            const violation = {
                directive: e.violatedDirective,
                blockedURI: e.blockedURI,
                policy: e.originalPolicy,
                timestamp: Date.now()
            };
            this.cspViolations.push(violation);
            this.reportFinding('csp-violation', e.violatedDirective, violation);
        });

        // Check CSP meta tags
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        if (cspMeta) {
            this.reportFinding('csp-policy', 'meta-tag', cspMeta.content);
        }
    }

    // Feature 7: WebSocket/WebRTC Inspector
    inspectRealtimeConnections() {
        // WebSocket monitoring
        const OriginalWebSocket = window.WebSocket;
        window.WebSocket = function(...args) {
            const ws = new OriginalWebSocket(...args);

            this.reportFinding('websocket-connection', args[0], {
                url: args[0],
                protocols: args[1]
            });

            // Monitor messages
            const originalSend = ws.send;
            ws.send = function(data) {
                this.reportFinding('websocket-send', args[0], this.truncateData(data));
                return originalSend.call(ws, data);
            }.bind(this);

            ws.addEventListener('message', (event) => {
                this.reportFinding('websocket-receive', args[0], this.truncateData(event.data));
            });

            return ws;
        }.bind(this);

        // WebRTC monitoring
        if (window.RTCPeerConnection) {
            const OriginalRTCPeerConnection = window.RTCPeerConnection;
            window.RTCPeerConnection = function(...args) {
                const pc = new OriginalRTCPeerConnection(...args);

                this.reportFinding('webrtc-connection', 'created', {
                    config: args[0]
                });

                // Monitor data channels
                pc.addEventListener('datachannel', (event) => {
                    this.reportFinding('webrtc-datachannel', 'created', {
                        label: event.channel.label
                    });
                });

                return pc;
            }.bind(this);
        }
    }

    // Feature 8: Third-Party Script Auditor
    auditThirdPartyScripts() {
        const scripts = document.querySelectorAll('script[src]');
        scripts.forEach(script => {
            try {
                const url = new URL(script.src);
                if (url.origin !== location.origin) {
                    this.thirdPartyScripts.add({
                        url: script.src,
                        origin: url.origin,
                        async: script.async,
                        defer: script.defer,
                        integrity: script.integrity || 'none'
                    });
                    this.reportFinding('third-party-script', url.origin, script.src);
                }
            } catch (e) {}
        });

        // Monitor dynamically added scripts
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeName === 'SCRIPT' && node.src) {
                        this.auditThirdPartyScripts();
                    }
                });
            });
        });

        observer.observe(document.head || document.documentElement, {
            childList: true,
            subtree: true
        });
    }

    // Feature 9: Timing Attack Detector
    detectTimingPatterns() {
        const timings = [];

        // Monitor fetch timing
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const startTime = performance.now();
            return originalFetch.apply(this, args).then(response => {
                const endTime = performance.now();
                const duration = endTime - startTime;

                timings.push({
                    url: args[0],
                    duration,
                    timestamp: Date.now()
                });

                // Detect potential timing attacks
                if (timings.length > 10) {
                    const similar = timings.filter(t =>
                        t.url.includes(new URL(args[0], location.href).pathname)
                    );

                    if (similar.length > 5) {
                        const avgTime = similar.reduce((a, b) => a + b.duration, 0) / similar.length;
                        const variance = Math.abs(duration - avgTime);

                        if (variance > avgTime * 0.5) {
                            this.reportFinding('timing-anomaly', args[0], {
                                duration,
                                average: avgTime,
                                variance
                            });
                        }
                    }
                }

                return response;
            });
        }.bind(this);
    }

    // Feature 10: Data Classification System
    classifyData() {
        this.dataClassifier = {
            classify: (data) => {
                const classifications = [];
                const dataStr = String(data);

                // PII Detection
                if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(dataStr)) {
                    classifications.push({ type: 'email', severity: 'HIGH', category: 'PII' });
                }
                if (/\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/.test(dataStr)) {
                    classifications.push({ type: 'phone', severity: 'HIGH', category: 'PII' });
                }
                if (/\d{3}-\d{2}-\d{4}/.test(dataStr)) {
                    classifications.push({ type: 'ssn', severity: 'CRITICAL', category: 'PII' });
                }

                // Financial
                if (/\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/.test(dataStr)) {
                    classifications.push({ type: 'credit-card', severity: 'CRITICAL', category: 'Financial' });
                }

                // Authentication tokens
                if (/Bearer\s+[\w-]{20,}/i.test(dataStr)) {
                    classifications.push({ type: 'bearer-token', severity: 'CRITICAL', category: 'Authentication' });
                }
                if (/sk-[a-zA-Z0-9]{48}/.test(dataStr)) {
                    classifications.push({ type: 'openai-api-key', severity: 'CRITICAL', category: 'API Key' });
                }
                if (/eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*/.test(dataStr)) {
                    classifications.push({ type: 'jwt-token', severity: 'CRITICAL', category: 'Authentication' });
                }
                if (/api[_-]?key[\s]*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?/gi.test(dataStr)) {
                    classifications.push({ type: 'api-key', severity: 'CRITICAL', category: 'API Key' });
                }

                // AWS Keys
                if (/AKIA[0-9A-Z]{16}/.test(dataStr)) {
                    classifications.push({ type: 'aws-access-key', severity: 'CRITICAL', category: 'Cloud' });
                }

                // GitHub tokens
                if (/ghp_[a-zA-Z0-9]{36}/.test(dataStr)) {
                    classifications.push({ type: 'github-token', severity: 'CRITICAL', category: 'Version Control' });
                }

                return classifications;
            }
        };

        // Monitor all input fields
        document.addEventListener('input', (e) => {
            if (e.target && e.target.value) {
                const classified = this.dataClassifier.classify(e.target.value);
                if (classified.length > 0) {
                    classified.forEach(item => {
                        this.reportFinding('sensitive-data-input', e.target.name || e.target.id || 'input', {
                            ...item,
                            value: e.target.value.substring(0, 50) + '...',
                            fieldType: e.target.type,
                            timestamp: Date.now()
                        });
                    });
                    this.classifiedData.push(...classified);
                }
            }
        });

        // Monitor all text content periodically
        setInterval(() => {
            this.scanPageForSensitiveData();
        }, 30000); // Every 30 seconds

        // Initial scan
        setTimeout(() => this.scanPageForSensitiveData(), 3000);
    }

    scanPageForSensitiveData() {
        // Scan all text nodes
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );

        let node;
        const foundData = [];

        while (node = walker.nextNode()) {
            if (node.nodeValue && node.nodeValue.trim().length > 10) {
                const classified = this.dataClassifier.classify(node.nodeValue);
                if (classified.length > 0) {
                    classified.forEach(item => {
                        foundData.push({
                            ...item,
                            context: node.nodeValue.substring(0, 100),
                            element: node.parentElement?.tagName
                        });
                    });
                }
            }
        }

        if (foundData.length > 0) {
            foundData.forEach(item => {
                this.reportFinding('sensitive-data-scan', item.type, item);
            });
            this.classifiedData.push(...foundData);
            console.log('[0DIN Sidekick] Found sensitive data:', foundData);
        }
    }

    // Feature 11: Fingerprinting Detection
    detectFingerprinting() {
        const self = this; // Store reference for use in overridden functions
        console.log('[0DIN Sidekick] Initializing fingerprinting detection...');

        // Monitor canvas fingerprinting
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
            console.log('[0DIN Sidekick] Canvas toDataURL called!');
            const fingerprintData = {
                category: 'canvas',
                method: 'toDataURL',
                timestamp: Date.now(),
                details: {
                    width: this.width,
                    height: this.height
                }
            };

            // Send finding to background
            chrome.runtime.sendMessage({
                type: 'ENHANCED_FINDING',
                finding: {
                    type: 'fingerprint-canvas',
                    key: 'toDataURL',
                    value: fingerprintData,
                    timestamp: new Date().toISOString(),
                    url: window.location.href
                }
            }, (response) => {
                console.log('[0DIN Sidekick] Fingerprint finding sent:', response);
            });

            self.fingerprintingAttempts.push(fingerprintData);
            console.warn('[0DIN Sidekick] Canvas fingerprinting detected: toDataURL');

            return originalToDataURL.apply(this, args);
        };

        // Monitor canvas getImageData
        const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = function(...args) {
            const fingerprintData = {
                category: 'canvas',
                method: 'getImageData',
                timestamp: Date.now(),
                details: {
                    x: args[0],
                    y: args[1],
                    width: args[2],
                    height: args[3]
                }
            };

            // Send finding to background
            chrome.runtime.sendMessage({
                type: 'ENHANCED_FINDING',
                finding: {
                    type: 'fingerprint-canvas',
                    key: 'getImageData',
                    value: fingerprintData,
                    timestamp: new Date().toISOString(),
                    url: window.location.href
                }
            }, (response) => {
                console.log('[0DIN Sidekick] Fingerprint finding sent:', response);
            });

            self.fingerprintingAttempts.push(fingerprintData);
            console.warn('[0DIN Sidekick] Canvas fingerprinting detected: getImageData');

            return originalGetImageData.apply(this, args);
        };

        // Monitor WebGL fingerprinting
        if (window.WebGLRenderingContext) {
            const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {
                // Check for vendor/renderer info parameters
                if (param === 0x1F00 || param === 0x1F01 || param === 0x1F02 || // VENDOR, RENDERER, VERSION
                    param === 37445 || param === 37446) { // WEBGL_debug_renderer_info

                    const fingerprintData = {
                        category: 'webgl',
                        method: 'getParameter',
                        parameter: param,
                        timestamp: Date.now()
                    };

                    // Send finding to background
                    chrome.runtime.sendMessage({
                        type: 'ENHANCED_FINDING',
                        finding: {
                            type: 'fingerprint-webgl',
                            key: `parameter-${param}`,
                            value: fingerprintData,
                            timestamp: new Date().toISOString(),
                            url: window.location.href
                        }
                    });
                    self.fingerprintingAttempts.push(fingerprintData);
                    console.warn('[0DIN Sidekick] WebGL fingerprinting detected:', param);
                }

                return originalGetParameter.call(this, param);
            };
        }

        // Monitor font enumeration
        if (document.fonts && document.fonts.check) {
            const originalCheck = document.fonts.check;
            document.fonts.check = function(...args) {
                const fingerprintData = {
                    category: 'fonts',
                    method: 'check',
                    font: args[0],
                    timestamp: Date.now()
                };

                // Send finding to background
                chrome.runtime.sendMessage({
                    type: 'ENHANCED_FINDING',
                    finding: {
                        type: 'fingerprint-font',
                        key: args[0],
                        value: fingerprintData,
                        timestamp: new Date().toISOString(),
                        url: window.location.href
                    }
                });
                self.fingerprintingAttempts.push(fingerprintData);
                console.warn('[0DIN Sidekick] Font fingerprinting detected:', args[0]);

                return originalCheck.apply(document.fonts, args);
            };
        }

        // Monitor navigator properties access
        const navigatorProps = [
            'userAgent', 'platform', 'languages', 'language',
            'hardwareConcurrency', 'deviceMemory', 'plugins', 'mimeTypes'
        ];

        navigatorProps.forEach(prop => {
            if (prop in navigator) {
                const descriptor = Object.getOwnPropertyDescriptor(navigator, prop) ||
                                 Object.getOwnPropertyDescriptor(Navigator.prototype, prop);

                if (descriptor && descriptor.get) {
                    Object.defineProperty(navigator, prop, {
                        get: function() {
                            const fingerprintData = {
                                category: 'navigator',
                                method: prop,
                                timestamp: Date.now()
                            };

                            // Only report if multiple properties accessed (likely fingerprinting)
                            if (self.fingerprintingAttempts.filter(f => f.category === 'navigator').length > 3) {
                                // Send finding to background
                                chrome.runtime.sendMessage({
                                    type: 'ENHANCED_FINDING',
                                    finding: {
                                        type: 'fingerprint-navigator',
                                        key: prop,
                                        value: fingerprintData,
                                        timestamp: new Date().toISOString(),
                                        url: window.location.href
                                    }
                                });
                                console.warn('[0DIN Sidekick] Navigator fingerprinting:', prop);
                            }

                            self.fingerprintingAttempts.push(fingerprintData);
                            return descriptor.get.call(navigator);
                        }
                    });
                }
            }
        });

        // Monitor screen properties
        const screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];

        screenProps.forEach(prop => {
            const descriptor = Object.getOwnPropertyDescriptor(screen, prop) ||
                             Object.getOwnPropertyDescriptor(Screen.prototype, prop);

            if (descriptor && descriptor.get) {
                Object.defineProperty(screen, prop, {
                    get: function() {
                        const fingerprintData = {
                            category: 'screen',
                            method: prop,
                            value: descriptor.get.call(screen),
                            timestamp: Date.now()
                        };

                        // Report if multiple screen properties accessed
                        if (self.fingerprintingAttempts.filter(f => f.category === 'screen').length > 2) {
                            // Send finding to background
                            chrome.runtime.sendMessage({
                                type: 'ENHANCED_FINDING',
                                finding: {
                                    type: 'fingerprint-screen',
                                    key: prop,
                                    value: fingerprintData,
                                    timestamp: new Date().toISOString(),
                                    url: window.location.href
                                }
                            });
                            console.warn('[0DIN Sidekick] Screen fingerprinting:', prop, fingerprintData.value);
                        }

                        self.fingerprintingAttempts.push(fingerprintData);
                        return fingerprintData.value;
                    }
                });
            }
        });

        // Monitor AudioContext fingerprinting
        if (window.AudioContext || window.webkitAudioContext) {
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            const OriginalAudioContext = AudioContextClass;

            window.AudioContext = window.webkitAudioContext = function(...args) {
                const fingerprintData = {
                    category: 'audio',
                    method: 'AudioContext',
                    timestamp: Date.now()
                };

                // Send finding to background
                chrome.runtime.sendMessage({
                    type: 'ENHANCED_FINDING',
                    finding: {
                        type: 'fingerprint-audio',
                        key: 'AudioContext',
                        value: fingerprintData,
                        timestamp: new Date().toISOString(),
                        url: window.location.href
                    }
                });
                self.fingerprintingAttempts.push(fingerprintData);
                console.warn('[0DIN Sidekick] Audio fingerprinting detected');

                return new OriginalAudioContext(...args);
            };
        }

        console.log('[0DIN Sidekick] Fingerprinting detection initialized');
    }

    // Feature 12: Event Listener Auditor
    auditEventListeners() {
        const originalAddEventListener = EventTarget.prototype.addEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            // Track sensitive events
            const sensitiveEvents = ['copy', 'paste', 'keydown', 'keyup', 'keypress', 'input', 'change'];

            if (sensitiveEvents.includes(type)) {
                const listenerInfo = {
                    target: this.nodeName || 'window',
                    type: type,
                    timestamp: Date.now()
                };

                if (!this.eventListeners.has(type)) {
                    this.eventListeners.set(type, []);
                }
                this.eventListeners.get(type).push(listenerInfo);

                if (type === 'copy' || type === 'paste') {
                    this.reportFinding('clipboard-monitor', type, listenerInfo);
                }
                if (type.includes('key')) {
                    this.reportFinding('keyboard-monitor', type, listenerInfo);
                }
            }

            return originalAddEventListener.call(this, type, listener, options);
        }.bind(this);
    }

    // Feature 13: iframe Security Monitor
    monitorIframes() {
        const checkIframes = () => {
            const iframes = document.querySelectorAll('iframe');
            iframes.forEach(iframe => {
                const iframeInfo = {
                    src: iframe.src,
                    sandbox: iframe.sandbox.value,
                    srcdoc: iframe.srcdoc ? 'present' : 'none',
                    origin: iframe.src ? new URL(iframe.src, location.href).origin : 'same-origin',
                    timestamp: Date.now()
                };

                this.iframes.push(iframeInfo);

                if (!iframe.sandbox.value) {
                    this.reportFinding('iframe-unsandboxed', iframe.src, iframeInfo);
                }

                if (iframeInfo.origin !== location.origin) {
                    this.reportFinding('iframe-cross-origin', iframeInfo.origin, iframeInfo);
                }
            });
        };

        checkIframes();

        // Monitor dynamically added iframes
        const observer = new MutationObserver(checkIframes);
        observer.observe(document.body || document.documentElement, {
            childList: true,
            subtree: true
        });
    }

    // Feature 15: Pattern Learning System
    initPatternLearning() {
        this.patterns = {
            normal: [],
            suspicious: [],

            learn: function(pattern) {
                // Simple pattern learning - in production, use ML
                const key = JSON.stringify({
                    type: pattern.type,
                    domain: pattern.domain,
                    method: pattern.method
                });

                if (!this.normal[key]) {
                    this.normal[key] = 0;
                }
                this.normal[key]++;

                // Flag as suspicious if rare
                if (this.normal[key] < 3) {
                    this.suspicious.push(pattern);
                }
            }
        };
    }

    // Feature 16: API Call Interceptor
    interceptAPICalls() {
        const apis = [
            'fetch', 'XMLHttpRequest', 'sendBeacon', 'navigator.sendBeacon'
        ];

        // Track API usage patterns
        apis.forEach(api => {
            if (api.includes('.')) {
                const [obj, method] = api.split('.');
                if (window[obj] && window[obj][method]) {
                    const original = window[obj][method];
                    window[obj][method] = function(...args) {
                        this.apiCalls.push({
                            api: api,
                            args: args.map(a => this.truncateData(a)),
                            timestamp: Date.now()
                        });

                        // Detect unusual sequences
                        if (this.apiCalls.length > 2) {
                            const recent = this.apiCalls.slice(-3);
                            if (recent.every(c => c.api === api)) {
                                this.reportFinding('api-burst', api, {
                                    count: 3,
                                    duration: recent[2].timestamp - recent[0].timestamp
                                });
                            }
                        }

                        return original.apply(this, args);
                    }.bind(this);
                }
            }
        });
    }

    // Feature 17: DOM Mutation Tracker
    trackDOMMutations() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                const mutationInfo = {
                    type: mutation.type,
                    target: mutation.target.nodeName,
                    timestamp: Date.now()
                };

                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeName === 'SCRIPT') {
                            mutationInfo.script = node.src || 'inline';
                            this.reportFinding('dom-script-injection', mutationInfo.script, mutationInfo);
                        }
                        if (node.nodeName === 'LINK' && node.rel === 'stylesheet') {
                            mutationInfo.stylesheet = node.href;
                            this.reportFinding('dom-style-injection', mutationInfo.stylesheet, mutationInfo);
                        }
                    });
                }

                if (mutation.type === 'attributes') {
                    if (mutation.attributeName === 'src' || mutation.attributeName === 'href') {
                        mutationInfo.attribute = mutation.attributeName;
                        mutationInfo.value = mutation.target[mutation.attributeName];
                        this.reportFinding('dom-attribute-change', mutationInfo.attribute, mutationInfo);
                    }
                }

                this.domMutations.push(mutationInfo);
            });
        });

        observer.observe(document.body || document.documentElement, {
            childList: true,
            attributes: true,
            subtree: true,
            attributeOldValue: true
        });
    }

    // Feature 18: Privacy Budget Monitor
    monitorPrivacyBudget() {
        // Monitor privacy-related APIs
        const privacyAPIs = [
            'navigator.getBattery',
            'navigator.geolocation',
            'navigator.mediaDevices',
            'navigator.permissions'
        ];

        privacyAPIs.forEach(api => {
            const parts = api.split('.');
            let obj = window;
            for (let i = 0; i < parts.length - 1; i++) {
                obj = obj[parts[i]];
                if (!obj) return;
            }

            const method = parts[parts.length - 1];
            if (obj[method]) {
                const original = obj[method];
                obj[method] = function(...args) {
                    this.reportFinding('privacy-api-access', api, {
                        timestamp: Date.now()
                    });
                    return original.apply(this, args);
                }.bind(this);
            }
        });
    }

    // Utility functions
    truncateData(data) {
        const str = typeof data === 'string' ? data : JSON.stringify(data);
        return str ? str.substring(0, 100) + (str.length > 100 ? '...' : '') : '';
    }

    detectDataType(data) {
        try {
            JSON.parse(data);
            return 'json';
        } catch {
            if (data.startsWith('eyJ')) return 'jwt';
            if (data.includes('=')) return 'base64';
            return 'string';
        }
    }

    isSensitive(data) {
        const classifications = this.dataClassifier ? this.dataClassifier.classify(data) : [];
        return classifications.length > 0;
    }

    reportFinding(type, key, value) {
        chrome.runtime.sendMessage({
            type: 'ENHANCED_FINDING',
            finding: {
                type,
                key,
                value: this.truncateData(value),
                timestamp: new Date().toISOString(),
                url: window.location.href
            }
        });
    }

    // Message handler for popup communication
    setupMessageHandlers() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            switch (request.action) {
                case 'deepScan':
                    this.performDeepScan();
                    sendResponse({ success: true });
                    break;

                case 'analyzeStorage':
                    this.analyzeStorage();
                    sendResponse({
                        storage: {
                            localStorage: {
                                items: localStorage.length,
                                sensitive: Object.values(this.storageSnapshot.localStorage || {})
                                    .filter(item => item.sensitive).length
                            },
                            sessionStorage: {
                                items: sessionStorage.length,
                                sensitive: Object.values(this.storageSnapshot.sessionStorage || {})
                                    .filter(item => item.sensitive).length
                            },
                            cookies: {
                                total: document.cookie.split(';').filter(c => c.trim()).length,
                                tracking: document.cookie.split(';').filter(c => /ga|utm|fbp/i.test(c)).length
                            },
                            indexedDB: {
                                databases: this.storageSnapshot.indexedDB ? .length || 0
                            },
                            cache: {
                                caches: 0 // Would need async implementation
                            }
                        }
                    });
                    break;

                case 'getReport':
                    sendResponse({
                        dataFlows: Array.from(this.dataFlows.entries()),
                        permissions: Array.from(this.permissions),
                        networkPatterns: this.networkPatterns,
                        crossOriginRequests: this.crossOriginRequests,
                        cspViolations: this.cspViolations,
                        thirdPartyScripts: Array.from(this.thirdPartyScripts),
                        fingerprintingAttempts: this.fingerprintingAttempts,
                        eventListeners: Array.from(this.eventListeners.entries()),
                        iframes: this.iframes,
                        apiCalls: this.apiCalls,
                        domMutations: this.domMutations,
                        classifiedData: this.classifiedData,
                        websocketConnections: this.websocketConnections,
                        privacyBudget: this.privacyBudget
                    });
                    break;

                default:
                    sendResponse({ error: 'Unknown action' });
            }
        });
    }

    performDeepScan() {
        console.log('[0DIN Sidekick] Performing deep security scan...');

        // Re-run all analyses
        this.analyzeStorage();
        this.auditThirdPartyScripts();
        this.monitorIframes();

        // Scan all text content for sensitive data
        const allText = document.body.innerText;
        const classifications = this.dataClassifier.classify(allText);

        classifications.forEach(classification => {
            this.reportFinding('deep-scan-classification', classification, {
                type: classification,
                timestamp: Date.now()
            });
        });

        // Check all input fields
        document.querySelectorAll('input, textarea').forEach(input => {
            if (input.value) {
                const inputClassifications = this.dataClassifier.classify(input.value);
                if (inputClassifications.length > 0) {
                    this.reportFinding('input-field-sensitive', input.name || input.id, {
                        classifications: inputClassifications,
                        fieldType: input.type
                    });
                }
            }
        });

        console.log('[0DIN Sidekick] Deep scan completed');
    }
}

// Initialize enhanced monitor
const enhancedMonitor = new EnhancedSecurityMonitor();
console.log('✅ Enhanced security monitoring initialized with all features');

// Listen for fingerprinting messages from the injected script
window.addEventListener('message', (event) => {
    if (event.data && event.data.source === '0DIN-fingerprint') {
        console.log('[0DIN Sidekick] Received fingerprint detection:', event.data.finding);

        // Forward to background script
        chrome.runtime.sendMessage({
            type: 'ENHANCED_FINDING',
            finding: {
                type: event.data.finding.type,
                key: event.data.finding.method,
                value: event.data.finding.details,
                timestamp: new Date().toISOString(),
                url: window.location.href
            }
        }, (response) => {
            console.log('[0DIN Sidekick] Fingerprint finding forwarded:', response);
        });
    }
});

console.log('[0DIN Sidekick] Fingerprinting message listener installed');