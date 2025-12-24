/**
 * Content script that injects fingerprinting detection into the page
 */

console.log('[0DIN Sidekick] Injecting fingerprint detection script...');

// Check if chrome runtime is available
if (typeof chrome === 'undefined' || !chrome.runtime) {
    console.error('[0DIN Sidekick] Chrome runtime not available!');
} else {
    console.log('[0DIN Sidekick] Chrome runtime is available');
}

// Create and inject the script
const script = document.createElement('script');
script.textContent = `
(function() {
    console.log('[0DIN Sidekick] Fingerprint detection running in page context');

    // Store original methods
    const originals = {
        toDataURL: HTMLCanvasElement.prototype.toDataURL,
        toBlob: HTMLCanvasElement.prototype.toBlob,
        getImageData: CanvasRenderingContext2D.prototype.getImageData,
        getParameter: WebGLRenderingContext.prototype.getParameter,
        AudioContext: window.AudioContext || window.webkitAudioContext,
        OfflineAudioContext: window.OfflineAudioContext,
        fontsCheck: document.fonts ? document.fonts.check : null
    };

    // Helper to send detection events
    function detectFingerprint(type, method, details) {
        const message = {
            source: '0DIN-fingerprint',
            type: type,
            method: method,
            details: details,
            timestamp: Date.now(),
            url: window.location.href
        };

        // Use postMessage for cross-context communication
        window.postMessage(message, '*');

        // Also try CustomEvent as backup
        const event = new CustomEvent('0DIN-fingerprint-detected', {
            detail: message
        });
        window.dispatchEvent(event);

        console.warn('[0DIN Sidekick] Fingerprinting detected:', type + '::' + method, details);
    }

    // 1. Canvas fingerprinting
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
        detectFingerprint('canvas', 'toDataURL', {
            width: this.width,
            height: this.height
        });
        return originals.toDataURL.apply(this, args);
    };

    HTMLCanvasElement.prototype.toBlob = function(...args) {
        detectFingerprint('canvas', 'toBlob', {
            width: this.width,
            height: this.height
        });
        return originals.toBlob.apply(this, args);
    };

    CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
        detectFingerprint('canvas', 'getImageData', {
            x: x, y: y, width: w, height: h
        });
        return originals.getImageData.apply(this, arguments);
    };

    // 2. WebGL fingerprinting
    WebGLRenderingContext.prototype.getParameter = function(param) {
        const result = originals.getParameter.apply(this, arguments);
        const fingerprintParams = {
            7936: 'VENDOR',
            7937: 'RENDERER',
            7938: 'VERSION',
            37445: 'UNMASKED_VENDOR_WEBGL',
            37446: 'UNMASKED_RENDERER_WEBGL'
        };

        if (fingerprintParams[param]) {
            detectFingerprint('webgl', fingerprintParams[param], {
                parameter: param,
                value: result
            });
        }
        return result;
    };

    // 3. Audio fingerprinting
    if (originals.AudioContext) {
        window.AudioContext = function(...args) {
            detectFingerprint('audio', 'AudioContext', {
                sampleRate: 44100
            });
            return new originals.AudioContext(...args);
        };
        if (window.webkitAudioContext) {
            window.webkitAudioContext = window.AudioContext;
        }
    }

    if (originals.OfflineAudioContext) {
        window.OfflineAudioContext = function(...args) {
            detectFingerprint('audio', 'OfflineAudioContext', {
                channels: args[0],
                length: args[1],
                sampleRate: args[2]
            });
            return new originals.OfflineAudioContext(...args);
        };
    }

    // 4. Font fingerprinting
    if (originals.fontsCheck) {
        document.fonts.check = function(...args) {
            detectFingerprint('font', 'check', {
                font: args[0]
            });
            return originals.fontsCheck.apply(document.fonts, args);
        };
    }

    // 5. Navigator fingerprinting
    const navProps = ['userAgent', 'platform', 'languages', 'hardwareConcurrency', 'deviceMemory'];
    navProps.forEach(prop => {
        const originalValue = navigator[prop];
        if (originalValue !== undefined) {
            Object.defineProperty(navigator, prop, {
                get: function() {
                    detectFingerprint('navigator', prop, {
                        value: originalValue
                    });
                    return originalValue;
                }
            });
        }
    });

    // 6. Screen fingerprinting
    const screenProps = ['width', 'height', 'colorDepth', 'pixelDepth'];
    screenProps.forEach(prop => {
        const originalValue = screen[prop];
        if (originalValue !== undefined) {
            Object.defineProperty(screen, prop, {
                get: function() {
                    detectFingerprint('screen', prop, {
                        value: originalValue
                    });
                    return originalValue;
                }
            });
        }
    });

    console.log('[0DIN Sidekick] All fingerprint detection hooks installed!');

    // Test the detection immediately
    setTimeout(() => {
        console.log('[0DIN Sidekick] Testing fingerprint detection...');

        // Test canvas
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.toDataURL();
            console.log('[0DIN Sidekick] Canvas test completed');
        } catch (e) {
            console.error('[0DIN Sidekick] Canvas test error:', e);
        }

        // Test navigator
        try {
            const ua = navigator.userAgent;
            console.log('[0DIN Sidekick] Navigator test completed');
        } catch (e) {
            console.error('[0DIN Sidekick] Navigator test error:', e);
        }
    }, 2000);
})();
`;

// Inject at the very beginning of the document
if (document.documentElement) {
    document.documentElement.appendChild(script);
    script.remove();
} else {
    // If documentElement doesn't exist yet, wait for it
    const observer = new MutationObserver((mutations, obs) => {
        if (document.documentElement) {
            document.documentElement.appendChild(script);
            script.remove();
            obs.disconnect();
        }
    });
    observer.observe(document, { childList: true, subtree: true });
}

// Listen for messages from the injected script
window.addEventListener('message', (event) => {
    // Check if it's our fingerprint message
    if (event.data && event.data.source === '0DIN-fingerprint') {
        console.log('[0DIN Sidekick] Fingerprint detected via postMessage:', event.data);

        // Send to background script
        try {
            chrome.runtime.sendMessage({
                type: 'ENHANCED_FINDING',
                finding: {
                    type: 'fingerprint-' + event.data.type,
                    key: event.data.method,
                    value: event.data.details,
                    category: event.data.type,
                    method: event.data.method,
                    timestamp: new Date().toISOString(),
                    url: window.location.href
                }
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error('[0DIN Sidekick] Error sending fingerprint:', chrome.runtime.lastError);
                } else {
                    console.log('[0DIN Sidekick] Fingerprint sent to background, response:', response);
                }
            });
        } catch (error) {
            console.error('[0DIN Sidekick] Exception sending message:', error);
        }
    }
});

// Also listen for custom events as backup
window.addEventListener('0DIN-fingerprint-detected', (event) => {
    console.log('[0DIN Sidekick] Fingerprint detected via CustomEvent:', event.detail);

    // Try sending to background script
    try {
        chrome.runtime.sendMessage({
            type: 'ENHANCED_FINDING',
            finding: {
                type: 'fingerprint-' + event.detail.type,
                key: event.detail.method,
                value: event.detail.details,
                category: event.detail.type,
                method: event.detail.method,
                timestamp: new Date().toISOString(),
                url: window.location.href
            }
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.error('[0DIN Sidekick] Error sending fingerprint:', chrome.runtime.lastError);

                // Try alternative approach - send a simple test message
                chrome.runtime.sendMessage({
                    type: 'TEST',
                    message: 'Testing connection'
                }, (testResponse) => {
                    console.log('[0DIN Sidekick] Test message response:', testResponse, chrome.runtime.lastError);
                });
            } else {
                console.log('[0DIN Sidekick] Fingerprint sent to background, response:', response);
            }
        });
    } catch (error) {
        console.error('[0DIN Sidekick] Exception sending message:', error);
    }
});

console.log('[0DIN Sidekick] Fingerprint detection injected and listening');

// Test immediate message sending
setTimeout(() => {
    console.log('[0DIN Sidekick] Sending test message to background...');
    chrome.runtime.sendMessage({
        type: 'ENHANCED_FINDING',
        finding: {
            type: 'fingerprint-test-init',
            key: 'initialization',
            value: { test: true },
            timestamp: new Date().toISOString(),
            url: window.location.href
        }
    }, (response) => {
        console.log('[0DIN Sidekick] Test init response:', response, chrome.runtime.lastError);
    });
}, 1000);