/**
 * Simple fingerprint detection that actually works
 */

console.log('[0DIN Sidekick] Fingerprint detector starting...');

// Inject detection script immediately
const injectedCode = `
(function() {
    console.log('[0DIN Sidekick] Installing fingerprint hooks in page context');

    // Flag to track if hooks are installed
    window.__0DIN_hooks_installed = true;

    // Store detections
    window.__0DIN_detections = [];

    // Hook Canvas toDataURL
    const original_toDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
        console.warn('[0DIN Sidekick] 🎯 FINGERPRINT: Canvas toDataURL called');
        window.__0DIN_detections.push({
            type: 'canvas',
            method: 'toDataURL',
            timestamp: Date.now()
        });
        window.postMessage({
            source: '0DIN_FINGERPRINT',
            type: 'canvas',
            method: 'toDataURL',
            timestamp: Date.now()
        }, '*');
        return original_toDataURL.apply(this, arguments);
    };

    // Hook Canvas getImageData
    const original_getImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function() {
        console.warn('[0DIN Sidekick] 🎯 FINGERPRINT: Canvas getImageData called');
        window.postMessage({
            source: '0DIN_FINGERPRINT',
            type: 'canvas',
            method: 'getImageData',
            timestamp: Date.now()
        }, '*');
        return original_getImageData.apply(this, arguments);
    };

    // Hook WebGL getParameter
    if (window.WebGLRenderingContext) {
        const original_getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(param) {
            if (param === 0x1F00 || param === 0x1F01 || param === 0x1F02) {
                console.warn('[0DIN Sidekick] 🎯 FINGERPRINT: WebGL getParameter called');
                window.postMessage({
                    source: '0DIN_FINGERPRINT',
                    type: 'webgl',
                    method: 'getParameter',
                    param: param,
                    timestamp: Date.now()
                }, '*');
            }
            return original_getParameter.apply(this, arguments);
        };
    }

    // Hook AudioContext
    if (window.AudioContext) {
        const OriginalAudioContext = window.AudioContext;
        window.AudioContext = function() {
            console.warn('[0DIN Sidekick] 🎯 FINGERPRINT: AudioContext created');
            window.postMessage({
                source: '0DIN_FINGERPRINT',
                type: 'audio',
                method: 'AudioContext',
                timestamp: Date.now()
            }, '*');
            return new OriginalAudioContext(...arguments);
        };
    }

    // Hook font checking
    if (document.fonts && document.fonts.check) {
        const original_check = document.fonts.check;
        document.fonts.check = function(font) {
            console.warn('[0DIN Sidekick] 🎯 FINGERPRINT: Font check:', font);
            window.postMessage({
                source: '0DIN_FINGERPRINT',
                type: 'font',
                method: 'check',
                font: font,
                timestamp: Date.now()
            }, '*');
            return original_check.apply(this, arguments);
        };
    }

    console.log('[0DIN Sidekick] ✅ Fingerprint hooks installed successfully!');

    // Test the hooks after 1 second
    setTimeout(() => {
        console.log('[0DIN Sidekick] Testing hooks...');
        try {
            const testCanvas = document.createElement('canvas');
            const ctx = testCanvas.getContext('2d');
            testCanvas.toDataURL();
            console.log('[0DIN Sidekick] Hook test complete - check for detection message above');
        } catch(e) {
            console.error('[0DIN Sidekick] Hook test error:', e);
        }
    }, 1000);
})();
`;

// Method 1: Inject via script tag
function injectViaScript() {
    const script = document.createElement('script');
    script.textContent = injectedCode;
    (document.head || document.documentElement).appendChild(script);
    script.remove();
    console.log('[0DIN Sidekick] Injected via script tag');
}

// Method 2: Inject via page context
function injectViaPageContext() {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('page-fingerprint.js');
    (document.head || document.documentElement).appendChild(script);
    script.onload = function() {
        script.remove();
    };
}

// Try injection immediately
if (document.documentElement) {
    injectViaScript();
} else {
    // Wait for document to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectViaScript);
    } else {
        injectViaScript();
    }
}

// Listen for fingerprint detections
window.addEventListener('message', function(event) {
    if (event.data && event.data.source === '0DIN_FINGERPRINT') {
        console.log('[0DIN Sidekick] 📍 Fingerprint detected in content script:', event.data);

        // Send to background with properly formatted data
        const finding = {
            type: `fingerprint-${event.data.type}`,
            key: event.data.method,
            value: event.data,
            category: event.data.type,  // Add category for display
            method: event.data.method,   // Add method for display
            timestamp: new Date().toISOString(),
            url: window.location.href
        };

        // Try to send to background
        if (chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({
                type: 'ENHANCED_FINDING',
                finding: finding
            }, function(response) {
                if (chrome.runtime.lastError) {
                    console.error('[0DIN Sidekick] ❌ Error sending to background:', chrome.runtime.lastError);

                    // Fallback: Try sending directly as SECURITY_FINDING
                    chrome.runtime.sendMessage({
                        type: 'SECURITY_FINDING',
                        finding: finding
                    });
                } else {
                    console.log('[0DIN Sidekick] ✅ Sent to background successfully:', response);
                }
            });
        } else {
            console.error('[0DIN Sidekick] Chrome runtime not available');
        }
    }
});

console.log('[0DIN Sidekick] Content script ready and listening for fingerprints');

// Verify connection to background
chrome.runtime.sendMessage({
    type: 'ENHANCED_FINDING',
    finding: {
        type: 'fingerprint-init',
        key: 'test',
        value: { message: 'Fingerprint detector initialized' },
        timestamp: new Date().toISOString(),
        url: window.location.href
    }
}, function(response) {
    if (chrome.runtime.lastError) {
        console.error('[0DIN Sidekick] Cannot connect to background:', chrome.runtime.lastError);
    } else {
        console.log('[0DIN Sidekick] Connected to background:', response);
    }
});