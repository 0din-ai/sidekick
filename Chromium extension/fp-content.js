/**
 * Fingerprint Detection Content Script
 * Runs in isolated context, doesn't violate CSP
 */

console.log('[FP Content] Fingerprint detection initializing...');

// Track fingerprinting attempts
let fingerprintCount = 0;

// Function to report fingerprints to background
function reportFingerprint(type, method, details) {
    fingerprintCount++;
    console.warn(`[FP Content] 🎯 FINGERPRINT #${fingerprintCount}: ${type}::${method}`);

    const finding = {
        type: 'fp-detection',
        key: `${type}-${method}`,
        value: details || { detected: true },
        category: type,
        method: method,
        domain: window.location.hostname,
        path: window.location.pathname,
        timestamp: new Date().toISOString(),
        url: window.location.href
    };

    // Send to background
    chrome.runtime.sendMessage({
        type: 'SECURITY_FINDING',
        finding: finding
    }, (response) => {
        if (chrome.runtime.lastError) {
            console.error('[FP Content] Error:', chrome.runtime.lastError);
        } else {
            console.log('[FP Content] Sent to background');
        }
    });
}

// Override methods in the content script context
// This doesn't violate CSP because it runs in the isolated world

// Monitor Canvas
const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(...args) {
    reportFingerprint('canvas', 'toDataURL', {
        width: this.width,
        height: this.height
    });
    return originalToDataURL.apply(this, args);
};

const originalToBlob = HTMLCanvasElement.prototype.toBlob;
HTMLCanvasElement.prototype.toBlob = function(...args) {
    reportFingerprint('canvas', 'toBlob', {
        width: this.width,
        height: this.height
    });
    return originalToBlob.apply(this, args);
};

const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
CanvasRenderingContext2D.prototype.getImageData = function(...args) {
    reportFingerprint('canvas', 'getImageData', {
        x: args[0],
        y: args[1],
        width: args[2],
        height: args[3]
    });
    return originalGetImageData.apply(this, args);
};

// Monitor WebGL
if (typeof WebGLRenderingContext !== 'undefined') {
    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
        // Common fingerprinting parameters
        const fingerprintParams = {
            0x1F00: 'VENDOR',
            0x1F01: 'RENDERER',
            0x1F02: 'VERSION',
            0x9245: 'UNMASKED_VENDOR_WEBGL',
            0x9246: 'UNMASKED_RENDERER_WEBGL'
        };

        if (fingerprintParams[param]) {
            reportFingerprint('webgl', fingerprintParams[param], {
                parameter: param
            });
        }
        return originalGetParameter.apply(this, arguments);
    };
}

// Monitor WebGL2
if (typeof WebGL2RenderingContext !== 'undefined') {
    const originalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {
        const fingerprintParams = {
            0x1F00: 'VENDOR',
            0x1F01: 'RENDERER',
            0x1F02: 'VERSION',
            0x9245: 'UNMASKED_VENDOR_WEBGL',
            0x9246: 'UNMASKED_RENDERER_WEBGL'
        };

        if (fingerprintParams[param]) {
            reportFingerprint('webgl2', fingerprintParams[param], {
                parameter: param
            });
        }
        return originalGetParameter2.apply(this, arguments);
    };
}

// Monitor AudioContext
if (typeof AudioContext !== 'undefined') {
    const OriginalAudioContext = AudioContext;
    window.AudioContext = function(...args) {
        reportFingerprint('audio', 'AudioContext', {
            sampleRate: 44100
        });
        return new OriginalAudioContext(...args);
    };
}

if (typeof webkitAudioContext !== 'undefined') {
    const OriginalWebkitAudioContext = webkitAudioContext;
    window.webkitAudioContext = function(...args) {
        reportFingerprint('audio', 'webkitAudioContext', {
            sampleRate: 44100
        });
        return new OriginalWebkitAudioContext(...args);
    };
}

// Monitor OfflineAudioContext
if (typeof OfflineAudioContext !== 'undefined') {
    const OriginalOfflineAudioContext = OfflineAudioContext;
    window.OfflineAudioContext = function(...args) {
        reportFingerprint('audio', 'OfflineAudioContext', {
            channels: args[0],
            length: args[1],
            sampleRate: args[2]
        });
        return new OriginalOfflineAudioContext(...args);
    };
}

// Monitor font checking
if (document.fonts && document.fonts.check) {
    const originalCheck = document.fonts.check;
    document.fonts.check = function(...args) {
        reportFingerprint('font', 'check', {
            font: args[0]
        });
        return originalCheck.apply(document.fonts, args);
    };
}

// Monitor navigator properties
const navProps = ['userAgent', 'platform', 'language', 'languages',
                  'hardwareConcurrency', 'deviceMemory', 'maxTouchPoints'];

navProps.forEach(prop => {
    if (prop in navigator) {
        const originalValue = navigator[prop];
        try {
            Object.defineProperty(navigator, prop, {
                get: function() {
                    reportFingerprint('navigator', prop, {
                        value: originalValue
                    });
                    return originalValue;
                },
                configurable: true
            });
        } catch(e) {
            // Some properties might not be configurable
        }
    }
});

// Monitor screen properties
const screenProps = ['width', 'height', 'availWidth', 'availHeight',
                     'colorDepth', 'pixelDepth'];

screenProps.forEach(prop => {
    if (prop in screen) {
        const originalValue = screen[prop];
        try {
            Object.defineProperty(screen, prop, {
                get: function() {
                    reportFingerprint('screen', prop, {
                        value: originalValue
                    });
                    return originalValue;
                },
                configurable: true
            });
        } catch(e) {
            // Some properties might not be configurable
        }
    }
});

console.log('[FP Content] Fingerprint detection ready!');

// Also monitor by observing DOM changes and method calls
let checkInterval = setInterval(() => {
    // Check if WebGL context is created
    const canvases = document.querySelectorAll('canvas');
    canvases.forEach(canvas => {
        if (canvas.getContext && !canvas._fpChecked) {
            canvas._fpChecked = true;

            // Check for WebGL context
            try {
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl') || canvas.getContext('webgl2');
                if (gl) {
                    reportFingerprint('webgl', 'context-created', {
                        type: gl.constructor.name
                    });
                }
            } catch(e) {}
        }
    });
}, 1000);

// Test detection after 3 seconds
setTimeout(() => {
    console.log('[FP Content] Running self-test...');
    try {
        // Test Canvas
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.fillText('test', 10, 10);
        canvas.toDataURL();

        // Test WebGL
        const glCanvas = document.createElement('canvas');
        const gl = glCanvas.getContext('webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            }
        }

        // Test Audio
        if (typeof AudioContext !== 'undefined') {
            new AudioContext();
        }

        console.log('[FP Content] Self-test complete');
    } catch(e) {
        console.error('[FP Content] Self-test error:', e);
    }
}, 3000);

// Clean up after 30 seconds
setTimeout(() => {
    clearInterval(checkInterval);
}, 30000);