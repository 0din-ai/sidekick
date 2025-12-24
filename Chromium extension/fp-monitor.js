/**
 * Fingerprint Monitor - Content Script
 * Monitors for fingerprinting attempts similar to how cookies are monitored
 */

console.log('[FP Monitor] Initializing fingerprint monitoring...');

// Function to detect and report fingerprinting
function reportFingerprint(type, method, details) {
    console.warn(`[FP Monitor] 🎯 FINGERPRINT DETECTED: ${type}::${method}`);

    const finding = {
        type: 'fp-detection',
        key: `${type}-${method}`,
        value: details || '[Fingerprint Attempt]',
        category: type,  // Add for popup display
        method: method,   // Add for popup display
        domain: window.location.hostname,
        path: window.location.pathname,
        timestamp: new Date().toISOString()
    };

    // Send directly as SECURITY_FINDING (like cookies do)
    chrome.runtime.sendMessage({
        type: 'SECURITY_FINDING',
        finding: finding
    }, (response) => {
        if (chrome.runtime.lastError) {
            console.error('[FP Monitor] Error:', chrome.runtime.lastError);
        } else {
            console.log('[FP Monitor] Sent to background');
        }
    });
}

// Monitor canvas operations by checking periodically
function monitorCanvas() {
    // Override toDataURL
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
        reportFingerprint('canvas', 'toDataURL', {
            width: this.width,
            height: this.height
        });
        return originalToDataURL.apply(this, args);
    };

    // Override getImageData
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

    console.log('[FP Monitor] Canvas monitoring active');
}

// Monitor WebGL
function monitorWebGL() {
    if (window.WebGLRenderingContext) {
        const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(param) {
            // Common fingerprinting parameters
            if (param === 0x1F00 || param === 0x1F01 || param === 0x1F02 ||
                param === 0x9245 || param === 0x9246) {
                reportFingerprint('webgl', 'getParameter', {
                    parameter: param
                });
            }
            return originalGetParameter.apply(this, arguments);
        };
        console.log('[FP Monitor] WebGL monitoring active');
    }
}

// Monitor Audio
function monitorAudio() {
    if (window.AudioContext || window.webkitAudioContext) {
        const OriginalAudioContext = window.AudioContext || window.webkitAudioContext;
        const NewAudioContext = function(...args) {
            reportFingerprint('audio', 'AudioContext', {
                sampleRate: 44100
            });
            return new OriginalAudioContext(...args);
        };

        if (window.AudioContext) window.AudioContext = NewAudioContext;
        if (window.webkitAudioContext) window.webkitAudioContext = NewAudioContext;

        console.log('[FP Monitor] Audio monitoring active');
    }
}

// Monitor font fingerprinting
function monitorFonts() {
    if (document.fonts && document.fonts.check) {
        const originalCheck = document.fonts.check;
        document.fonts.check = function(...args) {
            reportFingerprint('font', 'check', {
                font: args[0]
            });
            return originalCheck.apply(this, args);
        };
        console.log('[FP Monitor] Font monitoring active');
    }
}

// Initialize all monitors
try {
    monitorCanvas();
    monitorWebGL();
    monitorAudio();
    monitorFonts();

    // Send a test fingerprint to verify it's working
    setTimeout(() => {
        console.log('[FP Monitor] Sending test fingerprint...');
        reportFingerprint('test', 'initialization', {
            message: 'Fingerprint monitoring initialized'
        });
    }, 1000);

    console.log('[FP Monitor] All monitors activated successfully');
} catch (error) {
    console.error('[FP Monitor] Error setting up monitors:', error);
}

// Inject monitoring hooks directly into the page
const injectionScript = document.createElement('script');
injectionScript.textContent = `
    (function() {
        console.log('[FP Page] Installing in-page fingerprint hooks...');

        // Store original methods
        const originals = {
            toDataURL: HTMLCanvasElement.prototype.toDataURL,
            getImageData: CanvasRenderingContext2D.prototype.getImageData,
            getParameter: WebGLRenderingContext.prototype ? WebGLRenderingContext.prototype.getParameter : null,
            AudioContext: window.AudioContext || window.webkitAudioContext
        };

        // Hook Canvas toDataURL
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
            console.warn('[FP Page] 🎯 Canvas toDataURL called!');
            window.postMessage({fpDetected: 'canvas', method: 'toDataURL'}, '*');
            return originals.toDataURL.apply(this, args);
        };

        // Hook Canvas getImageData
        CanvasRenderingContext2D.prototype.getImageData = function(...args) {
            console.warn('[FP Page] 🎯 Canvas getImageData called!');
            window.postMessage({fpDetected: 'canvas', method: 'getImageData'}, '*');
            return originals.getImageData.apply(this, args);
        };

        // Hook WebGL
        if (originals.getParameter) {
            WebGLRenderingContext.prototype.getParameter = function(param) {
                if (param === 0x1F00 || param === 0x1F01 || param === 0x1F02) {
                    console.warn('[FP Page] 🎯 WebGL getParameter called!');
                    window.postMessage({fpDetected: 'webgl', method: 'getParameter'}, '*');
                }
                return originals.getParameter.apply(this, arguments);
            };
        }

        // Hook AudioContext
        if (originals.AudioContext) {
            window.AudioContext = function(...args) {
                console.warn('[FP Page] 🎯 AudioContext created!');
                window.postMessage({fpDetected: 'audio', method: 'AudioContext'}, '*');
                return new originals.AudioContext(...args);
            };
            if (window.webkitAudioContext) {
                window.webkitAudioContext = window.AudioContext;
            }
        }

        window.__fpMonitorActive = true;
        console.log('[FP Page] In-page hooks installed successfully!');
    })();
`;

// Inject ASAP
if (document.documentElement) {
    document.documentElement.appendChild(injectionScript);
    injectionScript.remove();
} else {
    // If documentElement not ready, wait for it
    const observer = new MutationObserver((mutations, obs) => {
        if (document.documentElement) {
            document.documentElement.appendChild(injectionScript);
            injectionScript.remove();
            obs.disconnect();
        }
    });
    observer.observe(document, { childList: true, subtree: true });
}

// Listen for messages from injected script
window.addEventListener('message', (event) => {
    if (event.data && event.data.fpDetected) {
        console.log('[FP Monitor] Received from page:', event.data);
        reportFingerprint(event.data.fpDetected, event.data.method, {
            detected: true,
            source: 'page-hook'
        });
    }
});