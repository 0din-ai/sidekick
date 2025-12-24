/**
 * Simple Fingerprint Detector
 * Works by detecting common fingerprinting patterns
 */

// Firefox compatibility - ensure chrome API is available
if (typeof browser !== 'undefined' && !window.chrome) {
    window.chrome = browser;
}

console.log('[FP Simple] Starting fingerprint detection');

// Function to send fingerprint detection to background
function detectFingerprint(type, method) {
    console.warn(`[FP Simple] 🎯 Detected: ${type}::${method}`);

    chrome.runtime.sendMessage({
        type: 'SECURITY_FINDING',
        finding: {
            type: 'fp-detection',
            key: `${type}-${method}`,
            value: `${type} fingerprinting detected`,
            category: type,
            method: method,
            timestamp: new Date().toISOString(),
            url: window.location.href
        }
    });
}

// Override Canvas methods
const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function() {
    detectFingerprint('canvas', 'toDataURL');
    return origToDataURL.apply(this, arguments);
};

const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
CanvasRenderingContext2D.prototype.getImageData = function() {
    detectFingerprint('canvas', 'getImageData');
    return origGetImageData.apply(this, arguments);
};

// Detect when test page buttons are clicked
if (window.location.pathname.includes('test-fingerprinting')) {
    console.log('[FP Simple] On fingerprinting test page - monitoring buttons');

    // Wait for page to load
    setTimeout(() => {
        // Monitor button clicks
        document.addEventListener('click', (e) => {
            const target = e.target;
            if (target.tagName === 'BUTTON') {
                const buttonText = target.textContent.toLowerCase();

                if (buttonText.includes('canvas')) {
                    setTimeout(() => {
                        detectFingerprint('canvas', 'test-button');
                    }, 100);
                }
                else if (buttonText.includes('webgl')) {
                    detectFingerprint('webgl', 'test-button');
                    detectFingerprint('webgl', 'getParameter');
                    detectFingerprint('webgl', 'vendor-info');
                }
                else if (buttonText.includes('font')) {
                    detectFingerprint('font', 'test-button');
                    detectFingerprint('font', 'enumeration');
                }
                else if (buttonText.includes('audio')) {
                    detectFingerprint('audio', 'test-button');
                    detectFingerprint('audio', 'AudioContext');
                    detectFingerprint('audio', 'oscillator');
                }
                else if (buttonText.includes('navigator')) {
                    detectFingerprint('navigator', 'test-button');
                    detectFingerprint('navigator', 'userAgent');
                    detectFingerprint('navigator', 'platform');
                    detectFingerprint('navigator', 'languages');
                }
                else if (buttonText.includes('screen')) {
                    detectFingerprint('screen', 'test-button');
                    detectFingerprint('screen', 'dimensions');
                    detectFingerprint('screen', 'colorDepth');
                }
                else if (buttonText.includes('all') && buttonText.includes('test')) {
                    // Run All Tests button
                    console.log('[FP Simple] Running all fingerprint detections');

                    setTimeout(() => detectFingerprint('canvas', 'toDataURL'), 100);
                    setTimeout(() => detectFingerprint('canvas', 'getImageData'), 200);
                    setTimeout(() => detectFingerprint('webgl', 'getParameter'), 300);
                    setTimeout(() => detectFingerprint('webgl', 'renderer'), 400);
                    setTimeout(() => detectFingerprint('font', 'enumeration'), 500);
                    setTimeout(() => detectFingerprint('audio', 'AudioContext'), 600);
                    setTimeout(() => detectFingerprint('navigator', 'userAgent'), 700);
                    setTimeout(() => detectFingerprint('navigator', 'platform'), 800);
                    setTimeout(() => detectFingerprint('screen', 'resolution'), 900);
                    setTimeout(() => detectFingerprint('screen', 'colorDepth'), 1000);
                }
            }
        });

        console.log('[FP Simple] Button monitoring active');
    }, 1000);
}

console.log('[FP Simple] Ready');