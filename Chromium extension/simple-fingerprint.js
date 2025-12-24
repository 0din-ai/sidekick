// Simple fingerprint detection that works
console.log('[0DIN] Simple fingerprint detector loading...');

// Create script to inject
const script = document.createElement('script');
script.textContent = `
    console.log('[0DIN] Injecting fingerprint hooks...');

    // Hook Canvas
    const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
        console.log('[0DIN] CANVAS FINGERPRINT DETECTED');
        window.postMessage({0DIN: 'canvas', method: 'toDataURL'}, '*');
        return _toDataURL.apply(this, arguments);
    };

    const _getImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function() {
        console.log('[0DIN] CANVAS FINGERPRINT DETECTED');
        window.postMessage({0DIN: 'canvas', method: 'getImageData'}, '*');
        return _getImageData.apply(this, arguments);
    };

    // Hook WebGL
    if (window.WebGLRenderingContext) {
        const _getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(p) {
            if (p === 0x1F00 || p === 0x1F01) {
                console.log('[0DIN] WEBGL FINGERPRINT DETECTED');
                window.postMessage({0DIN: 'webgl', method: 'getParameter'}, '*');
            }
            return _getParameter.apply(this, arguments);
        };
    }

    // Hook Audio
    if (window.AudioContext) {
        const _AudioContext = window.AudioContext;
        window.AudioContext = function() {
            console.log('[0DIN] AUDIO FINGERPRINT DETECTED');
            window.postMessage({0DIN: 'audio', method: 'AudioContext'}, '*');
            return new _AudioContext(...arguments);
        };
    }

    console.log('[0DIN] Hooks installed!');
`;

// Inject immediately
if (document.documentElement) {
    document.documentElement.appendChild(script);
    script.remove();
}

// Listen for messages
window.addEventListener('message', (e) => {
    if (e.data && e.data.0DIN) {
        console.log('[0DIN] Got fingerprint:', e.data);

        // Send to background with proper structure
        const finding = {
            type: 'fingerprint-' + e.data.0DIN,
            key: e.data.method,
            value: {
                technique: e.data.0DIN,
                method: e.data.method,
                detected: true
            },
            category: e.data.0DIN,  // Add category for popup display
            method: e.data.method,  // Add method for popup display
            timestamp: new Date().toISOString(),
            url: window.location.href
        };

        chrome.runtime.sendMessage({
            type: 'SECURITY_FINDING',
            finding: finding
        }, (response) => {
            console.log('[0DIN] Sent to background:', response);
        });

        // Also send as ENHANCED_FINDING for compatibility
        chrome.runtime.sendMessage({
            type: 'ENHANCED_FINDING',
            finding: finding
        });
    }
});

console.log('[0DIN] Ready!');

// Test injection after page loads
setTimeout(() => {
    console.log('[0DIN] Testing fingerprint detection...');
    const testCanvas = document.createElement('canvas');
    const ctx = testCanvas.getContext('2d');
    ctx.fillText('test', 10, 10);
    testCanvas.toDataURL();
}, 2000);