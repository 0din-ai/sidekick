/**
 * Fingerprinting Detection Injection Script
 * Runs at document_start to catch all fingerprinting attempts
 */

(function() {
    'use strict';

    console.log('[0DIN Sidekick] Installing fingerprint detection hooks at document_start');

    // Helper to send findings
    function sendFingerprintDetection(type, method, details) {
        const finding = {
            type: `fingerprint-${type}`,
            method: method,
            details: details,
            timestamp: Date.now(),
            url: window.location.href
        };

        // Send to extension
        window.postMessage({
            source: '0DIN-fingerprint',
            finding: finding
        }, '*');

        console.warn(`[0DIN Sidekick] Fingerprinting detected: ${type}::${method}`, details);
    }

    // 1. Canvas Fingerprinting Detection
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
        sendFingerprintDetection('canvas', 'toDataURL', {
            width: this.width,
            height: this.height,
            type: args[0]
        });
        return originalToDataURL.apply(this, args);
    };

    const originalToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function(...args) {
        sendFingerprintDetection('canvas', 'toBlob', {
            width: this.width,
            height: this.height
        });
        return originalToBlob.apply(this, args);
    };

    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
        sendFingerprintDetection('canvas', 'getImageData', {
            x: args[0],
            y: args[1],
            width: args[2],
            height: args[3]
        });
        return originalGetImageData.apply(this, args);
    };

    // 2. WebGL Fingerprinting Detection
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
        const result = getParameter.apply(this, arguments);

        // Check for fingerprinting parameters
        const fingerprintParams = [
            0x1F00, // VENDOR
            0x1F01, // RENDERER
            0x1F02, // VERSION
            0x9245, // UNMASKED_VENDOR_WEBGL
            0x9246  // UNMASKED_RENDERER_WEBGL
        ];

        if (fingerprintParams.includes(param)) {
            sendFingerprintDetection('webgl', 'getParameter', {
                parameter: param,
                value: result
            });
        }

        return result;
    };

    // Also hook WebGL2
    if (window.WebGL2RenderingContext) {
        const getParameter2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {
            const result = getParameter2.apply(this, arguments);

            const fingerprintParams = [0x1F00, 0x1F01, 0x1F02, 0x9245, 0x9246];
            if (fingerprintParams.includes(param)) {
                sendFingerprintDetection('webgl2', 'getParameter', {
                    parameter: param,
                    value: result
                });
            }

            return result;
        };
    }

    // 3. Audio Fingerprinting Detection
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (AudioContext) {
        const OriginalAudioContext = AudioContext;
        window.AudioContext = function(...args) {
            sendFingerprintDetection('audio', 'AudioContext', {
                sampleRate: 44100
            });
            return new OriginalAudioContext(...args);
        };
        if (window.webkitAudioContext) {
            window.webkitAudioContext = window.AudioContext;
        }
    }

    const OfflineAudioContext = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (OfflineAudioContext) {
        const OriginalOfflineAudioContext = OfflineAudioContext;
        window.OfflineAudioContext = function(...args) {
            sendFingerprintDetection('audio', 'OfflineAudioContext', {
                channels: args[0],
                length: args[1],
                sampleRate: args[2]
            });
            return new OriginalOfflineAudioContext(...args);
        };
    }

    // 4. Font Fingerprinting Detection
    if (document.fonts && document.fonts.check) {
        const originalCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = function(...args) {
            sendFingerprintDetection('font', 'check', {
                font: args[0]
            });
            return originalCheck(...args);
        };
    }

    // 5. Navigator Property Access Detection
    const navProps = ['userAgent', 'platform', 'language', 'languages', 'hardwareConcurrency',
                      'deviceMemory', 'maxTouchPoints', 'vendor', 'appCodeName', 'appName',
                      'appVersion', 'product', 'productSub', 'userAgentData'];

    navProps.forEach(prop => {
        if (prop in navigator) {
            let originalValue = navigator[prop];
            Object.defineProperty(navigator, prop, {
                get: function() {
                    sendFingerprintDetection('navigator', prop, {
                        property: prop,
                        value: originalValue
                    });
                    return originalValue;
                },
                configurable: true
            });
        }
    });

    // 6. Screen Property Access Detection
    const screenProps = ['width', 'height', 'availWidth', 'availHeight',
                        'colorDepth', 'pixelDepth'];

    screenProps.forEach(prop => {
        if (prop in screen) {
            let originalValue = screen[prop];
            Object.defineProperty(screen, prop, {
                get: function() {
                    sendFingerprintDetection('screen', prop, {
                        property: prop,
                        value: originalValue
                    });
                    return originalValue;
                },
                configurable: true
            });
        }
    });

    // 7. Plugin/MimeType Enumeration Detection
    if (navigator.plugins) {
        const originalPlugins = navigator.plugins;
        Object.defineProperty(navigator, 'plugins', {
            get: function() {
                sendFingerprintDetection('plugins', 'enumerate', {
                    count: originalPlugins.length
                });
                return originalPlugins;
            },
            configurable: true
        });
    }

    console.log('[0DIN Sidekick] Fingerprint detection hooks installed successfully!');
})();