/**
 * Fingerprinting Detection Module
 * Detects browser fingerprinting attempts
 */

class FingerprintDetector {
  constructor() {
    this.fingerprintAttempts = [];
    this.suspiciousAPIs = new Set();
    this.initializeDetection();
  }

  initializeDetection() {
    // Monitor Canvas fingerprinting
    this.monitorCanvas();

    // Monitor WebGL fingerprinting
    this.monitorWebGL();

    // Monitor AudioContext fingerprinting
    this.monitorAudioContext();

    // Monitor Font fingerprinting
    this.monitorFonts();

    // Monitor Screen and hardware info access
    this.monitorHardwareInfo();

    // Monitor WebRTC fingerprinting
    this.monitorWebRTC();

    // Monitor Navigator properties
    this.monitorNavigator();

    // Monitor Performance API abuse
    this.monitorPerformance();
  }

  monitorCanvas() {
    const original = {
      toDataURL: HTMLCanvasElement.prototype.toDataURL,
      toBlob: HTMLCanvasElement.prototype.toBlob,
      getImageData: CanvasRenderingContext2D.prototype.getImageData
    };

    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      this.recordFingerprint('canvas', 'toDataURL', {
        stack: new Error().stack,
        timestamp: Date.now()
      });
      return original.toDataURL.apply(this, args);
    }.bind(this);

    HTMLCanvasElement.prototype.toBlob = function(...args) {
      this.recordFingerprint('canvas', 'toBlob', {
        stack: new Error().stack,
        timestamp: Date.now()
      });
      return original.toBlob.apply(this, args);
    }.bind(this);

    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
      this.recordFingerprint('canvas', 'getImageData', {
        dimensions: { x: args[0], y: args[1], width: args[2], height: args[3] },
        stack: new Error().stack,
        timestamp: Date.now()
      });
      return original.getImageData.apply(this, args);
    }.bind(this);
  }

  monitorWebGL() {
    if (window.WebGLRenderingContext) {
      const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
      const originalGetExtension = WebGLRenderingContext.prototype.getExtension;

      WebGLRenderingContext.prototype.getParameter = function(pname) {
        const suspiciousParams = [
          0x1F00, // GL_VENDOR
          0x1F01, // GL_RENDERER
          0x1F02, // GL_VERSION
          0x8B8C  // GL_SHADING_LANGUAGE_VERSION
        ];

        if (suspiciousParams.includes(pname)) {
          this.recordFingerprint('webgl', 'getParameter', {
            parameter: pname,
            stack: new Error().stack,
            timestamp: Date.now()
          });
        }

        return originalGetParameter.apply(this, arguments);
      }.bind(this);

      WebGLRenderingContext.prototype.getExtension = function(name) {
        this.recordFingerprint('webgl', 'getExtension', {
          extension: name,
          stack: new Error().stack,
          timestamp: Date.now()
        });
        return originalGetExtension.apply(this, arguments);
      }.bind(this);
    }
  }

  monitorAudioContext() {
    if (window.AudioContext || window.webkitAudioContext) {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      const originalConstructor = AudioContextClass;

      window.AudioContext = window.webkitAudioContext = function(...args) {
        this.recordFingerprint('audio', 'AudioContext', {
          stack: new Error().stack,
          timestamp: Date.now()
        });
        return new originalConstructor(...args);
      }.bind(this);

      // Monitor OfflineAudioContext (commonly used for fingerprinting)
      if (window.OfflineAudioContext) {
        const originalOffline = window.OfflineAudioContext;
        window.OfflineAudioContext = function(...args) {
          this.recordFingerprint('audio', 'OfflineAudioContext', {
            channels: args[0],
            length: args[1],
            sampleRate: args[2],
            stack: new Error().stack,
            timestamp: Date.now()
          });
          return new originalOffline(...args);
        }.bind(this);
      }
    }
  }

  monitorFonts() {
    // Monitor document.fonts API
    if (document.fonts) {
      const originalCheck = document.fonts.check;
      document.fonts.check = function(font) {
        this.recordFingerprint('fonts', 'check', {
          font: font,
          stack: new Error().stack,
          timestamp: Date.now()
        });
        return originalCheck.apply(this, arguments);
      }.bind(this);
    }

    // Monitor offsetWidth/Height changes (font detection technique)
    const createElement = document.createElement.bind(document);
    document.createElement = function(tagName) {
      const element = createElement(tagName);

      if (tagName.toLowerCase() === 'span') {
        // Proxy offsetWidth and offsetHeight
        let accessCount = 0;
        const originalDescriptors = {
          offsetWidth: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth'),
          offsetHeight: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight')
        };

        ['offsetWidth', 'offsetHeight'].forEach(prop => {
          Object.defineProperty(element, prop, {
            get: function() {
              accessCount++;
              if (accessCount > 10) { // Suspicious if accessed many times
                this.recordFingerprint('fonts', 'dimension-check', {
                  property: prop,
                  accessCount: accessCount,
                  timestamp: Date.now()
                });
              }
              return originalDescriptors[prop].get.call(this);
            }.bind(this)
          });
        });
      }

      return element;
    }.bind(this);
  }

  monitorHardwareInfo() {
    // Monitor screen properties
    const screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
    screenProps.forEach(prop => {
      const originalDescriptor = Object.getOwnPropertyDescriptor(Screen.prototype, prop);
      if (originalDescriptor) {
        Object.defineProperty(screen, prop, {
          get: function() {
            this.recordFingerprint('hardware', `screen.${prop}`, {
              value: originalDescriptor.get.call(screen),
              timestamp: Date.now()
            });
            return originalDescriptor.get.call(screen);
          }.bind(this)
        });
      }
    });

    // Monitor deviceMemory
    if ('deviceMemory' in navigator) {
      const originalDescriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'deviceMemory');
      Object.defineProperty(navigator, 'deviceMemory', {
        get: function() {
          const value = originalDescriptor.get.call(navigator);
          this.recordFingerprint('hardware', 'deviceMemory', {
            value: value,
            timestamp: Date.now()
          });
          return value;
        }.bind(this)
      });
    }

    // Monitor hardwareConcurrency
    if ('hardwareConcurrency' in navigator) {
      const originalDescriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency');
      Object.defineProperty(navigator, 'hardwareConcurrency', {
        get: function() {
          const value = originalDescriptor.get.call(navigator);
          this.recordFingerprint('hardware', 'hardwareConcurrency', {
            value: value,
            timestamp: Date.now()
          });
          return value;
        }.bind(this)
      });
    }
  }

  monitorWebRTC() {
    if (window.RTCPeerConnection) {
      const originalRTCPeerConnection = window.RTCPeerConnection;
      window.RTCPeerConnection = function(...args) {
        this.recordFingerprint('webrtc', 'RTCPeerConnection', {
          configuration: args[0],
          stack: new Error().stack,
          timestamp: Date.now()
        });
        return new originalRTCPeerConnection(...args);
      }.bind(this);
    }

    // Monitor MediaDevices
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices;
      navigator.mediaDevices.enumerateDevices = function() {
        this.recordFingerprint('webrtc', 'enumerateDevices', {
          stack: new Error().stack,
          timestamp: Date.now()
        });
        return originalEnumerateDevices.apply(this, arguments);
      }.bind(this);
    }
  }

  monitorNavigator() {
    const suspiciousProps = [
      'userAgent',
      'platform',
      'language',
      'languages',
      'plugins',
      'mimeTypes',
      'vendor',
      'product',
      'productSub',
      'cookieEnabled',
      'onLine',
      'doNotTrack',
      'maxTouchPoints',
      'webdriver'
    ];

    suspiciousProps.forEach(prop => {
      if (prop in navigator) {
        const originalDescriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, prop) ||
                                  Object.getOwnPropertyDescriptor(navigator, prop);

        if (originalDescriptor && originalDescriptor.get) {
          Object.defineProperty(navigator, prop, {
            get: function() {
              this.suspiciousAPIs.add(`navigator.${prop}`);
              if (this.suspiciousAPIs.size > 5) {
                this.recordFingerprint('navigator', 'bulk-access', {
                  properties: Array.from(this.suspiciousAPIs),
                  timestamp: Date.now()
                });
              }
              return originalDescriptor.get.call(navigator);
            }.bind(this)
          });
        }
      }
    });
  }

  monitorPerformance() {
    if (window.performance && window.performance.now) {
      const originalNow = performance.now.bind(performance);
      let callCount = 0;
      let lastCall = 0;

      performance.now = function() {
        const now = Date.now();
        callCount++;

        // Detect rapid successive calls (timing attacks)
        if (now - lastCall < 10 && callCount > 100) {
          this.recordFingerprint('timing', 'performance.now', {
            callCount: callCount,
            frequency: callCount / ((now - this.startTime) / 1000),
            stack: new Error().stack,
            timestamp: now
          });
        }

        lastCall = now;
        return originalNow();
      }.bind(this);
    }
  }

  recordFingerprint(category, method, details) {
    const attempt = {
      category,
      method,
      details,
      url: window.location.href,
      domain: window.location.hostname
    };

    this.fingerprintAttempts.push(attempt);

    // Send to background script
    if (window.chrome && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'FINGERPRINT_ATTEMPT',
        data: attempt
      });
    }

    // Log to console in development
    console.warn(`[Fingerprint Detected] ${category}::${method}`, details);
  }

  getReport() {
    const report = {
      totalAttempts: this.fingerprintAttempts.length,
      categories: {},
      methods: {},
      risk: 'LOW'
    };

    this.fingerprintAttempts.forEach(attempt => {
      // Count by category
      if (!report.categories[attempt.category]) {
        report.categories[attempt.category] = 0;
      }
      report.categories[attempt.category]++;

      // Count by method
      const fullMethod = `${attempt.category}::${attempt.method}`;
      if (!report.methods[fullMethod]) {
        report.methods[fullMethod] = 0;
      }
      report.methods[fullMethod]++;
    });

    // Determine risk level
    if (report.totalAttempts > 50) {
      report.risk = 'CRITICAL';
    } else if (report.totalAttempts > 20) {
      report.risk = 'HIGH';
    } else if (report.totalAttempts > 10) {
      report.risk = 'MEDIUM';
    }

    // Identify fingerprinting technique
    const techniques = [];
    if (report.categories.canvas > 0) techniques.push('Canvas Fingerprinting');
    if (report.categories.webgl > 0) techniques.push('WebGL Fingerprinting');
    if (report.categories.audio > 0) techniques.push('Audio Fingerprinting');
    if (report.categories.fonts > 0) techniques.push('Font Fingerprinting');
    if (report.categories.webrtc > 0) techniques.push('WebRTC Fingerprinting');
    if (report.categories.hardware > 0) techniques.push('Hardware Fingerprinting');
    if (report.categories.timing > 0) techniques.push('Timing Attack');

    report.techniques = techniques;
    report.attempts = this.fingerprintAttempts;

    return report;
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FingerprintDetector;
}