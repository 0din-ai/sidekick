/**
 * Advanced Network Request Analyzer
 * Deep analysis of all network traffic
 */

class NetworkAnalyzer {
  constructor() {
    this.requests = new Map();
    this.suspiciousPatterns = {
      dataExfiltration: [
        /\/api\/upload/,
        /\/webhook/,
        /paste\.site/,
        /pastebin\.com/,
        /file\.io/,
        /transfer\.sh/
      ],
      tracking: [
        /google-analytics/,
        /doubleclick/,
        /facebook\.com\/tr/,
        /amazon-adsystem/,
        /scorecardresearch/
      ],
      cdn: [
        /cloudflare/,
        /akamai/,
        /fastly/,
        /cloudfront/
      ],
      api: [
        /\/api\//,
        /\/v\d+\//,
        /\/graphql/,
        /\/rest\//
      ]
    };

    this.initializeInterceptor();
  }

  initializeInterceptor() {
    // Override fetch
    const originalFetch = window.fetch;
    window.fetch = async (...args) => {
      const [resource, config] = args;
      const requestId = this.generateRequestId();

      const requestData = {
        id: requestId,
        method: (config && config.method) || 'GET',
        url: resource.toString(),
        headers: (config && config.headers) || {},
        body: config && config.body,
        timestamp: Date.now(),
        type: 'fetch'
      };

      this.analyzeRequest(requestData);

      try {
        const response = await originalFetch(...args);
        const responseClone = response.clone();

        // Analyze response
        this.analyzeResponse(requestId, {
          status: response.status,
          statusText: response.statusText,
          headers: Object.fromEntries(response.headers.entries()),
          url: response.url
        });

        return response;
      } catch (error) {
        this.recordError(requestId, error);
        throw error;
      }
    };

    // Override XMLHttpRequest
    const originalXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new originalXHR();
      const requestId = this.generateRequestId();

      const originalOpen = xhr.open;
      const originalSend = xhr.send;
      const originalSetRequestHeader = xhr.setRequestHeader;

      const headers = {};

      xhr.open = function(method, url, ...args) {
        xhr._requestData = {
          id: requestId,
          method,
          url,
          timestamp: Date.now(),
          type: 'xhr'
        };
        return originalOpen.apply(xhr, [method, url, ...args]);
      };

      xhr.setRequestHeader = function(name, value) {
        headers[name] = value;
        return originalSetRequestHeader.apply(xhr, arguments);
      };

      xhr.send = function(body) {
        if (xhr._requestData) {
          xhr._requestData.headers = headers;
          xhr._requestData.body = body;
          this.analyzeRequest(xhr._requestData);
        }

        xhr.addEventListener('load', () => {
          this.analyzeResponse(requestId, {
            status: xhr.status,
            statusText: xhr.statusText,
            responseHeaders: xhr.getAllResponseHeaders(),
            responseText: xhr.responseText
          });
        });

        xhr.addEventListener('error', () => {
          this.recordError(requestId, 'XHR Error');
        });

        return originalSend.apply(xhr, arguments);
      }.bind(this);

      return xhr;
    }.bind(this);
  }

  analyzeRequest(requestData) {
    const analysis = {
      ...requestData,
      classification: this.classifyRequest(requestData),
      suspiciousIndicators: this.checkSuspiciousPatterns(requestData.url),
      dataLeaks: this.checkForDataLeaks(requestData),
      corsAnalysis: this.analyzeCORS(requestData)
    };

    this.requests.set(requestData.id, analysis);

    // Send to background script
    if (window.chrome && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'NETWORK_REQUEST_ANALYZED',
        data: analysis
      });
    }

    return analysis;
  }

  analyzeResponse(requestId, responseData) {
    const request = this.requests.get(requestId);
    if (request) {
      request.response = {
        ...responseData,
        duration: Date.now() - request.timestamp,
        securityHeaders: this.checkSecurityHeaders(responseData.headers || {})
      };

      // Check for sensitive data in response
      if (responseData.responseText) {
        request.response.sensitiveData = this.scanForSensitiveData(responseData.responseText);
      }

      if (window.chrome && chrome.runtime) {
        chrome.runtime.sendMessage({
          type: 'NETWORK_RESPONSE_ANALYZED',
          data: request
        });
      }
    }
  }

  classifyRequest(requestData) {
    const url = new URL(requestData.url, window.location.origin);

    return {
      domain: url.hostname,
      protocol: url.protocol,
      isThirdParty: url.hostname !== window.location.hostname,
      isSecure: url.protocol === 'https:',
      hasCredentials: this.hasCredentials(requestData),
      method: requestData.method,
      contentType: requestData.headers['Content-Type'] || 'unknown'
    };
  }

  checkSuspiciousPatterns(url) {
    const indicators = [];

    for (const [category, patterns] of Object.entries(this.suspiciousPatterns)) {
      for (const pattern of patterns) {
        if (pattern.test(url)) {
          indicators.push({
            category,
            pattern: pattern.toString(),
            severity: this.getSeverityForCategory(category)
          });
        }
      }
    }

    return indicators;
  }

  checkForDataLeaks(requestData) {
    const leaks = [];

    // Check URL for sensitive data
    if (requestData.url.includes('token=') ||
        requestData.url.includes('api_key=') ||
        requestData.url.includes('password=')) {
      leaks.push({
        type: 'URL_PARAMETER',
        severity: 'CRITICAL'
      });
    }

    // Check body for sensitive patterns
    if (requestData.body) {
      const bodyStr = typeof requestData.body === 'string'
        ? requestData.body
        : JSON.stringify(requestData.body);

      if (/password|token|api_key|secret/i.test(bodyStr)) {
        leaks.push({
          type: 'REQUEST_BODY',
          severity: 'HIGH'
        });
      }
    }

    return leaks;
  }

  analyzeCORS(requestData) {
    const url = new URL(requestData.url, window.location.origin);
    const issCrossOrigin = url.origin !== window.location.origin;

    return {
      isCrossOrigin: issCrossOrigin,
      origin: url.origin,
      currentOrigin: window.location.origin,
      hasCredentials: requestData.credentials === 'include',
      headers: {
        'Access-Control-Allow-Origin': requestData.headers['Access-Control-Allow-Origin'],
        'Access-Control-Allow-Credentials': requestData.headers['Access-Control-Allow-Credentials']
      }
    };
  }

  checkSecurityHeaders(headers) {
    const securityHeaders = {
      'Content-Security-Policy': headers['content-security-policy'],
      'X-Frame-Options': headers['x-frame-options'],
      'X-Content-Type-Options': headers['x-content-type-options'],
      'Strict-Transport-Security': headers['strict-transport-security'],
      'X-XSS-Protection': headers['x-xss-protection']
    };

    const missing = [];
    for (const [header, value] of Object.entries(securityHeaders)) {
      if (!value) {
        missing.push(header);
      }
    }

    return {
      headers: securityHeaders,
      missing,
      score: (5 - missing.length) / 5 * 100
    };
  }

  scanForSensitiveData(text) {
    const patterns = {
      jwt: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*/g,
      apiKey: /[a-f0-9]{32,}/gi,
      email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
      ipAddress: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g
    };

    const found = {};
    for (const [type, pattern] of Object.entries(patterns)) {
      const matches = text.match(pattern);
      if (matches) {
        found[type] = matches.length;
      }
    }

    return found;
  }

  hasCredentials(requestData) {
    return !!(
      requestData.headers['Authorization'] ||
      requestData.headers['Cookie'] ||
      requestData.credentials === 'include'
    );
  }

  getSeverityForCategory(category) {
    const severities = {
      dataExfiltration: 'CRITICAL',
      tracking: 'MEDIUM',
      cdn: 'LOW',
      api: 'INFO'
    };
    return severities[category] || 'UNKNOWN';
  }

  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  recordError(requestId, error) {
    const request = this.requests.get(requestId);
    if (request) {
      request.error = {
        message: error.message || error,
        timestamp: Date.now()
      };
    }
  }

  getReport() {
    const requests = Array.from(this.requests.values());
    return {
      total: requests.length,
      thirdParty: requests.filter(r => r.classification.isThirdParty).length,
      insecure: requests.filter(r => !r.classification.isSecure).length,
      withCredentials: requests.filter(r => r.classification.hasCredentials).length,
      suspicious: requests.filter(r => r.suspiciousIndicators.length > 0).length,
      dataLeaks: requests.filter(r => r.dataLeaks && r.dataLeaks.length > 0).length,
      requests: requests
    };
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = NetworkAnalyzer;
}