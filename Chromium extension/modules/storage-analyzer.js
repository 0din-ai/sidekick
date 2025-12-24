/**
 * Storage Analysis Dashboard
 * Deep scan of all browser storage mechanisms
 */

class StorageAnalyzer {
  constructor() {
    this.storageTypes = ['localStorage', 'sessionStorage', 'indexedDB', 'cookies', 'cacheAPI'];
    this.findings = [];
  }

  async performFullScan() {
    const report = {
      timestamp: Date.now(),
      domain: window.location.hostname,
      results: {}
    };

    // Scan localStorage
    report.results.localStorage = this.scanLocalStorage();

    // Scan sessionStorage
    report.results.sessionStorage = this.scanSessionStorage();

    // Scan cookies
    report.results.cookies = this.scanCookies();

    // Scan IndexedDB
    report.results.indexedDB = await this.scanIndexedDB();

    // Scan Cache API
    report.results.cacheAPI = await this.scanCacheAPI();

    // Analyze findings
    report.analysis = this.analyzeFindings(report.results);

    return report;
  }

  scanLocalStorage() {
    const data = {};
    const analysis = {
      totalItems: localStorage.length,
      totalSize: 0,
      items: [],
      sensitiveData: []
    };

    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const value = localStorage.getItem(key);

      const itemSize = (key.length + value.length) * 2; // Approximate size in bytes
      analysis.totalSize += itemSize;

      const item = {
        key,
        value: value.substring(0, 100), // Truncate for safety
        size: itemSize,
        type: this.detectDataType(value),
        sensitive: this.checkSensitive(key, value)
      };

      analysis.items.push(item);

      if (item.sensitive) {
        analysis.sensitiveData.push({
          key,
          reason: item.sensitive,
          severity: this.getSeverityLevel(item.sensitive)
        });
      }
    }

    return analysis;
  }

  scanSessionStorage() {
    const analysis = {
      totalItems: sessionStorage.length,
      totalSize: 0,
      items: [],
      sensitiveData: []
    };

    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const value = sessionStorage.getItem(key);

      const itemSize = (key.length + value.length) * 2;
      analysis.totalSize += itemSize;

      const item = {
        key,
        value: value.substring(0, 100),
        size: itemSize,
        type: this.detectDataType(value),
        sensitive: this.checkSensitive(key, value)
      };

      analysis.items.push(item);

      if (item.sensitive) {
        analysis.sensitiveData.push({
          key,
          reason: item.sensitive,
          severity: this.getSeverityLevel(item.sensitive)
        });
      }
    }

    return analysis;
  }

  scanCookies() {
    const cookies = document.cookie.split(';').map(c => c.trim());
    const analysis = {
      totalCookies: cookies.length,
      cookies: [],
      insecure: [],
      tracking: []
    };

    cookies.forEach(cookie => {
      if (!cookie) return;

      const [name, value] = cookie.split('=');
      const cookieData = {
        name: name.trim(),
        value: value ? value.substring(0, 50) : '',
        httpOnly: false, // Can't detect from JavaScript
        secure: window.location.protocol === 'https:',
        sameSite: 'unknown',
        sensitive: this.checkSensitive(name, value || '')
      };

      analysis.cookies.push(cookieData);

      // Check for tracking cookies
      if (this.isTrackingCookie(name)) {
        analysis.tracking.push(name);
      }

      // Check for insecure cookies with sensitive data
      if (cookieData.sensitive && !cookieData.secure) {
        analysis.insecure.push({
          name,
          reason: 'Sensitive data over insecure connection'
        });
      }
    });

    return analysis;
  }

  async scanIndexedDB() {
    const analysis = {
      databases: [],
      totalSize: 0,
      objectStores: 0,
      records: 0
    };

    try {
      // Get database names
      const databases = await indexedDB.databases();

      for (const dbInfo of databases) {
        const dbAnalysis = {
          name: dbInfo.name,
          version: dbInfo.version,
          stores: [],
          size: 0
        };

        try {
          const db = await this.openDatabase(dbInfo.name);
          const storeNames = Array.from(db.objectStoreNames);

          for (const storeName of storeNames) {
            const transaction = db.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);

            const count = await this.promisifyRequest(store.count());

            dbAnalysis.stores.push({
              name: storeName,
              count,
              keyPath: store.keyPath,
              autoIncrement: store.autoIncrement
            });

            analysis.records += count;
          }

          analysis.objectStores += storeNames.length;
          db.close();
        } catch (error) {
          dbAnalysis.error = error.message;
        }

        analysis.databases.push(dbAnalysis);
      }
    } catch (error) {
      analysis.error = 'IndexedDB not accessible or not supported';
    }

    return analysis;
  }

  async scanCacheAPI() {
    const analysis = {
      caches: [],
      totalSize: 0,
      totalEntries: 0
    };

    if ('caches' in window) {
      try {
        const cacheNames = await caches.keys();

        for (const cacheName of cacheNames) {
          const cache = await caches.open(cacheName);
          const requests = await cache.keys();

          const cacheData = {
            name: cacheName,
            entries: requests.length,
            urls: requests.map(req => req.url)
          };

          analysis.caches.push(cacheData);
          analysis.totalEntries += requests.length;
        }
      } catch (error) {
        analysis.error = error.message;
      }
    } else {
      analysis.error = 'Cache API not supported';
    }

    return analysis;
  }

  detectDataType(value) {
    try {
      JSON.parse(value);
      return 'json';
    } catch {
      if (/^\d+$/.test(value)) return 'number';
      if (/^(true|false)$/i.test(value)) return 'boolean';
      if (/^[A-Za-z0-9+/=]+$/.test(value) && value.length % 4 === 0) return 'base64';
      if (/^eyJ/.test(value)) return 'jwt';
      return 'string';
    }
  }

  checkSensitive(key, value) {
    const sensitivePatterns = {
      token: /token|jwt|bearer|auth/i,
      password: /password|pwd|pass|secret/i,
      key: /api[_-]?key|private[_-]?key|secret[_-]?key/i,
      session: /session|sess/i,
      credit: /card|cc|cvv/i,
      personal: /ssn|email|phone|address/i,
      oauth: /oauth|refresh[_-]?token|access[_-]?token/i
    };

    for (const [type, pattern] of Object.entries(sensitivePatterns)) {
      if (pattern.test(key) || pattern.test(value)) {
        return type;
      }
    }

    // Check for JWT tokens
    if (/^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/.test(value)) {
      return 'jwt';
    }

    return null;
  }

  isTrackingCookie(name) {
    const trackingPatterns = [
      /_ga/,
      /_gid/,
      /utm_/,
      /fbp/,
      /doubleclick/,
      /analytics/,
      /tracking/,
      /beacon/
    ];

    return trackingPatterns.some(pattern => pattern.test(name));
  }

  getSeverityLevel(type) {
    const severityMap = {
      token: 'CRITICAL',
      password: 'CRITICAL',
      key: 'CRITICAL',
      session: 'HIGH',
      credit: 'CRITICAL',
      personal: 'HIGH',
      oauth: 'CRITICAL',
      jwt: 'CRITICAL'
    };

    return severityMap[type] || 'MEDIUM';
  }

  analyzeFindings(results) {
    const analysis = {
      riskScore: 0,
      issues: [],
      recommendations: []
    };

    // Check localStorage
    if (results.localStorage.sensitiveData.length > 0) {
      analysis.riskScore += 5 * results.localStorage.sensitiveData.length;
      analysis.issues.push({
        type: 'localStorage',
        severity: 'HIGH',
        message: `Found ${results.localStorage.sensitiveData.length} sensitive items in localStorage`
      });
      analysis.recommendations.push('Encrypt sensitive data in localStorage or use more secure storage');
    }

    // Check sessionStorage
    if (results.sessionStorage.sensitiveData.length > 0) {
      analysis.riskScore += 3 * results.sessionStorage.sensitiveData.length;
      analysis.issues.push({
        type: 'sessionStorage',
        severity: 'MEDIUM',
        message: `Found ${results.sessionStorage.sensitiveData.length} sensitive items in sessionStorage`
      });
    }

    // Check cookies
    if (results.cookies.insecure.length > 0) {
      analysis.riskScore += 7 * results.cookies.insecure.length;
      analysis.issues.push({
        type: 'cookies',
        severity: 'CRITICAL',
        message: `Found ${results.cookies.insecure.length} insecure cookies with sensitive data`
      });
      analysis.recommendations.push('Use Secure and HttpOnly flags for sensitive cookies');
    }

    if (results.cookies.tracking.length > 5) {
      analysis.issues.push({
        type: 'privacy',
        severity: 'LOW',
        message: `Detected ${results.cookies.tracking.length} tracking cookies`
      });
    }

    // Check IndexedDB
    if (results.indexedDB.databases.length > 0) {
      analysis.issues.push({
        type: 'indexedDB',
        severity: 'INFO',
        message: `Found ${results.indexedDB.databases.length} IndexedDB databases with ${results.indexedDB.records} total records`
      });
    }

    // Calculate final risk level
    if (analysis.riskScore > 50) {
      analysis.riskLevel = 'CRITICAL';
    } else if (analysis.riskScore > 30) {
      analysis.riskLevel = 'HIGH';
    } else if (analysis.riskScore > 15) {
      analysis.riskLevel = 'MEDIUM';
    } else {
      analysis.riskLevel = 'LOW';
    }

    return analysis;
  }

  openDatabase(name) {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(name);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  promisifyRequest(request) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async generateReport() {
    const scan = await this.performFullScan();

    return {
      timestamp: scan.timestamp,
      domain: scan.domain,
      summary: {
        riskLevel: scan.analysis.riskLevel,
        riskScore: scan.analysis.riskScore,
        totalIssues: scan.analysis.issues.length,
        criticalIssues: scan.analysis.issues.filter(i => i.severity === 'CRITICAL').length,
        highIssues: scan.analysis.issues.filter(i => i.severity === 'HIGH').length
      },
      storage: {
        localStorage: {
          items: scan.results.localStorage.totalItems,
          size: scan.results.localStorage.totalSize,
          sensitive: scan.results.localStorage.sensitiveData.length
        },
        sessionStorage: {
          items: scan.results.sessionStorage.totalItems,
          size: scan.results.sessionStorage.totalSize,
          sensitive: scan.results.sessionStorage.sensitiveData.length
        },
        cookies: {
          total: scan.results.cookies.totalCookies,
          insecure: scan.results.cookies.insecure.length,
          tracking: scan.results.cookies.tracking.length
        },
        indexedDB: {
          databases: scan.results.indexedDB.databases.length,
          stores: scan.results.indexedDB.objectStores,
          records: scan.results.indexedDB.records
        },
        cache: {
          caches: scan.results.cacheAPI.caches.length,
          entries: scan.results.cacheAPI.totalEntries
        }
      },
      issues: scan.analysis.issues,
      recommendations: scan.analysis.recommendations,
      fullResults: scan.results
    };
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = StorageAnalyzer;
}