/**
 * Data Classification System
 * Automatically categorizes sensitive data
 */

class DataClassifier {
  constructor() {
    this.patterns = {
      // Authentication tokens
      apiKeys: {
        patterns: [
          /api[_-]?key[\s]*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
          /bearer\s+([a-zA-Z0-9_\-\.]+)/gi,
          /token[\s]*[:=]\s*['"]?([a-zA-Z0-9_\-\.]{20,})['"]?/gi,
        ],
        severity: 'CRITICAL',
        category: 'Authentication'
      },

      // Personal Information
      emails: {
        patterns: [
          /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g
        ],
        severity: 'HIGH',
        category: 'PII'
      },

      phoneNumbers: {
        patterns: [
          /(\+?[1-9]\d{0,2}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
          /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g
        ],
        severity: 'HIGH',
        category: 'PII'
      },

      // Financial data
      creditCards: {
        patterns: [
          /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
          /\b\d{13,19}\b/g
        ],
        severity: 'CRITICAL',
        category: 'Financial'
      },

      // Social Security Numbers
      ssn: {
        patterns: [
          /\b\d{3}-\d{2}-\d{4}\b/g,
          /\b\d{9}\b/g
        ],
        severity: 'CRITICAL',
        category: 'PII'
      },

      // AWS keys
      awsKeys: {
        patterns: [
          /AKIA[0-9A-Z]{16}/g,
          /aws[_-]?access[_-]?key[_-]?id[\s]*[:=]\s*['"]?([A-Z0-9]{20})['"]?/gi,
          /aws[_-]?secret[_-]?access[_-]?key[\s]*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi
        ],
        severity: 'CRITICAL',
        category: 'Cloud Credentials'
      },

      // GitHub tokens
      githubTokens: {
        patterns: [
          /ghp_[a-zA-Z0-9]{36}/g,
          /gho_[a-zA-Z0-9]{36}/g,
          /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g
        ],
        severity: 'CRITICAL',
        category: 'Version Control'
      },

      // Private keys
      privateKeys: {
        patterns: [
          /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
          /-----BEGIN ENCRYPTED PRIVATE KEY-----/g
        ],
        severity: 'CRITICAL',
        category: 'Cryptographic'
      },

      // Passwords in URLs
      passwords: {
        patterns: [
          /password[\s]*[:=]\s*['"]?([^'"&\s]{8,})['"]?/gi,
          /pwd[\s]*[:=]\s*['"]?([^'"&\s]{8,})['"]?/gi,
          /pass[\s]*[:=]\s*['"]?([^'"&\s]{8,})['"]?/gi
        ],
        severity: 'CRITICAL',
        category: 'Authentication'
      },

      // OpenAI keys
      openaiKeys: {
        patterns: [
          /sk-[a-zA-Z0-9]{48}/g,
          /sk-proj-[a-zA-Z0-9]{48}/g
        ],
        severity: 'CRITICAL',
        category: 'AI Services'
      }
    };
  }

  classify(data) {
    const findings = [];
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

    for (const [type, config] of Object.entries(this.patterns)) {
      for (const pattern of config.patterns) {
        const matches = dataStr.matchAll(pattern);
        for (const match of matches) {
          findings.push({
            type,
            value: match[0],
            capture: match[1] || match[0],
            severity: config.severity,
            category: config.category,
            position: match.index,
            context: this.getContext(dataStr, match.index)
          });
        }
      }
    }

    return findings;
  }

  getContext(str, position, contextSize = 50) {
    const start = Math.max(0, position - contextSize);
    const end = Math.min(str.length, position + contextSize);
    return str.substring(start, end);
  }

  getSeverityScore(severity) {
    const scores = {
      'CRITICAL': 10,
      'HIGH': 7,
      'MEDIUM': 5,
      'LOW': 3,
      'INFO': 1
    };
    return scores[severity] || 0;
  }

  generateReport(findings) {
    const report = {
      timestamp: Date.now(),
      totalFindings: findings.length,
      criticalCount: findings.filter(f => f.severity === 'CRITICAL').length,
      highCount: findings.filter(f => f.severity === 'HIGH').length,
      categories: {},
      riskScore: 0
    };

    findings.forEach(finding => {
      if (!report.categories[finding.category]) {
        report.categories[finding.category] = [];
      }
      report.categories[finding.category].push(finding);
      report.riskScore += this.getSeverityScore(finding.severity);
    });

    return report;
  }
}

// Export for use in content script
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DataClassifier;
}