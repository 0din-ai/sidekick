# 0DIN Sidekick v1.0 - Enhanced Features Documentation

## Overview
0DIN Sidekick v1.0 includes advanced security monitoring features. This document explains how to use each feature.

## Browser Compatibility

This extension works with:
- **Chromium-based browsers**: Chrome, Edge, Brave, Opera
- **Firefox**: Firefox and Firefox Developer Edition

Choose the appropriate folder for your browser:
- `Chromium extension/` for Chromium-based browsers
- `Firefox Add-on/` for Firefox

## Installation

### For Chromium Browsers (Chrome, Edge, Brave, Opera)
1. Open your browser and navigate to the extensions page:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`
   - Opera: `opera://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `Chromium extension` folder
5. The extension will now monitor ALL websites (updated for third-party data tracking)

### For Firefox
1. Open Firefox and navigate to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on..."
4. Select the `manifest.json` file from the `Firefox Add-on` folder
5. The add-on will now monitor ALL websites

## Enhanced Features (All 18 except 14 and 20)

### 1. Data Flow Visualization
**Purpose**: Tracks and visualizes how data moves between domains
**How to Use**:
- Click on the Dashboard tab in the popup
- Data flows are automatically tracked
- View real-time data movement patterns
- Export results for analysis

### 2. Permission Audit System
**Purpose**: Monitors browser API access and permission usage
**How to Use**:
- Automatically audits all permission requests
- View in Dashboard under "Active Features"
- Detects: geolocation, camera, microphone, clipboard access
- Alerts on suspicious permission combinations

### 3. Storage Analysis Dashboard
**Purpose**: Deep scan of all browser storage mechanisms
**How to Use**:
- Click "Storage" tab in popup
- Click "Analyze Storage" button
- Reviews: localStorage, sessionStorage, IndexedDB, cookies, Cache API
- Identifies sensitive data in storage
- Shows storage size and item counts

### 4. Network Request Analyzer
**Purpose**: Advanced network traffic analysis
**How to Use**:
- Click "Network" tab in popup
- Automatically captures all requests
- Identifies:
  - Suspicious domains
  - Large data transfers
  - Base64 encoded data
  - API endpoints
- Color-coded by risk level

### 5. Cross-Origin Resource Monitoring
**Purpose**: Tracks CORS and cross-origin communications
**How to Use**:
- Automatically monitors all cross-origin requests
- View in Network tab
- Identifies:
  - Cross-origin messages
  - CORS violations
  - Third-party resource loads

### 6. CSP Analyzer
**Purpose**: Detects Content Security Policy issues
**How to Use**:
- Automatically analyzes CSP headers
- Reports violations in real-time
- Dashboard shows CSP status
- Identifies unsafe-inline and unsafe-eval usage

### 7. WebSocket/WebRTC Inspector
**Purpose**: Deep inspection of real-time communications
**How to Use**:
- Monitors all WebSocket connections
- Tracks WebRTC peer connections
- View in Network tab under "Real-time"
- Shows message frequency and data volume

### 8. Third-Party Script Auditor
**Purpose**: Inventory and analyze external scripts
**How to Use**:
- Automatically inventories all third-party scripts
- Dashboard shows count
- Identifies:
  - Script origins
  - Async/defer loading
  - Integrity checks
  - Dynamic script injection

### 9. Timing Attack Detector
**Purpose**: Identifies timing-based vulnerabilities
**How to Use**:
- Runs automatically in background
- Detects unusual timing patterns
- Alerts on potential timing attacks
- Shows in Dashboard when detected

### 10. Data Classification System
**Purpose**: Automatically categorizes sensitive data
**How to Use**:
- Click "Data Class" tab
- Automatically classifies:
  - Emails, phone numbers, SSNs
  - Credit card numbers
  - API keys and tokens
  - JWT tokens
  - AWS/GitHub/OpenAI keys
- Color-coded by severity

### 11. Fingerprinting Detection
**Purpose**: Detects browser fingerprinting attempts
**How to Use**:
- Click "Fingerprint" tab
- Detects:
  - Canvas fingerprinting
  - WebGL fingerprinting
  - Font enumeration
  - Hardware fingerprinting
  - Audio context fingerprinting
- Shows techniques and frequency

### 12. Event Listener Auditor
**Purpose**: Monitors all page event listeners
**How to Use**:
- Automatically tracks sensitive events
- Detects:
  - Keyboard loggers
  - Clipboard monitors
  - Form input tracking
- View suspicious listeners in Dashboard

### 13. iframe Security Monitor
**Purpose**: Tracks iframe usage and security
**How to Use**:
- Automatically monitors all iframes
- Identifies:
  - Unsandboxed iframes
  - Cross-origin iframes
  - Dynamic iframe injection
- Alerts on security risks

### 15. Pattern Learning System
**Purpose**: Learns normal behavior and detects anomalies
**How to Use**:
- Runs automatically
- Learns site behavior patterns
- Alerts on unusual activity
- Improves detection over time

### 16. API Call Interceptor
**Purpose**: Monitors specific API patterns
**How to Use**:
- Automatically intercepts API calls
- Detects:
  - API bursts
  - Unusual sequences
  - GraphQL queries
  - REST endpoints

### 17. DOM Mutation Tracker
**Purpose**: Tracks all DOM changes
**How to Use**:
- Monitors DOM mutations in real-time
- Detects:
  - Script injection
  - Style injection
  - Attribute changes
  - Dynamic content loading

### 18. Privacy Budget Monitor
**Purpose**: Tracks privacy API usage
**How to Use**:
- Monitors privacy-sensitive APIs
- Tracks:
  - Geolocation access
  - Camera/microphone usage
  - Battery API
  - Device memory
- Shows privacy budget consumption

## Using the Enhanced Popup

### Dashboard Tab
- Overview of all security metrics
- Risk level indicator
- Quick statistics
- Active feature status
- Export and clear buttons

### Deep Scan Feature
1. Click "Deep Scan" button in Dashboard
2. Performs comprehensive analysis:
   - Re-scans all storage
   - Analyzes all page text
   - Checks all input fields
   - Audits all scripts
3. Results appear in respective tabs

### Export Functionality
1. Click "Export" button
2. Downloads JSON file with:
   - All findings
   - Network requests
   - Storage analysis
   - Classified data
   - Fingerprinting attempts
3. File includes timestamp and domain

### Clear All Data
1. Click "Clear" button
2. Confirm the action
3. Removes all collected data
4. Resets all counters

## Security Considerations

- **Data Truncation**: Sensitive data is automatically truncated for safety
- **Local Storage**: All data stored locally in browser storage, not transmitted
- **Universal Monitoring**: Now monitors ALL websites to track third-party data flows

## Troubleshooting

### Extension/Add-on Not Working
1. Check extension is enabled in your browser
2. Verify you're using the correct folder (Chromium extension or Firefox Add-on)
3. Refresh the page
4. Check browser console for errors

### No Data Appearing
1. Ensure page has fully loaded
2. Click "Refresh" in popup
3. Perform actions on the page
4. Try "Deep Scan"

### Performance Issues
1. Clear findings regularly
2. Limit monitoring duration
3. Disable unused features
4. Export and clear data

### Browser-Specific Issues

**Firefox:**
- Temporary installations are removed when Firefox restarts
- For permanent installation, use Firefox Developer Edition or see Firefox Add-on/README.md
- Some features may require specific Firefox permissions

**Chromium:**
- Ensure Developer mode is enabled
- Check that Manifest V3 is supported (requires recent browser version)
- Reload extension after making changes

## Risk Levels Explained

- **LOW**: Normal activity detected
- **MEDIUM**: Some suspicious patterns
- **HIGH**: Multiple security concerns
- **CRITICAL**: Severe security issues detected

## Best Practices

1. **Regular Scanning**: Perform deep scans periodically
2. **Export Data**: Save findings before clearing
3. **Monitor Alerts**: Pay attention to critical findings
4. **Review Patterns**: Check for unusual activity patterns
5. **Update Regularly**: Keep extension updated

## Feature Status Indicators

- 🟢 Green dot: Feature active and monitoring
- ⚫ Gray dot: Feature inactive or no data
- Pulsing: Active data collection in progress

## Data Categories

- **Authentication**: Tokens, API keys, passwords
- **PII**: Personal identifiable information
- **Financial**: Credit cards, banking data
- **Cloud Credentials**: AWS, Azure, GCP keys
- **Version Control**: GitHub, GitLab tokens
- **Cryptographic**: Private keys, certificates

## Support

For issues or questions:
- Check browser console for detailed logs
- Export findings for analysis
- Review this documentation
- Test on a clean browser profile

For browser-specific help:
- **Chromium users**: See `Chromium extension/README.md`
- **Firefox users**: See `Firefox Add-on/README.md`

---

**0DIN Sidekick v1.0** - Compatible with Chromium and Firefox browsers
