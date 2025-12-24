# 0DIN Sidekick Security Research Tool

## Browser Compatibility

**Supported Browsers:**
- ✅ Chrome, Edge, Brave, Opera (Chromium-based browsers)
- ✅ Firefox and Firefox Developer Edition

The extension is available in two versions:
- **Chromium extension** folder - For Chrome, Edge, Brave, and other Chromium browsers
- **Firefox Add-on** folder - For Firefox and Firefox-based browsers

## Installation

### For Chromium Browsers (Chrome, Edge, Brave, Opera)

1. Open your browser and navigate to the extensions page:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`
   - Opera: `opera://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked"
4. Select the `Chromium extension` folder
5. The extension icon will appear in your toolbar

### For Firefox

1. Open Firefox and navigate to `about:debugging`
2. Click "This Firefox" in the left sidebar
3. Click "Load Temporary Add-on..."
4. Navigate to the `Firefox Add-on` folder and select the `manifest.json` file
5. The add-on will be loaded (note: temporary installations are removed when Firefox restarts)

For permanent Firefox installation, see the README in the `Firefox Add-on` folder.

## Features

### Content Script Monitoring
- **WebSocket Connections**: Monitors WebSocket data transmission
- **PostMessage**: Tracks cross-origin communication
- **DOM Scanning**: Identifies sensitive input fields and data attributes

### Background Processing
- Collects findings from content scripts
- Monitors HTTP headers via webRequest API
- Monitors navigation events

## How It Works

1. **Passive Monitoring**: The extension passively monitors browser activity without modifying behavior
2. **Pattern Recognition**: Identifies potential sensitive data using regex patterns
3. **Secure Storage**: Findings are stored locally in browser storage
4. **Data Truncation**: Sensitive values are truncated to prevent full exposure
5. **Export Capability**: Findings can be exported as JSON for analysis

## Usage

1. **Install the extension** (see Installation above)
2. **Navigate to a target website** (must be your own or authorized)
3. **Click the extension icon** to view findings
4. **Export findings** for detailed analysis
5. **Clear findings** when testing is complete

## Security Findings Format

```json
{
  "type": "finding-type",
  "key": "data-key",
  "value": "truncated-value...",
  "timestamp": "ISO-8601",
  "url": "source-url",
  "tabId": 123
}
```

## Ethical Use Guidelines

1. **Authorization Required**: Only use on systems you own or have written permission to test
2. **Responsible Disclosure**: Report findings through proper channels
3. **Data Protection**: Never share captured sensitive data
4. **Limited Scope**: Only test within authorized boundaries
5. **Documentation**: Maintain clear records of authorization

## Technical Details

### Manifest Versions
- **Chromium version**: Uses Manifest V3 for Chromium-based browsers
- **Firefox version**: Uses Manifest V2 for Firefox compatibility

### Permissions Used
- `storage`: Store findings locally
- `activeTab`: Monitor active tab
- `webRequest`: Intercept HTTP headers
- `cookies`: Monitor cookie changes
- `tabs`: Track tab information
- `webNavigation`: Monitor navigation events

### Host Permissions
- Monitors all websites (`<all_urls>`) for comprehensive security research

## Limitations

- Truncates sensitive data to prevent full exposure
- Requires manual analysis of findings
- Does not automatically exploit vulnerabilities
- Cannot access encrypted HTTPS response bodies directly

## Responsible Disclosure

If you discover security vulnerabilities:

1. **Document** the issue thoroughly
2. **Reproduce** the vulnerability
3. **Report** to the appropriate security team
4. **Wait** for vendor response before public disclosure
5. **Follow** coordinated disclosure timelines

## Legal Notice

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for misuse or illegal activities. Users must comply with all applicable laws and regulations.

## Project Structure

```
0DIN_sideckick/
├── Chromium extension/    # For Chrome, Edge, Brave, Opera
├── Firefox Add-on/        # For Firefox
├── CLAUDE.md             # Development documentation
├── FEATURES_DOCUMENTATION.md
└── README.md             # This file
```

## Support

For questions about ethical security research:
- Review OWASP testing guidelines
- Consult with security professionals
- Ensure proper authorization
- Follow responsible disclosure practices

For browser-specific installation help:
- Chromium: See `Chromium extension/README.md`
- Firefox: See `Firefox Add-on/README.md`

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.

**0DIN Sidekick v1.0** - Available for Chromium and Firefox browsers
