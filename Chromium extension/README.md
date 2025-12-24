# 0DIN Sidekick - Chromium Extension

Chromium version of the 0DIN Sidekick AI Security Research Tool. Compatible with Chrome, Edge, Brave, Opera, and other Chromium-based browsers.

## Features

- **Multi-LLM Prompter**: Test ChatGPT, Claude, Gemini, and OpenRouter models
- **Auto-Detection**: Automatically detects successful jailbreak attempts
- **Chain Mode**: Iterative testing with intelligent follow-up suggestions
- **Token Usage Tracker**: Monitor API costs and token consumption in real-time
- **Research History**: Full history of all prompts and responses
- **Submit to 0DIN**: One-click vulnerability submission to the 0DIN platform

## Installation

### Method 1: Load Unpacked Extension (Recommended for Development)

1. Open your Chromium browser (Chrome, Edge, Brave, etc.)
2. Navigate to the extensions page:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`
   - Opera: `opera://extensions/`
3. Enable "Developer mode" (toggle in the top right corner)
4. Click "Load unpacked"
5. Select the "Chromium extension" folder
6. The extension icon will appear in your browser toolbar

### Method 2: Package as CRX (for distribution)

To create a distributable package:

1. Go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Pack extension"
4. Select the "Chromium extension" folder
5. Click "Pack Extension"
6. This creates a `.crx` file and a `.pem` private key

**Note**: For public distribution, submit to the Chrome Web Store for review.

## Configuration

### API Keys Setup

1. Click the extension icon in the browser toolbar
2. Navigate to the "Settings" tab
3. Enter your API keys:
   - **ChatGPT API Key**: Get from [platform.openai.com](https://platform.openai.com/api-keys)
   - **Anthropic API Key**: Get from [console.anthropic.com](https://console.anthropic.com/settings/keys)
   - **Gemini API Key**: Get from [aistudio.google.com](https://aistudio.google.com/app/apikey)
   - **OpenRouter API Key**: Get from [openrouter.ai/keys](https://openrouter.ai/keys)
   - **0DIN Researcher API Key**: Get from [0din.ai/users/edit](https://0din.ai/users/edit)
4. Click "Save Settings"

### Getting 0DIN Researcher API Key

1. Go to [https://0din.ai/users/edit](https://0din.ai/users/edit)
2. Scroll to the bottom of the page
3. Create a new API token
4. Copy the token and paste it in the extension settings

## Usage

### Basic Testing

1. Select your preferred LLM from the dropdown
2. Enter your security research prompt
3. Click "Send Prompt"
4. View the response and check if jailbreak was successful (with Auto-Detection enabled)

### Chain Mode

1. Enable "Chain Mode" toggle
2. Send your initial prompt
3. The extension will analyze the response
4. If unsuccessful, it suggests follow-up prompts
5. Continue iterating to refine your approach

### Token Tracking

1. Navigate to the "Token Usage" tab
2. View real-time statistics:
   - Total tokens consumed
   - Total cost across all providers
   - API call count
   - Breakdown by provider and model
3. Click "Reset Tokens" to clear tracking data

### Submitting Vulnerabilities

When you discover a vulnerability:

1. Click "Submit to 0DIN" button in the Prompter tab
2. Fill in the details:
   - Title (auto-filled)
   - Summary (auto-filled from response)
   - Category (select from dropdown)
   - Severity (Critical/High/Medium/Low)
   - LLM Tested (manually enter model name)
   - Tags (select relevant tags)
3. Click "✓ Submit to 0DIN"
4. Your finding will be submitted to the 0DIN platform

## Browser Compatibility

### Tested Browsers

- ✅ Google Chrome (90+)
- ✅ Microsoft Edge (90+)
- ✅ Brave Browser
- ✅ Opera
- ✅ Vivaldi

### Known Issues

- Some Chromium forks may have different API implementations
- Service worker support required (Manifest V3)

## Permissions

The extension requires the following permissions:
- `storage`: Store API keys, research history, and findings
- `activeTab`: Monitor current tab for security research
- `webRequest`: Intercept HTTP headers
- `cookies`: Monitor cookie operations
- `tabs`: Track tab metadata
- `webNavigation`: Monitor navigation events
- `<all_urls>`: Monitor all websites for security research

## Troubleshooting

### Extension Not Loading

- Make sure you selected the entire "Chromium extension" folder, not just a single file
- Check the Extensions page for error messages
- Verify "Developer mode" is enabled
- Try reloading the extension (click the refresh icon)

### API Keys Not Saving

- Check browser console (F12) for storage errors
- Ensure the browser has permission to use local storage
- Try clearing extension data and re-entering keys

### Token Tracker Not Updating

- Verify you have entered valid API keys
- Check that the selected LLM provider is correct
- Open browser console to see if API calls are successful
- Check the Network tab for failed requests

### "Service Worker Registration Failed" Error

- This extension requires Manifest V3 support
- Update your browser to the latest version
- Try disabling and re-enabling the extension

## Development

### File Structure

```
Chromium extension/
├── manifest.json           # Chrome Manifest V3
├── background.js           # Service worker
├── enhanced-popup.html     # Popup UI
├── enhanced-popup.js       # Popup logic
├── content.js             # Content script
├── enhanced-content.js    # Enhanced monitoring
├── fp-simple.js           # Fingerprint detection
├── popup.html             # Legacy popup
├── popup.js               # Legacy popup script
├── fingerprint-detector.js # FP detector
├── fingerprint-inject.js  # FP injector
├── fp-content.js          # FP content script
├── fp-monitor.js          # FP monitor
├── inject-fingerprint.js  # FP inject script
├── simple-fingerprint.js  # Simple FP detector
└── modules/               # Utility modules
    ├── data-classifier.js
    ├── fingerprint-detector.js
    ├── network-analyzer.js
    └── storage-analyzer.js
```

### Debugging

1. Open the popup and right-click → "Inspect"
2. View service worker console: Extensions page → "Inspect views: service worker"
3. View content script console: Open DevTools (F12) on any website
4. Check Network tab for API requests

### Making Changes

After modifying any files:
1. Go to `chrome://extensions/`
2. Find "0DIN Sidekick"
3. Click the refresh icon (or Ctrl/Cmd+R on the extensions page)
4. Test your changes

## Security & Privacy

- All API keys are stored locally in browser storage
- No data is sent to 0DIN servers except when you explicitly submit vulnerabilities
- The extension is for authorized security research only
- Always test on your own systems with proper authorization

## Manifest V3 Features

This extension uses Manifest V3, which includes:
- Service workers instead of persistent background pages
- Improved security with host permissions
- Better privacy protections
- Enhanced performance

## Support

For issues, questions, or feature requests:
- Open an issue on the GitHub repository
- Contact the 0DIN team at [0din.ai](https://0din.ai)

## License

For authorized security research and testing only. Always follow responsible disclosure practices.

---

**0DIN Sidekick v1.0** - Chromium Edition
