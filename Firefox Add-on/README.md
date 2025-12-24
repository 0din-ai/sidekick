# 0DIN Sidekick - Firefox Add-on

Firefox version of the 0DIN Sidekick AI Security Research Tool.

## Features

- **Multi-LLM Prompter**: Test ChatGPT, Claude, Gemini, and OpenRouter models
- **Auto-Detection**: Automatically detects successful jailbreak attempts
- **Chain Mode**: Iterative testing with intelligent follow-up suggestions
- **Token Usage Tracker**: Monitor API costs and token consumption in real-time
- **Research History**: Full history of all prompts and responses
- **Submit to 0DIN**: One-click vulnerability submission to the 0DIN platform

## Installation

### Method 1: Temporary Installation (for testing)

1. Open Firefox and navigate to `about:debugging`
2. Click "This Firefox" in the left sidebar
3. Click "Load Temporary Add-on..."
4. Navigate to the Firefox Add-on folder and select the `manifest.json` file
5. The extension will be loaded temporarily (until Firefox restarts)

### Method 2: Permanent Installation (Developer Edition/Nightly)

Firefox requires add-ons to be signed for permanent installation in the release version. For development and testing:

1. Download Firefox Developer Edition or Firefox Nightly
2. Open `about:config` and search for `xpinstall.signatures.required`
3. Set it to `false`
4. Follow Method 1 steps above

### Method 3: Package as XPI (for distribution)

To create a distributable package:

```bash
cd "Firefox Add-on"
zip -r -FS ../0din-sidekick-firefox.xpi * --exclude '*.git*' --exclude '*README.md'
```

Then install the XPI file:
1. Open Firefox and navigate to `about:addons`
2. Click the gear icon and select "Install Add-on From File..."
3. Select the `0din-sidekick-firefox.xpi` file

**Note**: For public distribution, the add-on must be submitted to Mozilla Add-ons (AMO) for review and signing.

## Configuration

### API Keys Setup

1. Click the extension icon in the Firefox toolbar
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

## Firefox-Specific Notes

### Manifest Version

This Firefox version uses Manifest V2 for maximum compatibility with Firefox's WebExtensions API. The Chrome version uses Manifest V3.

### API Compatibility

The extension uses a browser API polyfill to ensure compatibility between Chrome's `chrome.*` API and Firefox's `browser.*` API. Both work seamlessly.

### Permissions

The extension requires the following permissions:
- `storage`: Store API keys, research history, and findings
- `activeTab`: Monitor current tab for security research
- `webRequest`: Intercept HTTP headers
- `webRequestBlocking`: Block/modify requests for analysis
- `cookies`: Monitor cookie operations
- `tabs`: Track tab metadata
- `webNavigation`: Monitor navigation events
- `<all_urls>`: Monitor all websites for security research

### Known Differences from Chrome Version

1. **Background Script**: Uses persistent background script instead of service worker
2. **API Namespace**: Supports both `browser.*` and `chrome.*` APIs
3. **Permissions**: Includes `webRequestBlocking` for Firefox compatibility

## Troubleshooting

### Extension Not Loading

- Make sure you selected the `manifest.json` file when loading
- Check the Browser Console (`Ctrl+Shift+J`) for errors
- Verify all files are present in the Firefox Add-on folder

### API Keys Not Saving

- Check browser console for storage errors
- Ensure Firefox has permission to use local storage
- Try clearing extension data and re-entering keys

### Token Tracker Not Updating

- Verify you have entered valid API keys
- Check that the selected LLM provider is correct
- Open browser console to see if API calls are successful

### "Add-on could not be installed" Error

- For permanent installation, use Firefox Developer Edition or Nightly
- Disable signature requirement in `about:config`
- Or install temporarily via `about:debugging`

## Development

### File Structure

```
Firefox Add-on/
├── manifest.json           # Firefox Manifest V2
├── background.js           # Background script
├── enhanced-popup.html     # Popup UI
├── enhanced-popup.js       # Popup logic
├── content.js             # Content script
├── enhanced-content.js    # Enhanced monitoring
├── fp-simple.js           # Fingerprint detection
└── modules/               # Utility modules
    ├── data-classifier.js
    ├── fingerprint-detector.js
    ├── network-analyzer.js
    └── storage-analyzer.js
```

### Debugging

1. Open the popup and right-click → "Inspect Element"
2. View background script console: `about:debugging` → "Inspect" next to the extension
3. View content script console: Open page DevTools on any website

## Security & Privacy

- All API keys are stored locally in Firefox's storage
- No data is sent to 0DIN servers except when you explicitly submit vulnerabilities
- The extension is for authorized security research only
- Always test on your own systems with proper authorization

## Support

For issues, questions, or feature requests:
- Open an issue on the GitHub repository
- Contact the 0DIN team at [0din.ai](https://0din.ai)

## License

For authorized security research and testing only. Always follow responsible disclosure practices.

---

**0DIN Sidekick v1.0** - Firefox Edition
