/**
 * Background Service Worker for Security Research
 * 0DIN Sidekick v1.0
 */

console.log('🔬 Security Research Background Worker Active');

// Store findings
let securityFindings = [];

// Enhanced data storage
let enhancedData = {
    network: [],
    classified: [],
    fingerprints: []
};

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('📨 Message received in background:', request.type);

    // Log fingerprint messages specifically
    if (request.type === 'ENHANCED_FINDING' && request.finding && request.finding.type && request.finding.type.includes('fingerprint')) {
        console.log('🎯🎯🎯 FINGERPRINT MESSAGE RECEIVED:', request.finding);
    }

    if (request.type === 'TEST') {
        console.log('🧪 Test message received:', request.message);
        sendResponse({ success: true, message: 'Test received' });
        return true;
    }

    if (request.type === 'SECURITY_FINDING') {
        console.log('📊 Security finding received:', request.finding);

        const finding = {
            ...request.finding,
            tabId: sender.tab?.id,
            tabUrl: sender.tab?.url
        };

        // Store finding
        securityFindings.push(finding);

        // Also add fingerprints to enhanced data
        if (finding.type && (finding.type.includes('fingerprint') || finding.type.includes('fp-detection'))) {
            enhancedData.fingerprints.push(finding);
            console.log('🎯 FINGERPRINT ADDED via SECURITY_FINDING:', finding);
        }

        // Store in chrome.storage
        chrome.storage.local.set({
            findings: securityFindings,
            enhancedData: enhancedData
        });

        sendResponse({ received: true });
        return true;
    }

    // Handle enhanced findings
    if (request.type === 'ENHANCED_FINDING') {
        console.log('🔬 Enhanced finding:', request.finding);

        const finding = {
            ...request.finding,
            tabId: sender.tab?.id,
            tabUrl: sender.tab?.url
        };

        securityFindings.push(finding);

        // Categorize enhanced findings - more inclusive for network
        if (finding.type.includes('network') ||
            finding.type.includes('fetch') ||
            finding.type.includes('xhr') ||
            finding.type.includes('request') ||
            finding.type.includes('api') ||
            finding.type.includes('cross-origin') ||
            finding.type.includes('websocket') ||
            finding.type.includes('navigation')) {
            enhancedData.network.push(finding);
            console.log('Added to network data:', finding.type);
        }
        if (finding.type.includes('classification') || finding.type.includes('sensitive')) {
            enhancedData.classified.push(finding);
            console.log('Added to classified data:', finding.type);
        }
        if (finding.type.includes('fingerprint')) {
            enhancedData.fingerprints.push(finding);
            console.log('🎯 Added to fingerprint data:', finding.type, finding);
            console.log('🎯 Total fingerprints now:', enhancedData.fingerprints.length);
        }

        // Store all data
        chrome.storage.local.set({
            findings: securityFindings,
            enhancedData: enhancedData
        }, () => {
            console.log('💾 Data saved to storage, fingerprints:', enhancedData.fingerprints.length);
        });

        sendResponse({ received: true, stored: true });
        return true;
    }

    // Forward messages from popup to content script
    if (request.action === 'deepScan' || request.action === 'analyzeStorage' || request.action === 'getReport') {
        // Get the active tab
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, request, function(response) {
                    sendResponse(response);
                });
            }
        });
        return true; // Keep channel open for async response
    }
});

// Monitor web requests (headers)
chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        const headers = details.requestHeaders;
        const url = details.url;

        // Check for sensitive headers
        headers.forEach(header => {
            if (header.name.toLowerCase() === 'authorization' ||
                header.name.toLowerCase() === 'cookie' ||
                header.name.toLowerCase() === 'x-api-key') {

                const finding = {
                    type: 'webRequest-header',
                    key: header.name,
                    value: header.value.substring(0, 100),
                    timestamp: new Date().toISOString(),
                    url: url,
                    method: details.method,
                    hasCredentials: true
                };

                securityFindings.push(finding);
                enhancedData.network.push(finding); // Also add to network data
                console.warn('⚠️ Sensitive header detected:', finding);

                // Store findings with enhanced data
                chrome.storage.local.set({
                    findings: securityFindings,
                    enhancedData: enhancedData
                });
            }
        });

        return { requestHeaders: headers };
    }, {
        urls: ["<all_urls>"]
    }, ["requestHeaders", "extraHeaders"]
);

// Monitor cookies on all sites
chrome.cookies.onChanged.addListener(function(changeInfo) {
    const cookie = changeInfo.cookie;

    // Monitor all cookies, not just OpenAI
    const finding = {
        type: 'cookie-change',
        key: cookie.name,
        value: '[COOKIE_VALUE_REDACTED]', // Don't store actual cookie values
        domain: cookie.domain,
        path: cookie.path,
        httpOnly: cookie.httpOnly,
        secure: cookie.secure,
        sameSite: cookie.sameSite,
        timestamp: new Date().toISOString()
    };

    securityFindings.push(finding);
    console.log('🍪 Cookie change detected:', finding);

    // Store findings
    chrome.storage.local.set({ findings: securityFindings });
});

// Monitor tabs for navigation on all sites
chrome.webNavigation.onCompleted.addListener(function(details) {
    console.log('📍 Navigation completed:', details.url);

    // Check if it's an auth-related URL or contains sensitive patterns
    if (details.url.includes('/auth') ||
        details.url.includes('/login') ||
        details.url.includes('/oauth') ||
        details.url.includes('/token') ||
        details.url.includes('/api/') ||
        details.url.includes('/session')) {

        const finding = {
            type: 'navigation-auth',
            url: details.url,
            timestamp: new Date().toISOString(),
            method: 'GET'
        };

        securityFindings.push(finding);
        enhancedData.network.push(finding); // Add auth navigation to network
        chrome.storage.local.set({
            findings: securityFindings,
            enhancedData: enhancedData
        });
    }
});

// Clear findings command (for testing)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'CLEAR_FINDINGS' || request.type === 'CLEAR_ALL_DATA') {
        securityFindings = [];
        enhancedData = {
            network: [],
            classified: [],
            fingerprints: []
        };
        chrome.storage.local.set({
            findings: [],
            enhancedData: {}
        });
        sendResponse({ cleared: true });
    }
});

// Export findings command
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'EXPORT_FINDINGS') {
        sendResponse({
            findings: securityFindings,
            enhancedData: enhancedData
        });
    }
});