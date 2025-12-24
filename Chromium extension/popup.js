/**
 * Popup Script for Security Research Tool
 */

document.addEventListener('DOMContentLoaded', async() => {
    await loadFindings();

    // Button event listeners
    document.getElementById('exportBtn').addEventListener('click', exportFindings);
    document.getElementById('clearBtn').addEventListener('click', clearFindings);
    document.getElementById('refreshBtn').addEventListener('click', loadFindings);
});

async function loadFindings() {
    try {
        // Get findings from storage
        const result = await chrome.storage.local.get(['findings']);
        const findings = result.findings || [];

        // Update statistics
        updateStatistics(findings);

        // Display findings
        displayFindings(findings);
    } catch (error) {
        console.error('Error loading findings:', error);
    }
}

function updateStatistics(findings) {
    const stats = {
        total: findings.length,
        storage: 0,
        network: 0,
        cookies: 0
    };

    findings.forEach(finding => {
        // Check for storage-related findings
        if (finding.type.includes('storage') || finding.type.includes('Storage')) {
            stats.storage++;
        }
        // Check for network-related findings (including headers)
        if (finding.type.includes('fetch') || finding.type.includes('xhr') ||
            finding.type.includes('websocket') || finding.type.includes('webRequest')) {
            stats.network++;
        }
        // Check for cookie-related findings
        // This now includes webRequest-header with Cookie key, cookie-change, and cookie-existing
        if (finding.type.includes('cookie') ||
            (finding.type === 'webRequest-header' && finding.key && finding.key.toLowerCase() === 'cookie') ||
            finding.type === 'cookie-change' ||
            finding.type === 'cookie-existing') {
            stats.cookies++;
        }
    });

    document.getElementById('totalFindings').textContent = stats.total;
    document.getElementById('storageItems').textContent = stats.storage;
    document.getElementById('networkRequests').textContent = stats.network;
    document.getElementById('cookiesTracked').textContent = stats.cookies;
}

function displayFindings(findings) {
    const container = document.getElementById('findingsList');

    if (findings.length === 0) {
        container.innerHTML = '<div class="no-findings">No findings yet. Browse to a monitored site.</div>';
        return;
    }

    // Show last 10 findings
    const recentFindings = findings.slice(-10).reverse();

    container.innerHTML = recentFindings.map(finding => {
        const truncatedValue = finding.value ? finding.value.substring(0, 50) + '...' : 'N/A';

        return `
      <div class="finding-item">
        <div class="finding-type">🔍 ${finding.type}</div>
        <div class="finding-details">
          <strong>Key:</strong> ${finding.key || 'N/A'}<br>
          <strong>Value:</strong> ${truncatedValue}<br>
          <strong>Time:</strong> ${new Date(finding.timestamp).toLocaleTimeString()}
        </div>
      </div>
    `;
    }).join('');
}

async function exportFindings() {
    try {
        const result = await chrome.storage.local.get(['findings']);
        const findings = result.findings || [];

        if (findings.length === 0) {
            showStatus('No findings to export');
            return;
        }

        // Create export data
        const exportData = {
            exportDate: new Date().toISOString(),
            tool: '0DIN Sidekick Security Research Tool',
            findingsCount: findings.length,
            findings: findings.map(f => ({
                ...f,
                value: f.value ? f.value.substring(0, 200) + '...' : 'N/A' // Truncate sensitive data
            }))
        };

        // Create downloadable JSON
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        // Create download link
        const a = document.createElement('a');
        a.href = url;
        a.download = `0DIN-sniper-findings-${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        URL.revokeObjectURL(url);

        showStatus('Findings exported successfully');
    } catch (error) {
        console.error('Error exporting findings:', error);
        showStatus('Error exporting findings');
    }
}

async function clearFindings() {
    if (!confirm('Are you sure you want to clear all findings?')) {
        return;
    }

    try {
        await chrome.storage.local.set({ findings: [] });

        // Send message to background script
        chrome.runtime.sendMessage({ type: 'CLEAR_FINDINGS' });

        await loadFindings();
        showStatus('All findings cleared');
    } catch (error) {
        console.error('Error clearing findings:', error);
        showStatus('Error clearing findings');
    }
}

function showStatus(message) {
    const statusEl = document.getElementById('status');
    statusEl.textContent = message;
    statusEl.classList.add('active');

    setTimeout(() => {
        statusEl.classList.remove('active');
    }, 3000);
}