/**
 * main.js - Client-Side Interactivity for Reconnaissance Information Organizer
 * 
 * Handles:
 * - Live terminal scanning animation during domain lookup
 * - Real-time history filtering
 * - Copy to clipboard functionality
 * - Quick lookup tool interactions
 */

document.addEventListener('DOMContentLoaded', () => {

    // 1. Domain Search with Live Terminal Simulation
    const scanForm = document.getElementById('scan-form');
    const domainInput = document.getElementById('domain-input');
    const scanBtn = document.getElementById('scan-btn');
    const terminalLoader = document.getElementById('terminal-loader');
    const terminalBody = document.getElementById('terminal-body');

    if (scanForm && domainInput) {
        scanForm.addEventListener('submit', async (e) => {
            const domain = domainInput.value.trim();
            if (!domain) return;

            // Prevent default form submit so we can show live scanning progress
            e.preventDefault();

            // Disable button and show terminal loader
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<span class="status-dot"></span> Scanning...';
            terminalLoader.style.display = 'block';
            terminalBody.innerHTML = '';

            const appendLog = (text, isSuccess = false, isError = false) => {
                const line = document.createElement('div');
                line.className = 'term-line' + (isSuccess ? ' done' : '') + (isError ? ' text-danger' : '');
                line.textContent = text;
                terminalBody.appendChild(line);
                terminalBody.scrollTop = terminalBody.scrollHeight;
            };

            appendLog(`[*] Initializing reconnaissance suite for target: ${domain}`);
            
            // Progressive status animations
            setTimeout(() => appendLog('[*] Step 1/3: Resolving IP addresses & reverse DNS records...'), 400);
            setTimeout(() => appendLog('[*] Step 2/3: Interrogating DNS zone (A, AAAA, MX, NS, TXT, SOA)...'), 900);
            setTimeout(() => appendLog('[*] Step 3/3: Querying WHOIS registrar databases...'), 1400);

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    appendLog('[+] Organizing collected data into SQLite database...', true);
                    appendLog('[+] Reconnaissance successful! Loading results...', true);
                    setTimeout(() => {
                        window.location.href = data.redirect_url;
                    }, 500);
                } else {
                    appendLog(`[-] Error: ${data.error || 'Reconnaissance failed.'}`, false, true);
                    scanBtn.disabled = false;
                    scanBtn.innerHTML = 'Initiate Recon';
                }
            } catch (err) {
                appendLog(`[-] Network communication error: ${err.message}`, false, true);
                scanBtn.disabled = false;
                scanBtn.innerHTML = 'Initiate Recon';
            }
        });
    }

    // 2. Sample Domain Hint Chips
    const hintChips = document.querySelectorAll('.hint-chip');
    hintChips.forEach(chip => {
        chip.addEventListener('click', () => {
            if (domainInput) {
                domainInput.value = chip.dataset.domain || chip.textContent.trim();
                domainInput.focus();
            }
        });
    });

    // 3. Copy to Clipboard Functionality
    document.querySelectorAll('.btn-copy').forEach(btn => {
        btn.addEventListener('click', () => {
            const textToCopy = btn.getAttribute('data-copy');
            if (textToCopy) {
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalText = btn.innerHTML;
                    btn.innerHTML = '✓ Copied';
                    btn.classList.add('text-neon-green');
                    setTimeout(() => {
                        btn.innerHTML = originalText;
                        btn.classList.remove('text-neon-green');
                    }, 1800);
                }).catch(err => {
                    console.error('Copy failed:', err);
                });
            }
        });
    });

    // 4. Live Search Filter for History Table
    const historySearch = document.getElementById('history-search');
    const historyRows = document.querySelectorAll('.history-row');

    if (historySearch && historyRows.length > 0) {
        historySearch.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();
            historyRows.forEach(row => {
                const domain = row.getAttribute('data-domain') || '';
                const ip = row.getAttribute('data-ip') || '';
                if (domain.toLowerCase().includes(query) || ip.toLowerCase().includes(query)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }

    // 5. Quick Lookup Tool Tabs and AJAX calls
    const tabBtns = document.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-target');
            const content = document.getElementById(targetId);
            if (content) content.classList.add('active');
        });
    });

});

// Helper for standalone Quick Lookup page
async function runQuickLookup(type) {
    const input = document.getElementById(`quick-${type}-input`);
    const btn = document.getElementById(`quick-${type}-btn`);
    const resultBox = document.getElementById(`quick-${type}-result`);

    if (!input || !input.value.trim()) return;

    btn.disabled = true;
    btn.textContent = 'Querying...';
    resultBox.style.display = 'block';
    resultBox.innerHTML = '<div class="text-cyber-blue mono">[*] Querying target...</div>';

    try {
        const response = await fetch('/api/quick-lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type, domain: input.value.trim() })
        });
        const data = await response.json();

        if (response.ok && data.success) {
            resultBox.innerHTML = `<pre class="mono" style="color: #00ff9d; font-size: 0.85rem; max-height: 350px; overflow-y: auto;">${JSON.stringify(data.data, null, 2)}</pre>`;
        } else {
            resultBox.innerHTML = `<div class="text-danger mono">[-] Error: ${data.error || 'Query failed'}</div>`;
        }
    } catch (err) {
        resultBox.innerHTML = `<div class="text-danger mono">[-] Network Error: ${err.message}</div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Run Query';
    }
}
