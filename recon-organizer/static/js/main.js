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
