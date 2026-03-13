// Xalgorix Web UI — WebSocket client and DOM renderer
(function () {
    'use strict';

    let ws = null;
    let scanRunning = false;
    let iterCount = 0;
    let toolCount = 0;
    let vulnCount = 0;
    let eventCount = 0;
    let scanStart = null;
    let timerInterval = null;
    const toolUsage = {};

    // Multi-target queue
    let loadedTargets = [];
    let currentTargetIdx = 0;
    let totalTargets = 0;

    const TOOL_ICONS = {
        terminal_execute: '⚡', browser_action: '🌐', view_file: '📝', create_file: '📝',
        str_replace: '📝', insert_line: '📝', list_files: '📄', search_files: '🔍',
        proxy_request: '🔗', list_proxy_requests: '🔗', python_action: '🐍',
        web_search: '🔍', add_note: '📌', report_vulnerability: '🐛',
        create_agent: '🤖', finish: '✅',
    };

    const LLM_PROVIDERS = {
        minimax: { model: 'MiniMax-M2.5', prefix: 'minimax', base: 'https://api.minimax.io/' },
        openai: { model: 'gpt-4o', prefix: 'openai', base: 'https://api.openai.com/v1' },
        deepseek: { model: 'deepseek-chat', prefix: 'deepseek', base: 'https://api.deepseek.com/' },
        anthropic: { model: 'claude-sonnet-4-20250514', prefix: 'anthropic', base: 'https://api.anthropic.com/' },
        google: { model: 'gemini-2.5-flash', prefix: 'google', base: 'https://generativelanguage.googleapis.com/v1beta/openai/' },
        groq: { model: 'llama-3.3-70b-versatile', prefix: 'groq', base: 'https://api.groq.com/openai/v1' },
        ollama: { model: 'llama3', prefix: 'ollama', base: 'http://localhost:11434/v1' },
        custom: { model: '', prefix: '', base: '' },
    };

    // ── WebSocket ──────────────────────────────────────────
    function connect() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${proto}//${location.host}/ws`);
        ws.onopen = () => console.log('WS connected');
        ws.onclose = () => { setTimeout(connect, 2000); };
        ws.onerror = (e) => console.error('WS error', e);
        ws.onmessage = (e) => {
            try { handleEvent(JSON.parse(e.data)); } catch (err) { console.error('Parse error', err); }
        };
    }

    // ── Event Handler ──────────────────────────────────────
    function handleEvent(evt) {
        // Update token counter from any event that carries it
        if (evt.total_tokens && evt.total_tokens > 0) {
            const formatted = evt.total_tokens >= 1000000
                ? (evt.total_tokens / 1000000).toFixed(1) + 'M'
                : evt.total_tokens >= 1000
                ? (evt.total_tokens / 1000).toFixed(1) + 'K'
                : String(evt.total_tokens);
            const el = document.getElementById('stat-tokens');
            if (el.textContent !== formatted) {
                el.textContent = formatted;
                popStat('stat-tokens', formatted);
            }
        }

        eventCount++;
        document.getElementById('total-events').textContent = eventCount;
        document.getElementById('event-count').textContent = `${eventCount} events`;

        switch (evt.type) {
            case 'queue_started':
                setStatus('running', 'SCANNING');
                hideWelcome();
                totalTargets = evt.total_targets || 1;
                if (totalTargets > 1) showQueueBar(totalTargets);
                addFeedItem(renderBanner('🚀', evt.content, 'cyan'));
                break;

            case 'target_started':
                currentTargetIdx = evt.target_index || 1;
                updateQueueBar(currentTargetIdx, totalTargets, evt.target);
                updateTargetList(currentTargetIdx - 1, 'active');
                addFeedItem(renderTargetBanner(evt.content));
                // Set URL path to scan ID so this scan has a unique URL
                if (evt.agent_id) {
                    history.pushState(null, '', '/' + evt.agent_id);
                }
                break;

            case 'target_completed':
                updateTargetList(currentTargetIdx - 1, 'done');
                addFeedItem(renderBanner('✅', evt.content, 'green'));
                break;

            case 'queue_finished':
                scanRunning = false;
                setStatus('finished', 'COMPLETED');
                stopTimer();
                toggleButtons(false);
                hideQueueBar();
                addFeedItem(renderBanner('🏁', evt.content, 'green'));
                break;

            case 'scan_started':
                setStatus('running', 'SCANNING');
                hideWelcome();
                addFeedItem(renderBanner('🚀', evt.content, 'cyan'));
                break;

            case 'thinking':
                iterCount++;
                popStat('stat-iter', iterCount);
                addFeedItem(renderThinking(evt.content), true);
                break;

            case 'tool_call':
                toolCount++;
                popStat('stat-tools', toolCount);
                toolUsage[evt.tool_name] = (toolUsage[evt.tool_name] || 0) + 1;
                updateToolStats();
                addFeedItem(renderToolCall(evt));
                break;

            case 'tool_result':
                addFeedItem(renderToolResult(evt));
                // Real-time vuln rendering when report_vulnerability succeeds
                if (evt.vulns && evt.vulns.length > 0) {
                    vulnCount += evt.vulns.length;
                    popStat('stat-vulns', vulnCount);
                    renderVulns(evt.vulns);
                }
                break;

            case 'message':
                if (evt.content && evt.content.trim() && !hasToolTags(evt.content)) {
                    addFeedItem(renderMessage(evt.content));
                }
                break;

            case 'error':
                addFeedItem(renderError(evt.content));
                break;

            case 'finished':
                if (evt.vulns && evt.vulns.length > 0) {
                    vulnCount += evt.vulns.length;
                    popStat('stat-vulns', vulnCount);
                    renderVulns(evt.vulns);
                }
                // Don't stop timer here for multi-target — queue_finished handles that
                if (totalTargets <= 1) {
                    scanRunning = false;
                    setStatus('finished', 'COMPLETED');
                    stopTimer();
                    toggleButtons(false);
                    addFeedItem(renderFinished(evt.content));
                }
                break;

            case 'stopped':
                scanRunning = false;
                setStatus('idle', 'STOPPED');
                stopTimer();
                toggleButtons(false);
                hideQueueBar();
                addFeedItem(renderError(evt.content));
                break;
        }
    }

    // ── Renderers ──────────────────────────────────────────
    function renderBanner(icon, content, color) {
        const el = document.createElement('div');
        el.className = 'event event-finished';
        if (color === 'cyan') {
            el.style.borderLeftColor = '#06b6d4';
            el.style.background = 'rgba(6,182,212,0.05)';
            el.style.color = '#22d3ee';
        }
        el.innerHTML = `${icon} ${esc(content)}`;
        return el;
    }

    function renderTargetBanner(content) {
        const el = document.createElement('div');
        el.className = 'event event-target';
        el.innerHTML = `🎯 ${esc(content)}`;
        return el;
    }

    function renderThinking(content) {
        const el = document.createElement('div');
        el.className = 'event event-thinking';
        el.textContent = `◈ ${content}`;
        return el;
    }

    function renderToolCall(evt) {
        const el = document.createElement('div');
        el.className = 'event event-tool';
        const icon = TOOL_ICONS[evt.tool_name] || '🔧';
        const timeStr = evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '';
        let argsHTML = '';
        if (evt.tool_args && Object.keys(evt.tool_args).length > 0) {
            const argsText = Object.entries(evt.tool_args)
                .map(([k, v]) => `${k}: ${v.length > 200 ? v.slice(0, 200) + '...' : v}`)
                .join('\n');
            argsHTML = `<div class="event-tool-args">${esc(argsText)}</div>`;
        }
        el.innerHTML = `
      <div class="event-tool-header">
        <span class="event-tool-icon">${icon}</span>
        <span class="event-tool-name">${esc(evt.tool_name)}</span>
        <span class="event-tool-time">${timeStr}</span>
      </div>${argsHTML}`;
        return el;
    }

    function renderToolResult(evt) {
        const el = document.createElement('div');
        const output = evt.error || evt.output || '';
        const truncated = output.length > 500 ? output.slice(0, 500) + '...' : output;
        el.className = `event event-result${evt.error ? ' error' : ''}`;
        el.textContent = `→ ${truncated}`;
        return el;
    }

    function renderMessage(content) {
        const el = document.createElement('div');
        el.className = 'event event-message';
        el.textContent = content;
        return el;
    }

    function renderError(content) {
        const el = document.createElement('div');
        el.className = 'event event-error-msg';
        el.innerHTML = `⚠ ${esc(content)}`;
        return el;
    }

    function renderFinished(content) {
        const el = document.createElement('div');
        el.className = 'event event-finished';
        el.innerHTML = `✅ <strong>Finished:</strong> ${esc((content || '').slice(0, 500))}`;
        return el;
    }

    function renderVulns(vulns) {
        const list = document.getElementById('vuln-list');
        if (list.querySelector('.empty-state')) list.innerHTML = '';
        vulns.forEach((v) => {
            const li = document.createElement('li');
            li.className = 'vuln-item';

            // Build details HTML — only show non-empty fields
            const details = [];
            if (v.description) details.push(`<div class="vuln-detail-row"><span class="vuln-label">Description</span><span class="vuln-value">${esc(v.description)}</span></div>`);
            if (v.endpoint) details.push(`<div class="vuln-detail-row"><span class="vuln-label">Endpoint</span><code class="vuln-code">${esc(v.endpoint)}</code></div>`);
            if (v.method) details.push(`<div class="vuln-detail-row"><span class="vuln-label">Method</span><span class="vuln-value">${esc(v.method)}</span></div>`);
            if (v.cve) details.push(`<div class="vuln-detail-row"><span class="vuln-label">CVE</span><span class="vuln-value">${esc(v.cve)}</span></div>`);
            if (v.cvss) details.push(`<div class="vuln-detail-row"><span class="vuln-label">CVSS</span><span class="vuln-value vuln-cvss">${v.cvss.toFixed(1)}</span></div>`);
            if (v.impact) details.push(`<div class="vuln-detail-row"><span class="vuln-label">Impact</span><span class="vuln-value">${esc(v.impact)}</span></div>`);
            if (v.technical_analysis) details.push(`<div class="vuln-detail-row"><span class="vuln-label">Technical Analysis</span><span class="vuln-value">${esc(v.technical_analysis)}</span></div>`);
            if (v.poc_description) details.push(`<div class="vuln-detail-row"><span class="vuln-label">PoC</span><span class="vuln-value">${esc(v.poc_description)}</span></div>`);
            if (v.poc_script) details.push(`<div class="vuln-detail-row"><span class="vuln-label">PoC Script</span><pre class="vuln-pre">${esc(v.poc_script)}</pre></div>`);
            if (v.remediation) details.push(`<div class="vuln-detail-row"><span class="vuln-label">Remediation</span><span class="vuln-value">${esc(v.remediation)}</span></div>`);

            li.innerHTML = `
                <div class="vuln-header" onclick="this.parentElement.classList.toggle('expanded')">
                    <span class="vuln-severity ${v.severity.toLowerCase()}"></span>
                    <span class="vuln-title">${esc(v.title)}</span>
                    <span class="vuln-badge ${v.severity.toLowerCase()}">${v.severity.toUpperCase()}</span>
                    <span class="vuln-expand-icon">▸</span>
                </div>
                <div class="vuln-details">${details.join('') || '<div class="vuln-detail-row"><span class="vuln-value dim">No additional details available</span></div>'}</div>
            `;
            list.appendChild(li);
        });
    }

    function updateToolStats() {
        const container = document.getElementById('tool-stats');
        const entries = Object.entries(toolUsage).sort((a, b) => b[1] - a[1]);
        container.innerHTML = entries.map(([name, count]) => `
      <div class="tool-stat">
        <span class="tool-stat-name">${TOOL_ICONS[name] || '🔧'} ${name.replace(/_/g, ' ')}</span>
        <span class="tool-stat-count">${count}</span>
      </div>
    `).join('');
    }

    // ── Queue UI ───────────────────────────────────────────
    function showQueueBar(total) {
        const bar = document.getElementById('queue-bar');
        bar.style.display = '';
        document.getElementById('queue-fill').style.width = '0%';
    }

    function updateQueueBar(idx, total, target) {
        document.getElementById('queue-label').textContent = `Target ${idx}/${total}`;
        document.getElementById('queue-target').textContent = target || '';
        document.getElementById('queue-fill').style.width = `${(idx / total) * 100}%`;
    }

    function hideQueueBar() {
        document.getElementById('queue-bar').style.display = 'none';
    }

    function renderTargetList(targets) {
        const card = document.getElementById('targets-card');
        const list = document.getElementById('target-list');
        card.style.display = '';
        list.innerHTML = targets.map((t, i) => `
      <li data-idx="${i}">
        <span class="t-status pending"></span>
        <span>${esc(t)}</span>
      </li>
    `).join('');
        loadedTargets = targets;
    }

    function updateTargetList(idx, status) {
        const list = document.getElementById('target-list');
        const items = list.querySelectorAll('li');
        if (items[idx]) {
            const dot = items[idx].querySelector('.t-status');
            dot.className = `t-status ${status}`;
        }
    }

    // ── DOM Helpers ────────────────────────────────────────
    function addFeedItem(el, replace) {
        const feed = document.getElementById('feed');
        if (replace) {
            const lastThinking = feed.querySelector('.event-thinking:last-of-type');
            if (lastThinking) lastThinking.remove();
        }
        feed.appendChild(el);
        feed.scrollTop = feed.scrollHeight;
    }

    function hideWelcome() {
        const w = document.getElementById('welcome');
        if (w) w.style.display = 'none';
    }

    function setStatus(cls, text) {
        const badge = document.getElementById('status-badge');
        badge.className = `status-badge ${cls}`;
        document.getElementById('status-text').textContent = text;
        // Toggle scanning classes on header, logo, feed, activity ring
        const isScanning = cls === 'running';
        document.querySelector('.header').classList.toggle('scanning', isScanning);
        document.querySelector('.logo-icon').classList.toggle('scanning', isScanning);
        document.querySelector('.feed').classList.toggle('scanning', isScanning);
        document.getElementById('activity-ring').style.display = isScanning ? '' : 'none';
    }

    function toggleButtons(running) {
        document.getElementById('btn-scan').style.display = running ? 'none' : '';
        document.getElementById('btn-scan').disabled = false;
        document.getElementById('btn-stop').style.display = running ? '' : 'none';
    }

    function hasToolTags(str) {
        return /<function=|<\/function>|<parameter[= ]|<\/parameter>|<invoke\s/.test(str);
    }

    function esc(str) {
        const d = document.createElement('div');
        d.textContent = str || '';
        return d.innerHTML;
    }

    // ── Timer ──────────────────────────────────────────────
    function startTimer() {
        scanStart = Date.now();
        timerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - scanStart) / 1000);
            const m = Math.floor(elapsed / 60);
            const s = elapsed % 60;
            document.getElementById('duration').textContent = m > 0 ? `${m}m ${s}s` : `${s}s`;
        }, 1000);
    }

    function stopTimer() { if (timerInterval) clearInterval(timerInterval); }

    // ── Stat Pop Animation ─────────────────────────────────
    function popStat(id, value) {
        const el = document.getElementById(id);
        el.textContent = value;
        el.classList.remove('pop');
        void el.offsetWidth; // force reflow
        el.classList.add('pop');
    }

    // ── Live Clock ─────────────────────────────────────────
    function updateClock() {
        const now = new Date();
        const h = String(now.getHours()).padStart(2, '0');
        const m = String(now.getMinutes()).padStart(2, '0');
        const s = String(now.getSeconds()).padStart(2, '0');
        const el = document.getElementById('live-clock');
        if (el) el.textContent = `${h}:${m}:${s}`;
    }
    setInterval(updateClock, 1000);
    updateClock();

    // ── File Upload: Targets ───────────────────────────────
    window.handleTargetsFile = function (input) {
        const file = input.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        fetch('/api/upload-targets', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.targets && data.targets.length > 0) {
                    // Put targets in input (comma-separated for display)
                    document.getElementById('target-input').value = data.targets.join(', ');
                    loadedTargets = data.targets;
                    renderTargetList(data.targets);
                    // Mark button as loaded
                    input.closest('.file-btn').classList.add('loaded');
                }
            })
            .catch(err => console.error('Upload error:', err));
    };

    // ── File Upload: Instructions ──────────────────────────
    window.handleInstructionsFile = function (input) {
        const file = input.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        fetch('/api/upload-instructions', { method: 'POST', body: formData })
            .then(r => r.json())
            .then(data => {
                if (data.content) {
                    document.getElementById('instruction-input').value = data.content;
                    input.closest('.file-btn').classList.add('loaded');
                }
            })
            .catch(err => console.error('Upload error:', err));
    };

    // ── Actions ────────────────────────────────────────────
    window.startScan = function () {
        const targetInput = document.getElementById('target-input').value.trim();
        if (!targetInput) {
            document.getElementById('target-input').focus();
            document.getElementById('target-input').style.borderColor = '#ef4444';
            setTimeout(() => document.getElementById('target-input').style.borderColor = '', 2000);
            return;
        }

        const instruction = document.getElementById('instruction-input').value.trim();
        const scanMode = document.getElementById('scan-mode').value;

        // Use loaded targets if available, otherwise parse comma-separated
        let targets;
        if (loadedTargets.length > 0) {
            targets = loadedTargets;
        } else {
            targets = targetInput.split(',').map(t => t.trim()).filter(Boolean);
        }

        // Reset state
        iterCount = 0; toolCount = 0; vulnCount = 0; eventCount = 0;
        currentTargetIdx = 0; totalTargets = targets.length;
        Object.keys(toolUsage).forEach(k => delete toolUsage[k]);
        document.getElementById('stat-iter').textContent = '0';
        document.getElementById('stat-tools').textContent = '0';
        document.getElementById('stat-vulns').textContent = '0';
        document.getElementById('feed').innerHTML = '';
        document.getElementById('vuln-list').innerHTML = '<li class="empty-state">Scanning...</li>';
        document.getElementById('tool-stats').innerHTML = '<div class="empty-state" style="grid-column:1/-1">Waiting...</div>';

        // Show target list if multiple
        if (targets.length > 1) {
            renderTargetList(targets);
        }

        scanRunning = true;
        toggleButtons(true);
        setStatus('running', 'SCANNING');
        startTimer();

        const payload = { targets, instruction, scan_mode: scanMode };

        // Include LLM provider settings if user configured them
        const provider = document.getElementById('llm-provider').value;
        const modelInput = document.getElementById('llm-model').value.trim();
        const apiKey = document.getElementById('llm-apikey').value.trim();
        const apiBase = document.getElementById('llm-apibase').value.trim();

        if (modelInput) {
            const p = LLM_PROVIDERS[provider] || {};
            payload.model = p.prefix ? `${p.prefix}/${modelInput}` : modelInput;
        }
        if (apiKey) payload.api_key = apiKey;
        if (apiBase) payload.api_base = apiBase;

        const discordWebhook = document.getElementById('discord-webhook').value.trim();
        if (discordWebhook) payload.discord_webhook = discordWebhook;

        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(payload));
        } else {
            fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
        }
    };

    window.stopScan = function () {
        fetch('/api/stop', { method: 'POST' });
    };

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !scanRunning && document.activeElement.tagName !== 'TEXTAREA') {
            window.startScan();
        }
    });

    connect();

    // ── Always check if server has a running scan ────────────
    async function checkServerStatus() {
        try {
            const resp = await fetch('/api/status');
            const status = await resp.json();
            if (status.running === true) {
                scanRunning = true;
                toggleButtons(true);
                startTimer();
                setStatus('running', 'SCANNING');
                hideWelcome();
            }
        } catch (e) { /* ignore */ }
    }

    checkServerStatus();

    // ── Load Scan on Page Init (only if URL has a scan hash) ─────
    async function loadLastScan() {
        const scanId = window.location.pathname.replace('/', '');
        if (!scanId) return; // Root path = clean idle page

        try {
            // Load specific scan by ID from URL path
            const resp = await fetch(`/api/scans/${encodeURIComponent(scanId)}`);
            const scan = await resp.json();
            if (!scan || !scan.id) return;

            // Hide welcome message since we have scan data
            hideWelcome();

            // Restore stats
            iterCount = scan.iterations || 0;
            toolCount = scan.tool_calls || 0;
            eventCount = (scan.events || []).length;
            document.getElementById('stat-iter').textContent = String(iterCount);
            document.getElementById('stat-tools').textContent = String(toolCount);
            document.getElementById('total-events').textContent = eventCount;
            document.getElementById('event-count').textContent = `${eventCount} events`;

            // Restore tokens
            if (scan.total_tokens > 0) {
                const formatted = scan.total_tokens >= 1000000
                    ? (scan.total_tokens / 1000000).toFixed(1) + 'M'
                    : scan.total_tokens >= 1000
                    ? (scan.total_tokens / 1000).toFixed(1) + 'K'
                    : String(scan.total_tokens);
                document.getElementById('stat-tokens').textContent = formatted;
            }

            // Restore vulns
            if (scan.vulns && scan.vulns.length > 0) {
                vulnCount = scan.vulns.length;
                document.getElementById('stat-vulns').textContent = String(vulnCount);
                renderVulns(scan.vulns);
            }

            // Replay events into feed (limit to last 100 for performance)
            const feed = document.getElementById('feed-body');
            feed.innerHTML = '';
            const events = scan.events || [];
            if (events.length === 0) {
                const div = document.createElement('div');
                div.className = 'event-item';
                div.innerHTML = `<span class="event-text dim">Scan ${scan.status === 'running' ? 'in progress' : 'data available'} for ${escapeHtml(scan.target || 'unknown')}</span>`;
                feed.appendChild(div);
            }
            const eventsToShow = events.slice(-100);
            eventsToShow.forEach(evt => {
                const div = document.createElement('div');
                div.className = 'event-item';
                if (evt.type === 'thinking') {
                    div.innerHTML = `<span class="event-icon">◈</span> <span class="event-text dim">${escapeHtml(evt.content || '')}</span>`;
                } else if (evt.type === 'tool_call') {
                    const icon = TOOL_ICONS[evt.tool_name] || '🔧';
                    div.innerHTML = `<span class="event-icon">${icon}</span> <span class="event-tool">${evt.tool_name}</span>`;
                } else if (evt.type === 'tool_result') {
                    const txt = evt.error ? `ERROR: ${evt.error}` : (evt.output || '').slice(0, 200);
                    div.className += evt.error ? ' event-error-msg' : '';
                    div.innerHTML = `<span class="event-text dim">→ ${escapeHtml(txt)}</span>`;
                } else if (evt.type === 'message') {
                    div.innerHTML = `<span class="event-text">${escapeHtml(evt.content || '')}</span>`;
                } else if (evt.type === 'finished') {
                    div.className += ' event-finished';
                    div.innerHTML = `<span class="event-icon">✅</span> <span class="event-text">${escapeHtml(evt.content || 'Scan completed')}</span>`;
                }
                if (div.innerHTML) feed.appendChild(div);
            });

            // Restore tool usage
            (scan.events || []).filter(e => e.type === 'tool_call').forEach(e => {
                toolUsage[e.tool_name] = (toolUsage[e.tool_name] || 0) + 1;
            });
            renderToolUsage();

            // Set status — check actual server state, not stale scan record
            const badge = document.getElementById('status-badge');
            const statusText = document.getElementById('status-text');
            let actuallyRunning = false;
            try {
                const statusResp = await fetch('/api/status');
                const serverStatus = await statusResp.json();
                actuallyRunning = serverStatus.running === true;
            } catch (e) { /* ignore */ }

            badge.className = 'status-badge idle';
            if (actuallyRunning) {
                statusText.textContent = 'SCANNING';
                badge.className = 'status-badge running';
                scanRunning = true;
                toggleButtons(true);
                startTimer();
            } else if (scan.status === 'finished') {
                statusText.textContent = 'COMPLETED';
            } else {
                statusText.textContent = 'IDLE';
            }

            // Show target in input
            if (scan.target) {
                document.getElementById('target-input').value = scan.target;
            }

            feed.scrollTop = feed.scrollHeight;
        } catch (e) {
            console.log('No previous scan to restore');
        }
    }

    loadLastScan();

    // ── LLM Provider Change Handler ───────────────────────
    window.onProviderChange = function () {
        const provider = document.getElementById('llm-provider').value;
        const p = LLM_PROVIDERS[provider] || {};
        document.getElementById('llm-model').value = p.model || '';
        document.getElementById('llm-apibase').value = p.base || '';
        document.getElementById('llm-model').placeholder = p.model ? `e.g. ${p.model}` : 'Model name';
    };
    // Auto-fill default on load
    window.onProviderChange();
})();
