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

    // Simple markdown to HTML converter
    function mdToHtml(text) {
        if (!text) return '';
        let html = text;
        // Escape HTML first
        html = html.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        // Convert markdown
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
        html = html.replace(/`(.+?)`/g, '<code>$1</code>');
        html = html.replace(/^## (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^### (.+)$/gm, '<h4>$1</h4>');
        html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
        html = html.replace(/^(\d+)\. (.+)$/gm, '<li>$2</li>');
        html = html.replace(/\n\n/g, '</p><p>');
        html = html.replace(/\n/g, '<br>');
        // Wrap lists
        html = html.replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>');
        return '<p>' + html + '</p>';
    }

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

    // ── WebSocket with Improved Reconnection ────────────────
    let wsReconnectAttempts = 0;
    let wsReconnectDelay = 1000;
    const wsMaxReconnectDelay = 30000;
    let wsReconnecting = false;
    
    function connect() {
        // Prevent multiple connection attempts
        if (wsReconnecting && ws && ws.readyState === WebSocket.OPEN) {
            return;
        }
        
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${proto}//${location.host}/ws`);
        
        ws.onopen = () => {
            console.log('WS connected');
            wsReconnectAttempts = 0;
            wsReconnectDelay = 1000;
            wsReconnecting = false;
            updateConnectionStatus('connected');
        };
        
        ws.onclose = () => {
            console.log('WS disconnected');
            wsReconnecting = true;
            updateConnectionStatus('disconnected');
            
            // Exponential backoff
            wsReconnectAttempts++;
            const delay = Math.min(wsReconnectDelay * Math.pow(1.5, wsReconnectAttempts - 1), wsMaxReconnectDelay);
            console.log(`WS reconnecting in ${delay}ms (attempt ${wsReconnectAttempts})`);
            
            setTimeout(connect, delay);
        };
        
        ws.onerror = (e) => {
            console.error('WS error', e);
            updateConnectionStatus('error');
        };
        
        ws.onmessage = (e) => {
            try { handleEvent(JSON.parse(e.data)); } catch (err) { console.error('Parse error', err); }
        };
    }
    
    function updateConnectionStatus(status) {
        // Create status indicator if not exists
        let indicator = document.getElementById('ws-status');
        if (!indicator) {
            const header = document.querySelector('.header-stats');
            indicator = document.createElement('div');
            indicator.id = 'ws-status';
            indicator.style.cssText = 'width:8px;height:8px;border-radius:50%;margin-right:8px;';
            header.insertBefore(indicator, header.firstChild);
        }
        
        switch(status) {
            case 'connected':
                indicator.style.background = 'var(--success)';
                indicator.style.boxShadow = '0 0 6px var(--success)';
                break;
            case 'disconnected':
                indicator.style.background = 'var(--warning)';
                indicator.style.boxShadow = '0 0 6px var(--warning)';
                break;
            case 'error':
                indicator.style.background = 'var(--danger)';
                indicator.style.boxShadow = '0 0 6px var(--danger)';
                break;
        }
    }
    
    // Function to manually reconnect
    window.reconnectWebSocket = function() {
        if (ws) {
            ws.close();
        }
        wsReconnectAttempts = 0;
        wsReconnectDelay = 1000;
        connect();
    };

    // ── Event Handler ──────────────────────────────────────
    function handleEvent(evt) {
        console.log('Received event:', evt.type, evt);
        
        // Update token counter from any event that carries it
        if (evt.total_tokens && evt.total_tokens > 0) {
            const formatted = evt.total_tokens >= 1000000
                ? (evt.total_tokens / 1000000).toFixed(1) + 'M'
                : evt.total_tokens >= 1000
                ? (evt.total_tokens / 1000).toFixed(1) + 'K'
                : String(evt.total_tokens);
            const el = document.getElementById('stat-tokens');
            if (el) {
                el.textContent = formatted;
                popStat('stat-tokens');
            }
        }

        eventCount++;
        hideEmptyState();

        switch (evt.type) {
            case 'queue_started':
                setStatus('running', 'SCANNING');
                totalTargets = evt.total_targets || 1;
                if (totalTargets > 1) showQueueBar();
                addFeedItem(renderBanner('🚀', evt.content));
                break;

            case 'target_started':
                currentTargetIdx = evt.target_index || 1;
                updateQueueBar(currentTargetIdx, totalTargets, evt.target);
                addFeedItem(renderTargetBanner(evt.target));
                if (evt.agent_id) {
                    history.pushState(null, '', '/' + evt.agent_id);
                }
                break;

            case 'target_completed':
                addFeedItem(renderBanner('✅', `Completed: ${evt.content || evt.target}`, 'success'));
                break;

            case 'queue_finished':
                scanRunning = false;
                setStatus('finished', 'COMPLETED');
                stopTimer();
                toggleButtons(false);
                hideQueueBar();
                addFeedItem(renderBanner('🏁', evt.content || 'All targets completed', 'success'));
                break;

            case 'report_ready':
                showReportButton(evt.report_url || evt.content);
                addFeedItem(renderBanner('📄', 'Report ready! Click to download.', 'success'));
                break;

            case 'scan_started':
                setStatus('running', 'SCANNING');
                addFeedItem(renderBanner('🚀', evt.content));
                break;

            case 'thinking':
                iterCount++;
                const iterEl = document.getElementById('stat-iter');
                if (iterEl) iterEl.textContent = iterCount;
                popStat('stat-iter');
                addFeedItem(renderThinking(evt.content), true);
                break;

            case 'tool_call':
                toolCount++;
                const toolEl = document.getElementById('stat-tools');
                if (toolEl) toolEl.textContent = toolCount;
                popStat('stat-tools');
                toolUsage[evt.tool_name] = (toolUsage[evt.tool_name] || 0) + 1;
                updateToolStats();
                addFeedItem(renderToolCall(evt));
                break;

            case 'tool_result':
                addFeedItem(renderToolResult(evt));
                // Real-time vuln rendering
                if (evt.vulns && evt.vulns.length > 0) {
                    vulnCount += evt.vulns.length;
                    const vulnEl = document.getElementById('stat-vulns');
                    if (vulnEl) vulnEl.textContent = vulnCount;
                    popStat('stat-vulns');
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
                    popStat('stat-vulns');
                    renderVulns(evt.vulns);
                }
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
                addFeedItem(renderError(evt.content || 'Scan stopped by user'));
                break;
        }
    }

    // ── Renderers ──────────────────────────────────────────
    function renderBanner(icon, content, type = 'accent') {
        const el = document.createElement('div');
        el.className = 'event event-finished';
        if (type === 'success') {
            el.style.background = 'var(--success-subtle)';
        }
        el.innerHTML = `${icon} ${esc(content)}`;
        return el;
    }

    function renderTargetBanner(target) {
        const el = document.createElement('div');
        el.className = 'event event-target';
        el.innerHTML = `🎯 Scanning: ${esc(target)}`;
        return el;
    }

    function renderThinking(content) {
        const el = document.createElement('div');
        el.className = 'event event-think';
        el.innerHTML = `<div class="typing"><span></span><span></span><span></span></div> ${esc(content)}`;
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
                .map(([k, v]) => `${k}: ${typeof v === 'string' && v.length > 200 ? v.slice(0, 200) + '...' : v}`)
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
        const truncated = output.length > 600 ? output.slice(0, 600) + '...' : output;
        el.className = `event event-result${evt.error ? ' error' : ''}`;
        el.textContent = truncated;
        return el;
    }

    function renderMessage(content) {
        const el = document.createElement('div');
        el.className = 'event event-message';
        // Render markdown in messages
        el.innerHTML = mdToHtml(content);
        return el;
    }

    function renderError(content) {
        const el = document.createElement('div');
        el.className = 'event event-error';
        el.innerHTML = `⚠️ ${esc(content)}`;
        return el;
    }

    function renderFinished(content) {
        const el = document.createElement('div');
        el.className = 'event event-finished';
        el.innerHTML = `✅ <strong>Scan Complete:</strong> ${esc((content || '').slice(0, 500))}`;
        return el;
    }

    function renderVulns(vulns) {
        const list = document.getElementById('vuln-list');
        const empty = list.querySelector('.empty-state');
        if (empty) list.innerHTML = '';
        
        const countEl = document.getElementById('vuln-count');
        if (countEl) countEl.textContent = vulnCount;
        
        vulns.forEach((v) => {
            const li = document.createElement('li');
            li.className = 'vuln-item';
            li._vulnData = v;
            li.innerHTML = `
                <div class="vuln-header" style="cursor:pointer">
                    <span class="vuln-severity-dot ${v.severity.toLowerCase()}"></span>
                    <span class="vuln-title-text">${esc(v.title)}</span>
                    <span class="vuln-badge ${v.severity.toLowerCase()}">${v.severity.toUpperCase()}</span>
                </div>
            `;
            // Add click handler to open modal
            li.querySelector('.vuln-header').addEventListener('click', function() {
                openVulnModal(v);
            });
            list.appendChild(li);
        });
    }

    // Toggle vuln expand - now opens modal
    window.toggleVuln = function(el, vulnData) {
        // Store vuln data on the element if not already there
        if (vulnData) {
            el.closest('.vuln-item')._vulnData = vulnData;
        }
        const vulnItem = el.closest('.vuln-item');
        const v = vulnItem._vulnData;
        if (v) {
            openVulnModal(v);
        }
    };

    // Modal functions
    window.openVulnModal = function(v) {
        const modal = document.getElementById('vuln-modal');
        const titleEl = document.getElementById('modal-title');
        const bodyEl = document.getElementById('modal-body');
        
        titleEl.querySelector('#modal-severity-dot').className = `vuln-severity-dot ${v.severity.toLowerCase()}`;
        document.getElementById('modal-vuln-title').textContent = v.title;
        
        let html = `
            <div class="modal-meta">
                <div class="modal-meta-item">
                    <div class="modal-meta-label">Severity</div>
                    <div class="modal-meta-value ${v.severity.toLowerCase()}">${v.severity.toUpperCase()}</div>
                </div>
                <div class="modal-meta-item">
                    <div class="modal-meta-label">CVSS</div>
                    <div class="modal-meta-value ${v.severity.toLowerCase()}">${v.cvss ? v.cvss.toFixed(1) : 'N/A'}</div>
                </div>
                ${v.method ? `<div class="modal-meta-item"><div class="modal-meta-label">Method</div><div class="modal-meta-value">${esc(v.method)}</div></div>` : ''}
                ${v.cve ? `<div class="modal-meta-item"><div class="modal-meta-label">CVE</div><div class="modal-meta-value"><code class="modal-code">${esc(v.cve)}</code></div></div>` : ''}
            </div>
        `;
        
        if (v.endpoint) html += `<div class="modal-section"><div class="modal-label">Endpoint</div><div class="modal-value"><code class="modal-code">${esc(v.endpoint)}</code></div></div>`;
        if (v.description) html += `<div class="modal-section"><div class="modal-label">Description</div><div class="modal-value">${mdToHtml(v.description)}</div></div>`;
        if (v.impact) html += `<div class="modal-section"><div class="modal-label">Impact</div><div class="modal-value">${mdToHtml(v.impact)}</div></div>`;
        if (v.technical_analysis) html += `<div class="modal-section"><div class="modal-label">Technical Analysis</div><div class="modal-value">${mdToHtml(v.technical_analysis)}</div></div>`;
        if (v.poc_description) html += `<div class="modal-section"><div class="modal-label">Proof of Concept</div><div class="modal-value">${mdToHtml(v.poc_description)}</div></div>`;
        if (v.poc_script) html += `<div class="modal-section"><div class="modal-label">PoC Script</div><pre class="modal-pre">${esc(v.poc_script)}</pre></div>`;
        if (v.remediation) html += `<div class="modal-section"><div class="modal-label">Remediation</div><div class="modal-value">${mdToHtml(v.remediation)}</div></div>`;
        
        bodyEl.innerHTML = html;
        modal.classList.add('active');
    };

    window.closeModal = function() {
        document.getElementById('vuln-modal').classList.remove('active');
    };

    // Close modal on click outside
    document.getElementById('vuln-modal').addEventListener('click', function(e) {
        if (e.target === this) closeModal();
    });

    // Close help modal on click outside
    document.getElementById('help-modal').addEventListener('click', function(e) {
        if (e.target === this) closeHelpModal();
    });

    // Close modal on ESC
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
            closeHelpModal();
        }
    });

    function updateToolStats() {
        const list = document.getElementById('tools-list');
        const countEl = document.getElementById('tools-count');
        const entries = Object.entries(toolUsage).sort((a, b) => b[1] - a[1]);
        
        // Calculate total tool calls
        const totalCalls = Object.values(toolUsage).reduce((sum, count) => sum + count, 0);
        
        // Update header stat to match
        const headerToolEl = document.getElementById('stat-tools');
        if (headerToolEl) headerToolEl.textContent = totalCalls;
        
        // Show total in sidebar count
        countEl.textContent = totalCalls;
        
        if (entries.length === 0) {
            list.innerHTML = '<li class="empty-state" style="padding: 20px 0"><div class="empty-title" style="font-size: 13px">No tools used yet</div></li>';
            return;
        }
        
        list.innerHTML = entries.map(([name, count]) => `
            <li style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
                <span style="font-size:12px;color:var(--text-secondary)">${TOOL_ICONS[name] || '🔧'} ${name.replace(/_/g, ' ')}</span>
                <span style="font-size:12px;font-weight:600;color:var(--accent-primary)">${count}</span>
            </li>
        `).join('');
    }

    // ── Queue UI ───────────────────────────────────────────
    function showQueueBar() {
        document.getElementById('queue-bar').classList.add('active');
    }

    function updateQueueBar(idx, total, target) {
        document.getElementById('queue-progress').textContent = `Scanning ${idx}/${total}`;
        document.getElementById('queue-target').textContent = target || '';
        document.getElementById('queue-fill').style.width = `${(idx / total) * 100}%`;
    }

    function hideQueueBar() {
        document.getElementById('queue-bar').classList.remove('active');
    }

    // ── DOM Helpers ────────────────────────────────────────
    function addFeedItem(el, replace) {
        const feed = document.getElementById('feed-body');
        if (replace) {
            const lastThink = feed.querySelector('.event-think:last-of-type');
            if (lastThink) lastThink.remove();
        }
        feed.appendChild(el);
        feed.scrollTop = feed.scrollHeight;
    }

    function hideEmptyState() {
        const empty = document.getElementById('empty-state');
        if (empty) empty.style.display = 'none';
    }

    function setStatus(cls, text) {
        const badge = document.getElementById('status-badge');
        badge.className = `status-badge ${cls}`;
        document.getElementById('status-text').textContent = text;
        
        const feedCard = document.getElementById('feed-card');
        feedCard.classList.toggle('scanning', cls === 'running');
    }

    function toggleButtons(running) {
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        startBtn.classList.toggle('hidden', running);
        stopBtn.classList.toggle('hidden', !running);
        startBtn.disabled = false;
    }

    function showReportButton(url) {
        // Remove existing
        const existing = document.querySelector('.report-btn');
        if (existing) existing.remove();
        
        // Add to first sidebar card
        const card = document.querySelector('.sidebar-card');
        const btn = document.createElement('a');
        btn.href = url;
        btn.target = '_blank';
        btn.className = 'report-btn';
        btn.innerHTML = '📄 Download PDF Report';
        card.parentNode.insertBefore(btn, card.nextSibling);
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
    function formatDuration(totalSeconds) {
        const h = Math.floor(totalSeconds / 3600);
        const m = Math.floor((totalSeconds % 3600) / 60);
        const s = totalSeconds % 60;
        if (h > 0) return `${h}h ${m}m ${s}s`;
        return m > 0 ? `${m}m ${s}s` : `${s}s`;
    }

    function startTimer(startFrom) {
        scanStart = startFrom ? new Date(startFrom).getTime() : Date.now();
        timerInterval = setInterval(() => {
            const elapsed = Math.floor((Date.now() - scanStart) / 1000);
            document.getElementById('live-clock').textContent = formatDuration(elapsed);
        }, 1000);
    }

    function stopTimer() { 
        if (timerInterval) clearInterval(timerInterval); 
    }

    // ── Stat Pop Animation ─────────────────────────────────
    function popStat(id) {
        const el = document.getElementById(id);
        el.classList.remove('pop');
        void el.offsetWidth;
        el.classList.add('pop');
    }

    // ── Live Clock ─────────────────────────────────────────
    function updateClock() {
        const now = new Date();
        
        // If scan is running, show scan duration
        if (scanRunning && scanStart) {
            const elapsed = Math.floor((Date.now() - scanStart) / 1000);
            const h = Math.floor(elapsed / 3600);
            const m = Math.floor((elapsed % 3600) / 60);
            const s = elapsed % 60;
            
            let timeStr;
            if (h > 0) {
                // 1+ hours: HH:MM:SS
                timeStr = `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
            } else if (m > 0) {
                // 1-59 minutes: MM:SS
                timeStr = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
            } else {
                // Under 1 minute: Xs
                timeStr = `${s}s`;
            }
            document.getElementById('live-clock').textContent = timeStr;
        } else {
            // Show time of day when idle
            const h = String(now.getHours()).padStart(2, '0');
            const m = String(now.getMinutes()).padStart(2, '0');
            const s = String(now.getSeconds()).padStart(2, '0');
            document.getElementById('live-clock').textContent = `${h}:${m}:${s}`;
        }
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
                    document.getElementById('target-input').value = data.targets.join(', ');
                    loadedTargets = data.targets;
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
            targetInput = document.getElementById('target-input');
            targetInput.focus();
            targetInput.style.borderColor = '#ff4757';
            setTimeout(() => targetInput.style.borderColor = '', 2000);
            return;
        }

        const instruction = document.getElementById('instruction-input').value.trim();
        const scanMode = document.getElementById('scan-mode').value;
        
        // Get severity filter
        const severityFilter = [];
        if (document.getElementById('sev-critical').checked) severityFilter.push('critical');
        if (document.getElementById('sev-high').checked) severityFilter.push('high');
        if (document.getElementById('sev-medium').checked) severityFilter.push('medium');
        if (document.getElementById('sev-low').checked) severityFilter.push('low');
        if (document.getElementById('sev-info').checked) severityFilter.push('info');
        
        // Parse targets
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
        
        ['stat-iter', 'stat-tools', 'stat-vulns'].forEach(id => {
            document.getElementById(id).textContent = '0';
        });
        
        document.getElementById('feed-body').innerHTML = '';
        document.getElementById('vuln-list').innerHTML = '<li class="empty-state" style="padding:20px 0"><div class="empty-title">Scanning...</div></li>';
        document.getElementById('tools-list').innerHTML = '<li class="empty-state" style="padding:20px 0"><div class="empty-title">Waiting...</div></li>';
        
        // Remove report button if exists
        const reportBtn = document.querySelector('.report-btn');
        if (reportBtn) reportBtn.remove();

        scanRunning = true;
        toggleButtons(true);
        setStatus('running', 'SCANNING');
        startTimer();

        const payload = { targets, instruction, scan_mode: scanMode, severity_filter: severityFilter };

        // Include LLM provider settings
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

        const discordWebhook = document.getElementById('discord-webhook')?.value?.trim();
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

    window.clearFeed = function() {
        document.getElementById('feed-body').innerHTML = `
            <div class="empty-state" id="empty-state">
                <div class="empty-icon">🎯</div>
                <div class="empty-title">Ready to Scan</div>
                <div class="empty-desc">Enter a target and start your pentest</div>
            </div>
        `;
    };

    window.downloadEvents = function() {
        const feed = document.getElementById('feed-body');
        const text = feed.innerText;
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'xalgorix-feed.txt';
        a.click();
    };

    window.scrollToBottom = function() {
        const feed = document.getElementById('feed-body');
        feed.scrollTop = feed.scrollHeight;
    };

    window.loadLastScan = async function() {
        // First check if there's a running scan via /api/status
        try {
            const statusResp = await fetch('/api/status');
            const status = await statusResp.json();
            
            if (status.running && status.scan_id) {
                // There's a running scan, load it
                history.replaceState(null, '', '/' + status.scan_id);
                await loadScanById(status.scan_id);
                return;
            }
        } catch (e) {
            console.log('Status check failed');
        }
        
        // Otherwise try to load from URL path
        let scanId = window.location.pathname.replace('/', '');
        if (!scanId) {
            // Try to get latest scan
            try {
                const resp = await fetch('/api/scans/latest');
                const latest = await resp.json();
                if (latest && latest.id) {
                    scanId = latest.id;
                    history.replaceState(null, '', '/' + scanId);
                }
            } catch (e) {
                console.log('No latest scan found');
                return;
            }
        }
        
        if (scanId) {
            await loadScanById(scanId);
        }
    };

    async function loadScanById(scanId) {
        try {
            const resp = await fetch(`/api/scans/${encodeURIComponent(scanId)}`);
            const scan = await resp.json();
            if (!scan || !scan.id) return;

            // Reset UI
            iterCount = scan.iterations || 0;
            toolCount = scan.tool_calls || 0;
            vulnCount = (scan.vulns || []).length;
            
            const iterEl = document.getElementById('stat-iter');
            const toolsEl = document.getElementById('stat-tools');
            const vulnsEl = document.getElementById('stat-vulns');
            const tokensEl = document.getElementById('stat-tokens');
            
            if (iterEl) iterEl.textContent = String(iterCount);
            if (toolsEl) toolsEl.textContent = String(toolCount);
            if (vulnsEl) vulnsEl.textContent = String(vulnCount);

            // Tokens
            if (scan.total_tokens > 0 && tokensEl) {
                const formatted = scan.total_tokens >= 1000000
                    ? (scan.total_tokens / 1000000).toFixed(1) + 'M'
                    : scan.total_tokens >= 1000
                    ? (scan.total_tokens / 1000).toFixed(1) + 'K'
                    : String(scan.total_tokens);
                tokensEl.textContent = formatted;
            }

            // Vulns
            if (scan.vulns && scan.vulns.length > 0) {
                renderVulns(scan.vulns);
            }

            // Events
            const feed = document.getElementById('feed-body');
            feed.innerHTML = '';
            const events = scan.events || [];
            
            if (events.length > 0) {
                events.slice(-100).forEach(evt => {
                    const div = document.createElement('div');
                    if (evt.type === 'thinking') {
                        div.className = 'event event-think';
                        div.innerHTML = `<div class="typing"><span></span><span></span><span></span></div> ${esc(evt.content || '')}`;
                    } else if (evt.type === 'tool_call') {
                        div.className = 'event event-tool';
                        div.innerHTML = `<div class="event-tool-header"><span class="event-tool-icon">${TOOL_ICONS[evt.tool_name] || '🔧'}</span><span class="event-tool-name">${esc(evt.tool_name)}</span></div>`;
                    } else if (evt.type === 'tool_result') {
                        div.className = 'event event-result';
                        div.textContent = (evt.output || '').slice(0, 200);
                    } else if (evt.type === 'message') {
                        div.className = 'event event-message';
                        div.textContent = evt.content;
                    } else if (evt.type === 'finished') {
                        div.className = 'event event-finished';
                        div.textContent = `✅ ${evt.content || 'Completed'}`;
                    }
                    if (div.innerHTML) feed.appendChild(div);
                });
            }

            // Tool usage
            (scan.events || []).filter(e => e.type === 'tool_call').forEach(e => {
                toolUsage[e.tool_name] = (toolUsage[e.tool_name] || 0) + 1;
            });
            updateToolStats();

            // Status
            try {
                const statusResp = await fetch('/api/status');
                const serverStatus = await statusResp.json();
                if (serverStatus.running) {
                    setStatus('running', 'SCANNING');
                    scanRunning = true;
                    toggleButtons(true);
                    startTimer(scan.started_at ? new Date(scan.started_at) : null);
                } else if (scan.status === 'finished') {
                    setStatus('finished', 'COMPLETED');
                    showReportButton(`/api/report/${encodeURIComponent(scan.id)}`);
                }
            } catch (e) {}

            if (scan.target) {
                document.getElementById('target-input').value = scan.target;
            }

            feed.scrollTop = feed.scrollHeight;
        } catch (e) {
            console.log('No previous scan to restore');
        }
    };

    window.showHelp = function() {
        const modal = document.getElementById('help-modal');
        modal.classList.add('active');
    };

    window.closeHelpModal = function() {
        document.getElementById('help-modal').classList.remove('active');
    };

    // Enter key to start scan
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey && !scanRunning && document.activeElement.tagName !== 'TEXTAREA') {
            window.startScan();
        }
    });

    // LLM Provider Change
    window.onProviderChange = function () {
        const provider = document.getElementById('llm-provider').value;
        const p = LLM_PROVIDERS[provider] || {};
        document.getElementById('llm-model').value = p.model || '';
        document.getElementById('llm-apibase').value = p.base || '';
        document.getElementById('llm-model').placeholder = p.model ? `e.g. ${p.model}` : 'Model name';
    };

    // Rate Limiting
    window.saveRateLimit = async function() {
        const requests = parseInt(document.getElementById('rate-limit-requests').value) || 60;
        const windowSec = parseInt(document.getElementById('rate-limit-window').value) || 60;
        
        try {
            const resp = await fetch('/api/settings/rate-limit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ requests, window: windowSec })
            });
            const data = await resp.json();
            
            const statusEl = document.getElementById('rate-limit-status');
            statusEl.textContent = `✅ Saved: ${data.requests} requests/${data.window}s`;
            statusEl.style.color = 'var(--success)';
            
            // Hide status after 3 seconds
            setTimeout(() => {
                statusEl.textContent = '';
            }, 3000);
        } catch (err) {
            const statusEl = document.getElementById('rate-limit-status');
            statusEl.textContent = '❌ Failed to save';
            statusEl.style.color = 'var(--danger)';
        }
    };

    async function loadRateLimitSettings() {
        try {
            const resp = await fetch('/api/settings/rate-limit');
            const data = await resp.json();
            document.getElementById('rate-limit-requests').value = data.requests;
            document.getElementById('rate-limit-window').value = data.window;
        } catch (err) {
            console.log('Could not load rate limit settings');
        }
    }

    // Initialize severity checkbox handlers
    function initSeverityCheckboxes() {
        const checkboxes = ['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info'];
        checkboxes.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                const label = el.closest('.severity-checkbox');
                if (el.checked) {
                    label.classList.add('checked');
                }
                el.addEventListener('change', function() {
                    if (this.checked) {
                        label.classList.add('checked');
                    } else {
                        label.classList.remove('checked');
                    }
                });
            }
        });
    }

    // Initialize
    window.onProviderChange();
    loadRateLimitSettings();
    initSeverityCheckboxes();
    connect();
    
    // Polling fallback - check status every 5 seconds in case WebSocket fails
    setInterval(async () => {
        try {
            const resp = await fetch('/api/status');
            const status = await resp.json();
            if (status.running && !scanRunning) {
                // Scan started while we were disconnected - reload page
                location.reload();
            } else if (!status.running && scanRunning) {
                // Scan finished while we were disconnected - reload to show results
                location.reload();
            }
        } catch (e) {}
    }, 5000);
    
    // Fetch and display version
    async function loadVersion() {
        try {
            const resp = await fetch('/api/version');
            const data = await resp.json();
            if (data.version) {
                document.getElementById('version-display').textContent = data.version;
            }
        } catch (e) {
            console.error('Failed to load version:', e);
        }
    }
    loadVersion();
    
    // Check server status
    async function checkServerStatus() {
        try {
            const resp = await fetch('/api/status');
            const status = await resp.json();
            if (status.running && status.scan_id) {
                scanRunning = true;
                toggleButtons(true);
                setStatus('running', 'SCANNING');
                history.replaceState(null, '', '/' + status.scan_id);
                await loadLastScan();
            } else {
                await loadLastScan();
            }
        } catch (e) {
            await loadLastScan();
        }
    }
    
    checkServerStatus();
})();
