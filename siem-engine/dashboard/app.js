/**
 * =============================================================================
 * GHAYMAH SIEM DASHBOARD — Frontend Application
 * =============================================================================
 * Connects to the Python SIEM engine API, fetches alerts and malicious IPs,
 * and renders them in real-time on the dashboard.
 * =============================================================================
 */

(function () {
    'use strict';

    // ── Configuration ──
    const CONFIG = {
        API_BASE: window.location.origin,
        REFRESH_INTERVAL: 5000,  // ms
        MAX_VISIBLE_ALERTS: 200,
    };

    // ── State ──
    let allAlerts = [];
    let allIPs = [];
    let stats = {};
    let currentFilters = { severity: 'all', source: 'all' };

    // ── DOM References ──
    const DOM = {
        // Stats
        countCritical: document.getElementById('count-critical'),
        countHigh: document.getElementById('count-high'),
        countMedium: document.getElementById('count-medium'),
        countLow: document.getElementById('count-low'),
        countTotal: document.getElementById('count-total'),
        countIPs: document.getElementById('count-ips'),
        // Lists
        alertsList: document.getElementById('alerts-list'),
        ipsList: document.getElementById('ips-list'),
        ipCountBadge: document.getElementById('ip-count-badge'),
        // Filters
        filterSeverity: document.getElementById('filter-severity'),
        filterSource: document.getElementById('filter-source'),
        // Modal
        modalOverlay: document.getElementById('modal-overlay'),
        modalTitle: document.getElementById('modal-title'),
        modalBody: document.getElementById('modal-body'),
        modalClose: document.getElementById('modal-close'),
        // Status
        lastUpdate: document.getElementById('last-update'),
    };

    // ── API Fetchers ──

    async function fetchAlerts() {
        try {
            const res = await fetch(`${CONFIG.API_BASE}/api/alerts`);
            if (res.ok) {
                allAlerts = await res.json();
                renderAlerts();
            }
        } catch (err) {
            console.warn('[SIEM] Failed to fetch alerts:', err.message);
        }
    }

    async function fetchIPs() {
        try {
            const res = await fetch(`${CONFIG.API_BASE}/api/ips`);
            if (res.ok) {
                allIPs = await res.json();
                renderIPs();
            }
        } catch (err) {
            console.warn('[SIEM] Failed to fetch IPs:', err.message);
        }
    }

    async function fetchStats() {
        try {
            const res = await fetch(`${CONFIG.API_BASE}/api/stats`);
            if (res.ok) {
                stats = await res.json();
                renderStats();
            }
        } catch (err) {
            console.warn('[SIEM] Failed to fetch stats:', err.message);
        }
    }

    // ── Renderers ──

    function renderStats() {
        const sev = stats.by_severity || {};
        animateCounter(DOM.countCritical, sev.CRITICAL || 0);
        animateCounter(DOM.countHigh, sev.HIGH || 0);
        animateCounter(DOM.countMedium, sev.MEDIUM || 0);
        animateCounter(DOM.countLow, (sev.LOW || 0) + (sev.INFO || 0));
        animateCounter(DOM.countTotal, stats.total_alerts || 0);
        animateCounter(DOM.countIPs, (stats.malicious_ips || 0) + (stats.suspicious_ips || 0));

        DOM.lastUpdate.textContent = `Updated: ${new Date().toLocaleTimeString()}`;
    }

    function animateCounter(el, target) {
        const current = parseInt(el.textContent) || 0;
        if (current === target) return;

        const diff = target - current;
        const steps = Math.min(Math.abs(diff), 20);
        const increment = diff / steps;
        let step = 0;

        const timer = setInterval(() => {
            step++;
            if (step >= steps) {
                el.textContent = target;
                clearInterval(timer);
            } else {
                el.textContent = Math.round(current + increment * step);
            }
        }, 30);
    }

    function renderAlerts() {
        const filtered = allAlerts.filter(alert => {
            if (currentFilters.severity !== 'all' && alert.severity !== currentFilters.severity) return false;
            if (currentFilters.source !== 'all' && alert.source !== currentFilters.source) return false;
            return true;
        }).slice(0, CONFIG.MAX_VISIBLE_ALERTS);

        if (filtered.length === 0) {
            DOM.alertsList.innerHTML = `
                <div class="empty-state">
                    <p>🛡️ No alerts matching current filters.</p>
                </div>
            `;
            return;
        }

        DOM.alertsList.innerHTML = filtered.map(alert => `
            <div class="alert-item" data-alert-id="${escapeHtml(alert.id)}" onclick="window.showAlertDetail('${escapeHtml(alert.id)}')">
                <div class="alert-severity-bar ${alert.severity.toLowerCase()}"></div>
                <div class="alert-content">
                    <div class="alert-header">
                        <span class="alert-badge badge-${alert.severity.toLowerCase()}">${escapeHtml(alert.severity)}</span>
                        <span class="source-badge ${escapeHtml(alert.source)}">${getSourceIcon(alert.source)} ${escapeHtml(alert.source)}</span>
                        <span class="alert-rule-name">${escapeHtml(alert.rule_name)}</span>
                    </div>
                    <div class="alert-description">${escapeHtml(alert.description)}</div>
                    <div class="alert-meta">
                        <span class="alert-meta-item">
                            🆔 <span>${escapeHtml(alert.rule_id)}</span>
                        </span>
                        <span class="alert-meta-item">
                            🌐 <span class="alert-ip">${escapeHtml(alert.source_ip)}</span>
                        </span>
                        ${alert.port ? `<span class="alert-meta-item">🔌 Port ${alert.port}</span>` : ''}
                        <span class="alert-meta-item">
                            🕐 ${formatTimestamp(alert.timestamp)}
                        </span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    function renderIPs() {
        DOM.ipCountBadge.textContent = allIPs.length;

        if (allIPs.length === 0) {
            DOM.ipsList.innerHTML = `
                <div class="empty-state">
                    <p>✅ No malicious IPs detected.</p>
                </div>
            `;
            return;
        }

        DOM.ipsList.innerHTML = allIPs.map(ip => {
            const scoreClass = ip.score >= 70 ? 'score-critical' :
                               ip.score >= 40 ? 'score-high' : 'score-medium';
            return `
                <div class="ip-item">
                    <div class="ip-score ${scoreClass}">${ip.score}</div>
                    <div class="ip-details">
                        <div class="ip-address">${escapeHtml(ip.ip)}</div>
                        <div class="ip-stats">
                            <span class="ip-stat">Events: <strong>${ip.total_events}</strong></span>
                            <span class="ip-stat">Failed Auth: <strong>${ip.failed_logins}</strong></span>
                            <span class="ip-stat">Scans: <strong>${ip.port_scans}</strong></span>
                            <span class="ip-stat">Blocked: <strong>${ip.blocked_requests}</strong></span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    // ── Alert Detail Modal ──

    window.showAlertDetail = function (alertId) {
        const alert = allAlerts.find(a => a.id === alertId);
        if (!alert) return;

        DOM.modalTitle.textContent = `${alert.rule_name} — ${alert.id}`;
        DOM.modalBody.innerHTML = `
            <div class="detail-row">
                <span class="detail-label">Alert ID</span>
                <span class="detail-value">${escapeHtml(alert.id)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Timestamp</span>
                <span class="detail-value">${escapeHtml(alert.timestamp)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Severity</span>
                <span class="detail-value"><span class="alert-badge badge-${alert.severity.toLowerCase()}">${escapeHtml(alert.severity)}</span></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Source</span>
                <span class="detail-value"><span class="source-badge ${escapeHtml(alert.source)}">${getSourceIcon(alert.source)} ${escapeHtml(alert.source)}</span></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Rule</span>
                <span class="detail-value">${escapeHtml(alert.rule_id)} — ${escapeHtml(alert.rule_name)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Source IP</span>
                <span class="detail-value alert-ip">${escapeHtml(alert.source_ip)}</span>
            </div>
            ${alert.destination_ip ? `
            <div class="detail-row">
                <span class="detail-label">Destination IP</span>
                <span class="detail-value">${escapeHtml(alert.destination_ip)}</span>
            </div>` : ''}
            ${alert.port ? `
            <div class="detail-row">
                <span class="detail-label">Port</span>
                <span class="detail-value">${alert.port}</span>
            </div>` : ''}
            ${alert.count > 1 ? `
            <div class="detail-row">
                <span class="detail-label">Event Count</span>
                <span class="detail-value">${alert.count}</span>
            </div>` : ''}
            ${alert.mitre_tactic ? `
            <div class="detail-row">
                <span class="detail-label">MITRE Tactic</span>
                <span class="detail-value">${escapeHtml(alert.mitre_tactic)}</span>
            </div>` : ''}
            ${alert.mitre_technique ? `
            <div class="detail-row">
                <span class="detail-label">MITRE Technique</span>
                <span class="detail-value">${escapeHtml(alert.mitre_technique)}</span>
            </div>` : ''}
            <div class="detail-row">
                <span class="detail-label">Description</span>
                <span class="detail-value">${escapeHtml(alert.description)}</span>
            </div>
            ${alert.raw_log ? `
            <div class="detail-row">
                <span class="detail-label">Raw Log</span>
                <span class="detail-value raw-log">${escapeHtml(alert.raw_log)}</span>
            </div>` : ''}
        `;

        DOM.modalOverlay.classList.add('active');
    };

    function closeModal() {
        DOM.modalOverlay.classList.remove('active');
    }

    // ── Utilities ──

    function escapeHtml(str) {
        if (typeof str !== 'string') return String(str);
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function getSourceIcon(source) {
        const icons = { firewall: '🔥', webserver: '🌐', auth: '🔑' };
        return icons[source] || '📋';
    }

    function formatTimestamp(ts) {
        try {
            const d = new Date(ts);
            return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        } catch {
            return ts;
        }
    }

    // ── Event Listeners ──

    DOM.filterSeverity.addEventListener('change', (e) => {
        currentFilters.severity = e.target.value;
        renderAlerts();
    });

    DOM.filterSource.addEventListener('change', (e) => {
        currentFilters.source = e.target.value;
        renderAlerts();
    });

    DOM.modalClose.addEventListener('click', closeModal);
    DOM.modalOverlay.addEventListener('click', (e) => {
        if (e.target === DOM.modalOverlay) closeModal();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });

    // ── Initialize ──

    async function init() {
        console.log('[SIEM] Initializing Ghaymah SIEM Dashboard...');
        await Promise.all([fetchAlerts(), fetchIPs(), fetchStats()]);

        // Auto-refresh
        setInterval(async () => {
            await Promise.all([fetchAlerts(), fetchIPs(), fetchStats()]);
        }, CONFIG.REFRESH_INTERVAL);

        console.log('[SIEM] Dashboard initialized. Refreshing every', CONFIG.REFRESH_INTERVAL / 1000, 'seconds.');
    }

    init();
})();
