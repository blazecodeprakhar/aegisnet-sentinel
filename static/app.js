// AegisNet Sentinel SOC Dashboard Logic
let socket = null;
let trafficChart = null;
let severityChart = null;
let currentFilter = 'ALL';
let alertsList = [];
let prevTotalPackets = 0;
let ppsTimer = null;

// DOM Elements
const wsStatus = document.getElementById('wsStatus');
const wsText = document.getElementById('wsText');
const platformBadge = document.getElementById('platformBadge');
const platformText = document.getElementById('platformText');
const clockDisplay = document.getElementById('clockDisplay');

const kpiPackets = document.getElementById('kpiPackets');
const kpiPps = document.getElementById('kpiPps');
const kpiAlerts = document.getElementById('kpiAlerts');
const kpiBans = document.getElementById('kpiBans');
const kpiUptime = document.getElementById('kpiUptime');

const alertsTableBody = document.getElementById('alertsTableBody');
const bansListContainer = document.getElementById('bansListContainer');
const activeBansCountBadge = document.getElementById('activeBansCountBadge');
const manualBlockForm = document.getElementById('manualBlockForm');
const blockIpInput = document.getElementById('blockIpInput');

// Initialize Charts
function initCharts() {
    // 1. Traffic Breakdown Line Chart
    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: Array(15).fill(''),
            datasets: [
                {
                    label: 'TCP Packets',
                    data: Array(15).fill(0),
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.05)',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                },
                {
                    label: 'UDP Packets',
                    data: Array(15).fill(0),
                    borderColor: '#a855f7',
                    backgroundColor: 'rgba(168, 85, 247, 0.05)',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                },
                {
                    label: 'ICMP / Other',
                    data: Array(15).fill(0),
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.05)',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } } }
            },
            scales: {
                x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#6b7280' } },
                y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#9ca3af' }, beginAtZero: true }
            }
        }
    });

    // 2. Threat Severity Doughnut Chart
    const ctxSev = document.getElementById('severityChart').getContext('2d');
    severityChart = new Chart(ctxSev, {
        type: 'doughnut',
        data: {
            labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f59e0b', '#00f2fe', '#10b981'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#9ca3af', font: { family: 'Inter', size: 11 } } }
            },
            cutout: '70%'
        }
    });
}

// Clock
setInterval(() => {
    const now = new Date();
    clockDisplay.textContent = now.toTimeString().split(' ')[0];
}, 1000);

// WebSocket Manager
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;
    
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        wsStatus.className = 'status-badge ws-badge connected';
        wsText.textContent = 'LIVE FEED ONLINE';
        fetchInitialData();
    };

    socket.onmessage = (event) => {
        const payload = JSON.parse(event.data);
        handleWsEvent(payload);
    };

    socket.onclose = () => {
        wsStatus.className = 'status-badge ws-badge disconnected';
        wsText.textContent = 'RECONNECTING...';
        setTimeout(connectWebSocket, 3000);
    };

    socket.onerror = (err) => {
        console.error('WebSocket Error:', err);
    };
}

function handleWsEvent(msg) {
    if (msg.event === 'CONNECTED') {
        updateStats(msg.stats);
        if (msg.recent_alerts) {
            alertsList = msg.recent_alerts;
            renderAlertsTable();
        }
    } else if (msg.event === 'NEW_ALERT') {
        alertsList.unshift(msg.data);
        if (alertsList.length > 200) alertsList.pop();
        renderAlertsTable();
        if (msg.stats) updateStats(msg.stats);
        fetchBans();
    }
}

// REST Updates
async function fetchInitialData() {
    try {
        const resStats = await fetch('/api/stats');
        const statsData = await resStats.json();
        platformText.textContent = statsData.platform;
        updateStats(statsData.stats);

        const resAlerts = await fetch('/api/alerts');
        alertsList = await resAlerts.json();
        renderAlertsTable();

        fetchBans();
    } catch (err) {
        console.error('Error fetching initial data:', err);
    }
}

async function fetchBans() {
    try {
        const resBans = await fetch('/api/firewall/bans');
        const bans = await resBans.json();
        renderBans(bans);
    } catch (err) {
        console.error('Error fetching firewall bans:', err);
    }
}

function updateStats(stats) {
    if (!stats) return;

    kpiPackets.textContent = stats.total_packets.toLocaleString();
    kpiAlerts.textContent = stats.alerts_count;
    kpiBans.textContent = stats.active_bans_count;
    
    // Format uptime
    const secs = stats.uptime_seconds;
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    kpiUptime.textContent = `${m}m ${s}s`;

    // Calculate Packets Per Second (PPS)
    const pps = Math.max(0, stats.total_packets - prevTotalPackets);
    prevTotalPackets = stats.total_packets;
    kpiPps.textContent = pps;

    // Update Traffic Chart
    if (trafficChart) {
        trafficChart.data.datasets[0].data.shift();
        trafficChart.data.datasets[0].data.push(stats.tcp_packets);
        trafficChart.data.datasets[1].data.shift();
        trafficChart.data.datasets[1].data.push(stats.udp_packets);
        trafficChart.data.datasets[2].data.shift();
        trafficChart.data.datasets[2].data.push(stats.icmp_packets + stats.other_packets);
        trafficChart.update('none');
    }

    // Update Severity Chart
    if (severityChart && stats.severity_counts) {
        severityChart.data.datasets[0].data = [
            stats.severity_counts.CRITICAL || 0,
            stats.severity_counts.HIGH || 0,
            stats.severity_counts.MEDIUM || 0,
            stats.severity_counts.LOW || 0
        ];
        severityChart.update();
    }
}

function renderAlertsTable() {
    const filtered = currentFilter === 'ALL' ? alertsList : alertsList.filter(a => a.severity === currentFilter);

    if (filtered.length === 0) {
        alertsTableBody.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    <i class="fa-solid fa-shield-cat"></i> No ${currentFilter !== 'ALL' ? currentFilter : ''} security alerts logged.
                </td>
            </tr>`;
        return;
    }

    alertsTableBody.innerHTML = filtered.map(alert => `
        <tr>
            <td>${alert.formatted_time || ''}</td>
            <td><span class="severity-pill sev-${alert.severity}">${alert.severity}</span></td>
            <td><strong>${alert.type}</strong></td>
            <td><span class="text-cyan">${alert.src_ip}</span></td>
            <td style="color: var(--text-secondary); max-width: 320px;">${alert.details}</td>
            <td><span class="action-badge action-${alert.firewall_action}">${alert.firewall_action}</span></td>
        </tr>
    `).join('');
}

function renderBans(bans) {
    activeBansCountBadge.textContent = `${bans.length} ACTIVE`;

    if (bans.length === 0) {
        bansListContainer.innerHTML = `<div class="empty-bans">No active IP bans currently enforced.</div>`;
        return;
    }

    bansListContainer.innerHTML = bans.map(b => `
        <div class="ban-item">
            <div>
                <div class="ban-ip"><i class="fa-solid fa-ban"></i> ${b.ip}</div>
                <div class="ban-meta">${b.reason} • Expiring in ${b.remaining_seconds}s</div>
            </div>
            <button class="btn-sm-unblock" onclick="unblockIp('${b.ip}')">UNBLOCK</button>
        </div>
    `).join('');
}

async function unblockIp(ip) {
    try {
        const res = await fetch('/api/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        if (res.ok) {
            fetchBans();
        }
    } catch (err) {
        console.error('Failed to unblock IP:', err);
    }
}

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        renderAlertsTable();
    });
});

// Manual Block Form Handler
manualBlockForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const ip = blockIpInput.value.trim();
    if (!ip) return;

    try {
        const res = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: "Manual SOC Admin Block", ttl_seconds: 300 })
        });
        if (res.ok) {
            blockIpInput.value = '';
            fetchBans();
        } else {
            alert('Failed to block IP. Check IP syntax or whitelist settings.');
        }
    } catch (err) {
        console.error('Error blocking IP manually:', err);
    }
});

// Auto-refresh bans every 5 seconds for countdowns
setInterval(fetchBans, 5000);

// Init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    connectWebSocket();
});
