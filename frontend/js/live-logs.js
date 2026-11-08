/* =====================================================
   SentinelAI-X — Live Logs logic
   Vanilla JS: simulated log stream, search/filter,
   pause/resume, clear, export, auto-scroll terminal
===================================================== */

(function () {
  'use strict';

  /* ---------- Sidebar toggle (mobile) ---------- */

  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  const menuToggle = document.getElementById('menu-toggle');

  function openSidebar() {
    sidebar.classList.add('is-open');
    backdrop.classList.add('is-open');
  }

  function closeSidebar() {
    sidebar.classList.remove('is-open');
    backdrop.classList.remove('is-open');
  }

  menuToggle.addEventListener('click', function () {
    sidebar.classList.contains('is-open') ? closeSidebar() : openSidebar();
  });

  backdrop.addEventListener('click', closeSidebar);

  document.querySelectorAll('.nav-link').forEach(function (link) {
    link.addEventListener('click', closeSidebar);
  });

  /* ---------- Logout ---------- */

  document.getElementById('logout-btn').addEventListener('click', function () {
    window.location.href = 'login.html';
  });

  /* ---------- Live clock ---------- */

  const clockTime = document.getElementById('clock-time');
  const clockDate = document.getElementById('clock-date');

  function updateClock() {
    const now = new Date();
    clockTime.textContent =
      String(now.getHours()).padStart(2, '0') + ':' +
      String(now.getMinutes()).padStart(2, '0') + ':' +
      String(now.getSeconds()).padStart(2, '0');
    clockDate.textContent = now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
  }

  updateClock();
  window.setInterval(updateClock, 1000);

  /* ---------- Helpers ---------- */

  function clamp(val, min, max) { return Math.max(min, Math.min(max, val)); }
  function randomWalk(value, min, max, step) { return clamp(value + (Math.random() - 0.5) * step, min, max); }
  function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

  function formatTime(date) {
    return String(date.getHours()).padStart(2, '0') + ':' +
           String(date.getMinutes()).padStart(2, '0') + ':' +
           String(date.getSeconds()).padStart(2, '0');
  }

  function internalIp() {
    return '10.0.4.' + randInt(2, 90);
  }

  function externalIp() {
    const pools = ['203.0.113.', '198.51.100.', '192.0.2.'];
    return pools[randInt(0, pools.length - 1)] + randInt(2, 250);
  }

  /* ---------- Log templates ---------- */

  const templates = [
    { severity: 'info', eventType: 'Connection Established', status: 'Allowed', msg: 'TCP handshake completed', dir: 'out' },
    { severity: 'info', eventType: 'DNS Query', status: 'Allowed', msg: 'Domain lookup resolved successfully', dir: 'out' },
    { severity: 'info', eventType: 'SSL Handshake', status: 'Allowed', msg: 'TLS 1.3 session negotiated', dir: 'out' },
    { severity: 'success', eventType: 'Login Successful', status: 'Allowed', msg: 'Agent authenticated via secure token', dir: 'in' },
    { severity: 'success', eventType: 'Scan Completed', status: 'Allowed', msg: 'Full sweep completed with no issues found', dir: 'internal' },
    { severity: 'success', eventType: 'Signature Update', status: 'Allowed', msg: 'Threat intelligence feed synced', dir: 'internal' },
    { severity: 'warning', eventType: 'Rate Limit Exceeded', status: 'Monitored', msg: 'Client exceeded request threshold', dir: 'in' },
    { severity: 'warning', eventType: 'Unusual Traffic Pattern', status: 'Monitored', msg: 'Elevated retransmission rate observed', dir: 'in' },
    { severity: 'warning', eventType: 'Session Anomaly', status: 'Monitored', msg: 'Session duration outside normal range', dir: 'in' },
    { severity: 'critical', eventType: 'Port Scan Detected', status: 'Blocked', msg: 'Sequential SYN packets across multiple ports', dir: 'in' },
    { severity: 'critical', eventType: 'Brute Force Attempt', status: 'Blocked', msg: 'Repeated failed authentication attempts', dir: 'in' },
    { severity: 'critical', eventType: 'Malware Signature Match', status: 'Blocked', msg: 'Payload matched known threat signature', dir: 'in' },
    { severity: 'critical', eventType: 'Firewall Rule Triggered', status: 'Blocked', msg: 'Inbound connection violated policy rule #14', dir: 'in' }
  ];

  function buildLogEntry() {
    const t = templates[randInt(0, templates.length - 1)];
    let sourceIp, destIp;

    if (t.dir === 'in') { sourceIp = externalIp(); destIp = internalIp(); }
    else if (t.dir === 'out') { sourceIp = internalIp(); destIp = externalIp(); }
    else { sourceIp = internalIp(); destIp = internalIp(); }

    return {
      id: Date.now() + '-' + Math.random().toString(36).slice(2, 7),
      time: new Date(),
      sourceIp: sourceIp,
      destIp: destIp,
      eventType: t.eventType,
      severity: t.severity,
      status: t.status,
      msg: t.msg
    };
  }

  /* ---------- State ---------- */

  const MAX_STORE = 250;
  const MAX_TERMINAL_LINES = 80;
  const MAX_TABLE_ROWS = 40;

  let logStore = [];
  let activeLevel = 'all';
  let searchTerm = '';
  let isPaused = false;
  let genInterval = null;

  let stats = { total: 0, critical: 0, blocked: 0 };
  let activeConnections = 46;

  /* ---------- DOM refs ---------- */

  const terminal = document.getElementById('log-terminal');
  const tableBody = document.getElementById('log-table-body');
  const emptyNote = document.getElementById('log-empty-note');
  const tableHint = document.getElementById('log-table-hint');
  const searchInput = document.getElementById('log-search');
  const filterChips = document.querySelectorAll('.chip');

  const statTotalEl = document.getElementById('stat-total-value');
  const statCriticalEl = document.getElementById('stat-critical-value');
  const statBlockedEl = document.getElementById('stat-blocked-value');
  const statConnectionsEl = document.getElementById('stat-connections-value');

  /* ---------- Matching ---------- */

  function matchesFilter(entry) {
    const matchesLevel = activeLevel === 'all' || entry.severity === activeLevel;
    const term = searchTerm;
    const matchesSearch = term === '' ||
      entry.sourceIp.indexOf(term) !== -1 ||
      entry.destIp.indexOf(term) !== -1 ||
      entry.eventType.toLowerCase().indexOf(term) !== -1 ||
      entry.msg.toLowerCase().indexOf(term) !== -1;
    return matchesLevel && matchesSearch;
  }

  /* ---------- Terminal rendering ---------- */

  let autoScroll = true;

  terminal.addEventListener('scroll', function () {
    autoScroll = terminal.scrollTop + terminal.clientHeight >= terminal.scrollHeight - 30;
  });

  function terminalLineHtml(entry) {
    return '<span class="t-time">[' + formatTime(entry.time) + ']</span> ' +
      '<span class="t-tag">' + entry.severity.toUpperCase() + '</span> ' +
      entry.sourceIp + ' &rarr; ' + entry.destIp + ' &middot; ' +
      entry.eventType + ' — ' + entry.msg;
  }

  function appendTerminalLine(entry) {
    const line = document.createElement('div');
    line.className = 'terminal__line level-' + entry.severity;
    line.innerHTML = terminalLineHtml(entry);
    terminal.appendChild(line);

    while (terminal.children.length > MAX_TERMINAL_LINES) {
      terminal.removeChild(terminal.firstChild);
    }

    if (autoScroll) terminal.scrollTop = terminal.scrollHeight;
  }

  function rebuildTerminal() {
    terminal.innerHTML = '';
    const filtered = logStore.filter(matchesFilter).slice(-MAX_TERMINAL_LINES);
    filtered.forEach(function (entry) {
      const line = document.createElement('div');
      line.className = 'terminal__line level-' + entry.severity;
      line.innerHTML = terminalLineHtml(entry);
      line.style.animation = 'none';
      line.style.opacity = '1';
      terminal.appendChild(line);
    });
    terminal.scrollTop = terminal.scrollHeight;
    autoScroll = true;
  }

  /* ---------- Table rendering ---------- */

  function levelBadge(severity) {
    return '<span class="level-badge level-badge--' + severity + '">' + severity + '</span>';
  }

  function statusDotClass(status) {
    if (status === 'Blocked') return 'dot--danger';
    if (status === 'Monitored') return 'dot--warn';
    return 'dot--ok';
  }

  function tableRowHtml(entry) {
    return '<tr>' +
      '<td class="mono dim" data-label="Timestamp">' + formatTime(entry.time) + '</td>' +
      '<td class="mono" data-label="Source IP">' + entry.sourceIp + '</td>' +
      '<td class="mono" data-label="Destination IP">' + entry.destIp + '</td>' +
      '<td data-label="Event Type">' + entry.eventType + '</td>' +
      '<td data-label="Severity">' + levelBadge(entry.severity) + '</td>' +
      '<td data-label="Status"><span class="status-tag"><span class="dot ' + statusDotClass(entry.status) + '"></span>' + entry.status + '</span></td>' +
    '</tr>';
  }

  function prependTableRow(entry) {
    tableBody.insertAdjacentHTML('afterbegin', tableRowHtml(entry));
    while (tableBody.children.length > MAX_TABLE_ROWS) {
      tableBody.removeChild(tableBody.lastChild);
    }
  }

  function rebuildTable() {
    const filtered = logStore.filter(matchesFilter).slice(-MAX_TABLE_ROWS).reverse();
    tableBody.innerHTML = filtered.map(tableRowHtml).join('');
    emptyNote.hidden = filtered.length !== 0;
    tableHint.textContent = filtered.length + ' of ' + logStore.length + ' entries';
  }

  /* ---------- Stats ---------- */

  function renderStats() {
    statTotalEl.textContent = stats.total.toLocaleString('en-US');
    statCriticalEl.textContent = stats.critical.toLocaleString('en-US');
    statBlockedEl.textContent = stats.blocked.toLocaleString('en-US');
    statConnectionsEl.textContent = Math.round(activeConnections).toLocaleString('en-US');
  }

  window.setInterval(function () {
    activeConnections = randomWalk(activeConnections, 20, 90, 8);
    statConnectionsEl.textContent = Math.round(activeConnections).toLocaleString('en-US');
  }, 2500);

  /* ---------- Log ingestion ---------- */

  function ingestLog() {
    const entry = buildLogEntry();
    logStore.push(entry);
    if (logStore.length > MAX_STORE) logStore.shift();

    stats.total += 1;
    if (entry.severity === 'critical') stats.critical += 1;
    if (entry.status === 'Blocked') stats.blocked += 1;
    renderStats();

    if (matchesFilter(entry)) {
      appendTerminalLine(entry);
      prependTableRow(entry);
      tableHint.textContent = logStore.filter(matchesFilter).length + ' of ' + logStore.length + ' entries';
      emptyNote.hidden = true;
    }
  }

  function startStream() {
    genInterval = window.setInterval(ingestLog, 1400);
  }

  // seed with initial entries
  for (let i = 0; i < 14; i++) {
    const entry = buildLogEntry();
    entry.time = new Date(Date.now() - (14 - i) * 4000);
    logStore.push(entry);
    stats.total += 1;
    if (entry.severity === 'critical') stats.critical += 1;
    if (entry.status === 'Blocked') stats.blocked += 1;
  }
  renderStats();
  rebuildTerminal();
  rebuildTable();
  startStream();

  /* ---------- Search + filter ---------- */

  searchInput.addEventListener('input', function () {
    searchTerm = searchInput.value.trim().toLowerCase();
    rebuildTerminal();
    rebuildTable();
  });

  filterChips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      filterChips.forEach(function (c) { c.classList.remove('is-active'); });
      chip.classList.add('is-active');
      activeLevel = chip.getAttribute('data-level');
      rebuildTerminal();
      rebuildTable();
    });
  });

  /* ---------- Pause / Resume ---------- */

  const pauseBtn = document.getElementById('pause-btn');
  const pauseBtnLabel = document.getElementById('pause-btn-label');
  const iconPause = pauseBtn.querySelector('.icon-pause');
  const iconResume = pauseBtn.querySelector('.icon-resume');
  const livePill = document.getElementById('live-status-pill');
  const livePulseDot = document.getElementById('live-pulse-dot');
  const liveStatusLabel = document.getElementById('live-status-label');

  pauseBtn.addEventListener('click', function () {
    isPaused = !isPaused;

    if (isPaused) {
      window.clearInterval(genInterval);
      pauseBtn.classList.add('is-paused');
      pauseBtnLabel.textContent = 'Resume Logs';
      iconPause.style.display = 'none';
      iconResume.style.display = 'block';
      livePill.classList.remove('status-pill--ok');
      livePill.classList.add('status-pill--paused');
      livePulseDot.classList.add('is-paused');
      liveStatusLabel.textContent = 'Paused';
    } else {
      startStream();
      pauseBtn.classList.remove('is-paused');
      pauseBtnLabel.textContent = 'Pause Logs';
      iconPause.style.display = 'block';
      iconResume.style.display = 'none';
      livePill.classList.remove('status-pill--paused');
      livePill.classList.add('status-pill--ok');
      livePulseDot.classList.remove('is-paused');
      liveStatusLabel.textContent = 'Streaming';
    }
  });

  /* ---------- Clear Logs ---------- */

  document.getElementById('clear-btn').addEventListener('click', function () {
    logStore = [];
    stats = { total: 0, critical: 0, blocked: 0 };
    renderStats();
    terminal.innerHTML = '';
    tableBody.innerHTML = '';
    emptyNote.hidden = false;
    tableHint.textContent = '0 of 0 entries';
    showToolbarStatus('Logs cleared.');
  });

  /* ---------- Export Logs (CSV) ---------- */

  document.getElementById('export-btn').addEventListener('click', function () {
    const rows = logStore.filter(matchesFilter);
    const header = ['Timestamp', 'Source IP', 'Destination IP', 'Event Type', 'Severity', 'Status', 'Message'];
    const lines = [header.join(',')];

    rows.forEach(function (entry) {
      lines.push([
        formatTime(entry.time), entry.sourceIp, entry.destIp,
        '"' + entry.eventType + '"', entry.severity, entry.status, '"' + entry.msg + '"'
      ].join(','));
    });

    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinelai-x-live-logs.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToolbarStatus('Exported ' + rows.length + ' log entries.');
  });

  /* ---------- Toolbar status message ---------- */

  const toolbarStatus = document.getElementById('toolbar-status');
  let statusTimer = null;

  function showToolbarStatus(message) {
    toolbarStatus.textContent = message;
    toolbarStatus.classList.add('is-visible');
    window.clearTimeout(statusTimer);
    statusTimer = window.setTimeout(function () {
      toolbarStatus.classList.remove('is-visible');
    }, 2600);
  }

  /* ---------- Simulated packet activity ticker ---------- */

  const packetBars = document.getElementById('packet-bars');
  const packetRateEl = document.getElementById('packet-rate');
  const barEls = [];

  for (let i = 0; i < 12; i++) {
    const span = document.createElement('span');
    packetBars.appendChild(span);
    barEls.push(span);
  }

  let packetRate = 620;

  function renderPacketTicker() {
    packetRate = Math.round(randomWalk(packetRate, 200, 1400, 260));
    packetRateEl.textContent = packetRate.toLocaleString('en-US') + ' pkt/s';

    barEls.forEach(function (bar) {
      bar.style.height = randInt(20, 100) + '%';
    });
  }

  renderPacketTicker();
  window.setInterval(renderPacketTicker, 900);

})();