/* =====================================================
   SentinelAI-X — Dashboard logic
   Vanilla JS: simulated live metrics, no backend calls
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
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');
    clockTime.textContent = hh + ':' + mm + ':' + ss;

    const dateOpts = { weekday: 'short', month: 'short', day: 'numeric' };
    clockDate.textContent = now.toLocaleDateString('en-US', dateOpts);
  }

  updateClock();
  window.setInterval(updateClock, 1000);

  /* ---------- Threat summary: count-up animation ---------- */

  document.querySelectorAll('.stat-box__value').forEach(function (el) {
    const target = parseInt(el.getAttribute('data-count'), 10) || 0;
    const duration = 700;
    const start = performance.now();

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 2);
      el.textContent = Math.round(eased * target);
      if (progress < 1) window.requestAnimationFrame(tick);
    }

    window.requestAnimationFrame(tick);
  });

  /* ---------- CPU / RAM simulated gauges ---------- */

  const cpuFill = document.getElementById('cpu-fill');
  const cpuValue = document.getElementById('cpu-value');
  const cpuMeta = document.getElementById('cpu-meta');
  const coreBars = document.getElementById('core-bars');

  const ramFill = document.getElementById('ram-fill');
  const ramValue = document.getElementById('ram-value');
  const ramMeta = document.getElementById('ram-meta');
  const ramFree = document.getElementById('ram-free');

  const RAM_TOTAL_GB = 16;

  let cpuPct = 24;
  let ramPct = 68;

  // build 8 core bars once
  const coreEls = [];
  for (let i = 0; i < 8; i++) {
    const span = document.createElement('span');
    coreBars.appendChild(span);
    coreEls.push(span);
  }

  function clamp(val, min, max) {
    return Math.max(min, Math.min(max, val));
  }

  function randomWalk(value, min, max, step) {
    const delta = (Math.random() - 0.5) * step;
    return clamp(value + delta, min, max);
  }

  function renderCpuRam() {
    cpuFill.style.width = cpuPct.toFixed(0) + '%';
    cpuValue.textContent = cpuPct.toFixed(0) + '%';
    cpuMeta.textContent = (3.0 + (cpuPct / 100) * 1.2).toFixed(1) + ' GHz';

    coreEls.forEach(function (span) {
      const coreLoad = clamp(cpuPct + (Math.random() - 0.5) * 30, 4, 100);
      span.style.setProperty('--h', coreLoad.toFixed(0) + '%');
    });

    ramFill.style.width = ramPct.toFixed(0) + '%';
    ramValue.textContent = ramPct.toFixed(0) + '%';
    const usedGb = (RAM_TOTAL_GB * ramPct) / 100;
    ramMeta.textContent = usedGb.toFixed(1) + ' / ' + RAM_TOTAL_GB + ' GB';
    ramFree.textContent = (RAM_TOTAL_GB - usedGb).toFixed(1) + ' GB';
  }

  renderCpuRam();

  window.setInterval(function () {
    cpuPct = randomWalk(cpuPct, 12, 78, 14);
    ramPct = randomWalk(ramPct, 45, 85, 6);
    renderCpuRam();
  }, 2200);

  /* ---------- Packet capture counters ---------- */

  const packetsCapturedEl = document.getElementById('packets-captured');
  const packetsDroppedEl = document.getElementById('packets-dropped');
  const captureRateEl = document.getElementById('capture-rate');

  let packetsCaptured = 1284392;
  let packetsDropped = 47;

  function renderPackets() {
    packetsCapturedEl.textContent = packetsCaptured.toLocaleString('en-US');
    packetsDroppedEl.textContent = packetsDropped.toLocaleString('en-US');
    const rate = (18 + Math.random() * 14).toFixed(1);
    captureRateEl.textContent = rate + ' Mbps';
  }

  renderPackets();

  window.setInterval(function () {
    packetsCaptured += Math.floor(600 + Math.random() * 900);
    if (Math.random() < 0.3) packetsDropped += 1;
    renderPackets();
  }, 1500);

  /* ---------- Network interfaces ---------- */

  const interfaces = [
    { name: 'eth0', status: 'up', ip: '10.0.4.12/24', rx: '842 Mb/s', tx: '210 Mb/s' },
    { name: 'wlan0', status: 'up', ip: '10.0.4.31/24', rx: '112 Mb/s', tx: '48 Mb/s' },
    { name: 'tap0', status: 'idle', ip: '172.16.0.1/30', rx: '0 Mb/s', tx: '0 Mb/s' }
  ];

  const interfacesBody = document.getElementById('interfaces-body');

  interfaces.forEach(function (iface) {
    const tr = document.createElement('tr');

    const statusDotClass = iface.status === 'up' ? 'dot--ok' : 'dot--warn';
    const statusLabel = iface.status === 'up' ? 'Up' : 'Idle';

    tr.innerHTML =
      '<td class="mono">' + iface.name + '</td>' +
      '<td><span class="iface-status"><span class="dot ' + statusDotClass + '"></span>' + statusLabel + '</span></td>' +
      '<td class="mono dim">' + iface.ip + '</td>' +
      '<td class="mono">' + iface.rx + '</td>' +
      '<td class="mono">' + iface.tx + '</td>';

    interfacesBody.appendChild(tr);
  });

  /* ---------- Recent alerts ---------- */

  const alerts = [
    { level: 'critical', title: 'Possible port scan detected', source: '203.0.113.44', time: '2m ago' },
    { level: 'high', title: 'Repeated failed SSH auth attempts', source: '198.51.100.9', time: '11m ago' },
    { level: 'medium', title: 'Unusual outbound DNS volume', source: '10.0.4.18', time: '27m ago' },
    { level: 'high', title: 'Signature match: known C2 beacon pattern', source: '192.0.2.77', time: '48m ago' },
    { level: 'medium', title: 'New device joined the network', source: '10.0.4.52', time: '1h ago' }
  ];

  const alertList = document.getElementById('alert-list');

  alerts.forEach(function (alert) {
    const li = document.createElement('li');
    li.className = 'alert-item';
    li.innerHTML =
      '<span class="alert-item__badge alert-item__badge--' + alert.level + '"></span>' +
      '<span class="alert-item__body">' +
        '<p class="alert-item__title">' + alert.title + '</p>' +
        '<span class="alert-item__meta"><span>' + alert.source + '</span><span>' + alert.time + '</span></span>' +
      '</span>';
    alertList.appendChild(li);
  });

  /* ---------- Live log stream (simulated) ---------- */

  const logTerminal = document.getElementById('log-terminal');
  const MAX_LOG_LINES = 60;

  const logTemplates = [
    { level: 'info', tag: 'NET', text: 'Flow established 10.0.4.{n} -> 93.184.216.34:443 (TLS 1.3)' },
    { level: 'info', tag: 'IDS', text: 'Signature check passed for 812 packets on eth0' },
    { level: 'ok', tag: 'AUTH', text: 'Agent AGT-004{n} authenticated from 10.0.4.{n}' },
    { level: 'warn', tag: 'IDS', text: 'Anomalous packet size distribution on wlan0' },
    { level: 'warn', tag: 'NET', text: 'Retransmission rate elevated on eth0 (3.{n}%)' },
    { level: 'danger', tag: 'IDS', text: 'Signature match: SYN scan pattern from 203.0.113.{n}' },
    { level: 'danger', tag: 'AUTH', text: 'Failed authentication attempt from 198.51.100.{n}' },
    { level: 'info', tag: 'SYS', text: 'Threat intelligence feed synced (14{n} indicators)' },
    { level: 'ok', tag: 'SYS', text: 'Sensor node SN-0{n} heartbeat received' }
  ];

  function formatLogTime() {
    const now = new Date();
    return String(now.getHours()).padStart(2, '0') + ':' +
           String(now.getMinutes()).padStart(2, '0') + ':' +
           String(now.getSeconds()).padStart(2, '0');
  }

  function appendLogLine() {
    const template = logTemplates[Math.floor(Math.random() * logTemplates.length)];
    const n = Math.floor(Math.random() * 90) + 10;
    const text = template.text.replace(/\{n\}/g, n);

    const line = document.createElement('div');
    line.className = 'terminal__line level-' + template.level;
    line.innerHTML =
      '<span class="t-time">[' + formatLogTime() + ']</span> ' +
      '<span class="t-tag">' + template.tag + '</span> ' +
      text;

    logTerminal.appendChild(line);

    while (logTerminal.children.length > MAX_LOG_LINES) {
      logTerminal.removeChild(logTerminal.firstChild);
    }

    logTerminal.scrollTop = logTerminal.scrollHeight;
  }

  // seed the terminal with a handful of lines on load
  for (let i = 0; i < 8; i++) appendLogLine();

  window.setInterval(appendLogLine, 1800);

})();