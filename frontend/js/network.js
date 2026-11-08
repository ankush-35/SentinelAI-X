/* =====================================================
   SentinelAI-X — Network logic
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

  /* ---------- Connected devices summary ---------- */

  const deviceCountEl = document.getElementById('device-count');
  const wiredCountEl = document.getElementById('wired-count');
  const wirelessCountEl = document.getElementById('wireless-count');
  const idleCountEl = document.getElementById('idle-count');

  function renderDeviceSummary() {
    const wired = 5;
    const wireless = 6;
    const idle = 2;
    const total = wired + wireless;

    deviceCountEl.textContent = total;
    wiredCountEl.textContent = wired;
    wirelessCountEl.textContent = wireless;
    idleCountEl.textContent = idle;
  }

  renderDeviceSummary();

  /* ---------- Upload / download speed ---------- */

  const uploadValueEl = document.getElementById('upload-value');
  const uploadFillEl = document.getElementById('upload-fill');
  const uploadPeakEl = document.getElementById('upload-peak');
  const downloadValueEl = document.getElementById('download-value');
  const downloadFillEl = document.getElementById('download-fill');
  const downloadPeakEl = document.getElementById('download-peak');

  let uploadMbps = 12.4;
  let downloadMbps = 84.6;
  let uploadPeak = uploadMbps;
  let downloadPeak = downloadMbps;
  const MAX_LINK_MBPS = 200;

  function renderSpeeds() {
    uploadMbps = randomWalk(uploadMbps, 3, 60, 10);
    downloadMbps = randomWalk(downloadMbps, 20, 180, 30);
    uploadPeak = Math.max(uploadPeak, uploadMbps);
    downloadPeak = Math.max(downloadPeak, downloadMbps);

    uploadValueEl.textContent = uploadMbps.toFixed(1);
    downloadValueEl.textContent = downloadMbps.toFixed(1);
    uploadFillEl.style.width = clamp((uploadMbps / MAX_LINK_MBPS) * 100, 2, 100).toFixed(0) + '%';
    downloadFillEl.style.width = clamp((downloadMbps / MAX_LINK_MBPS) * 100, 2, 100).toFixed(0) + '%';
    uploadPeakEl.textContent = 'Peak: ' + uploadPeak.toFixed(1) + ' Mbps';
    downloadPeakEl.textContent = 'Peak: ' + downloadPeak.toFixed(1) + ' Mbps';

    document.getElementById('eth0-throughput').textContent = downloadMbps.toFixed(0) + ' Mb/s';
    document.getElementById('wlan0-throughput').textContent = (downloadMbps * 0.18 + uploadMbps * 0.1).toFixed(0) + ' Mb/s';
  }

  renderSpeeds();
  window.setInterval(renderSpeeds, 2000);

  /* ---------- Network health ---------- */

  const healthPill = document.getElementById('health-pill');
  const healthLatency = document.getElementById('health-latency');
  const healthLoss = document.getElementById('health-loss');
  const healthJitter = document.getElementById('health-jitter');

  let latency = 12;
  let loss = 0;
  let jitter = 1.2;

  function renderHealth() {
    latency = Math.round(randomWalk(latency, 6, 40, 8));
    loss = clamp(randomWalk(loss, 0, 1.5, 0.4), 0, 3);
    jitter = clamp(randomWalk(jitter, 0.4, 4, 1), 0, 6);

    healthLatency.textContent = latency + ' ms';
    healthLoss.textContent = loss.toFixed(1) + '%';
    healthJitter.textContent = jitter.toFixed(1) + ' ms';

    let label = 'Excellent';
    healthPill.classList.remove('status-pill--ok');
    if (latency > 30 || loss > 1) {
      label = 'Degraded';
    } else {
      healthPill.classList.add('status-pill--ok');
    }
    healthPill.textContent = label;
  }

  renderHealth();
  window.setInterval(renderHealth, 3000);

  /* ---------- Packet statistics ---------- */

  const pktSentEl = document.getElementById('pkt-sent');
  const pktReceivedEl = document.getElementById('pkt-received');
  const pktErrorsEl = document.getElementById('pkt-errors');
  const pktDroppedEl = document.getElementById('pkt-dropped');

  function renderPackets() {
    pktSentEl.textContent = Math.round(18000 + Math.random() * 6000).toLocaleString('en-US');
    pktReceivedEl.textContent = Math.round(24000 + Math.random() * 8000).toLocaleString('en-US');
    pktErrorsEl.textContent = Math.round(Math.random() * 12);
    pktDroppedEl.textContent = Math.round(Math.random() * 5);
  }

  renderPackets();
  window.setInterval(renderPackets, 2000);

  /* ---------- Bandwidth usage chart (24 points) ---------- */

  const bandwidthChart = document.getElementById('bandwidth-chart');
  const bwDown = [40, 35, 30, 28, 25, 32, 48, 70, 95, 110, 105, 120, 130, 125, 115, 128, 145, 160, 140, 108, 84, 68, 52, 44];
  const bwUp = [8, 6, 5, 5, 4, 6, 10, 14, 20, 24, 22, 26, 28, 27, 24, 26, 30, 34, 29, 22, 17, 13, 10, 9];
  const maxBw = Math.max.apply(null, bwDown.map(function (v, i) { return v + bwUp[i]; }));

  function renderBandwidth() {
    bandwidthChart.innerHTML = '';

    bwDown.forEach(function (downVal, i) {
      const upVal = bwUp[i];
      const bar = document.createElement('div');
      bar.className = 'bw-bar';

      const hourLabel = i % 4 === 0 ? (i === 0 ? '12a' : i === 12 ? '12p' : (i > 12 ? i - 12 : i) + (i > 12 ? 'p' : 'a')) : '';

      bar.innerHTML =
        '<div class="bw-bar__stack" title="Down: ' + downVal + ' Mbps · Up: ' + upVal + ' Mbps">' +
          '<div class="bw-bar__seg bw-bar__seg--up"></div>' +
          '<div class="bw-bar__seg bw-bar__seg--down"></div>' +
        '</div>' +
        '<span class="bw-bar__label">' + hourLabel + '</span>';

      bandwidthChart.appendChild(bar);

      const segDown = bar.querySelector('.bw-bar__seg--down');
      const segUp = bar.querySelector('.bw-bar__seg--up');

      window.setTimeout(function () {
        window.requestAnimationFrame(function () {
          segDown.style.height = Math.max(3, (downVal / maxBw) * 100).toFixed(0) + '%';
          segUp.style.height = Math.max(2, (upVal / maxBw) * 100).toFixed(0) + '%';
        });
      }, i * 16);
    });
  }

  renderBandwidth();

  /* ---------- Device table ---------- */

  const devices = [
    { name: 'Laptop-07 (Ankush)', ip: '10.0.4.22', mac: '3C:A6:F6:1B:4D:02', status: 'online', traffic: 842 },
    { name: 'Desktop-12', ip: '10.0.4.18', mac: 'A4:83:E7:2C:9F:11', status: 'online', traffic: 1204 },
    { name: 'SRV-DB01', ip: '10.0.4.10', mac: '00:1B:44:9A:2C:5E', status: 'online', traffic: 3120 },
    { name: 'NAS-01', ip: '10.0.4.15', mac: '9C:B6:D0:12:8A:4F', status: 'idle', traffic: 96 },
    { name: 'Cam-Lobby', ip: '10.0.4.41', mac: 'D8:3A:DD:66:C1:20', status: 'online', traffic: 214 },
    { name: 'Phone-Ankush', ip: '10.0.4.52', mac: 'F0:18:98:AB:34:77', status: 'online', traffic: 58 },
    { name: 'Tablet-Guest', ip: '10.0.4.63', mac: '7C:2E:BD:45:11:9A', status: 'idle', traffic: 12 },
    { name: 'Printer-02', ip: '10.0.4.70', mac: '68:9C:E2:00:5D:33', status: 'offline', traffic: 0 }
  ];

  const deviceTableBody = document.getElementById('device-table-body');
  const deviceTableHint = document.getElementById('device-table-hint');

  function statusDotClass(status) {
    if (status === 'online') return 'dot--ok';
    if (status === 'idle') return 'dot--warn';
    return 'dot--danger';
  }

  function renderDeviceTable() {
    deviceTableBody.innerHTML = '';

    devices.forEach(function (dev) {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td data-label="Device Name">' + dev.name + '</td>' +
        '<td class="mono" data-label="IP Address">' + dev.ip + '</td>' +
        '<td class="mono dim" data-label="MAC Address">' + dev.mac + '</td>' +
        '<td data-label="Status"><span class="iface-status"><span class="dot ' + statusDotClass(dev.status) + '"></span>' + dev.status.charAt(0).toUpperCase() + dev.status.slice(1) + '</span></td>' +
        '<td class="mono" data-label="Traffic">' + dev.traffic.toLocaleString('en-US') + ' MB</td>';
      deviceTableBody.appendChild(tr);
    });

    deviceTableHint.textContent = devices.length + ' devices';
  }

  renderDeviceTable();

  window.setInterval(function () {
    devices.forEach(function (dev) {
      if (dev.status !== 'offline') {
        dev.traffic += Math.round(Math.random() * 6);
      }
    });
    renderDeviceTable();
  }, 4000);

})();