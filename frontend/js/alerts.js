/* =====================================================
   SentinelAI-X — Alerts logic
   Vanilla JS: simulated alert stream, search/filter,
   detail modal, resolve/ignore, CSV/PDF export, toasts
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

  function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

  function internalIp() { return '10.0.4.' + randInt(2, 90); }

  function externalIp() {
    const pools = ['203.0.113.', '198.51.100.', '192.0.2.'];
    return pools[randInt(0, pools.length - 1)] + randInt(2, 250);
  }

  function formatTime(date) {
    return String(date.getHours()).padStart(2, '0') + ':' +
           String(date.getMinutes()).padStart(2, '0') + ':' +
           String(date.getSeconds()).padStart(2, '0');
  }

  function relativeTime(date) {
    const diffMs = Date.now() - date.getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    return Math.floor(hrs / 24) + 'd ago';
  }

  let alertCounter = 10430;
  function nextAlertId() {
    alertCounter += 1;
    return 'ALT-' + alertCounter;
  }

  /* ---------- Alert templates ---------- */

  const templates = [
    { severity: 'critical', threatType: 'DDoS Attack', description: 'Sustained volumetric flood detected against the primary gateway, consistent with a multi-vector DDoS attempt.', mitigation: 'Enable upstream rate limiting and activate the scrubbing profile for the affected interface.' },
    { severity: 'critical', threatType: 'Malware Signature Match', description: 'Inbound payload matched a known remote-access-trojan signature during deep packet inspection.', mitigation: 'Quarantine the destination host immediately and run a full endpoint scan.' },
    { severity: 'critical', threatType: 'Brute Force Attempt', description: 'Repeated failed authentication attempts detected against an exposed SSH service within a short window.', mitigation: 'Temporarily block the source IP and enforce account lockout after 5 failed attempts.' },
    { severity: 'high', threatType: 'Port Scan Detected', description: 'Sequential SYN packets observed across multiple ports, indicating reconnaissance activity.', mitigation: 'Add the source IP to the watchlist and monitor for follow-up connection attempts.' },
    { severity: 'high', threatType: 'C2 Beacon Traffic', description: 'Periodic outbound connections matched a known command-and-control communication pattern.', mitigation: 'Isolate the affected host from the network and inspect running processes.' },
    { severity: 'high', threatType: 'Credential Stuffing', description: 'High-volume login attempts using previously leaked credential pairs were detected.', mitigation: 'Force a password reset for affected accounts and enable multi-factor authentication.' },
    { severity: 'medium', threatType: 'Unusual Traffic Pattern', description: 'Outbound traffic volume from an internal host deviated significantly from its baseline.', mitigation: 'Review the host\'s recent process activity and confirm it matches expected behavior.' },
    { severity: 'medium', threatType: 'DNS Tunneling', description: 'DNS query patterns suggest possible data exfiltration via encoded subdomains.', mitigation: 'Inspect DNS logs for the host and restrict outbound DNS to approved resolvers.' },
    { severity: 'medium', threatType: 'Rate Limit Exceeded', description: 'A client exceeded the configured request threshold on a public-facing endpoint.', mitigation: 'Apply temporary throttling and confirm the client is not a misconfigured integration.' },
    { severity: 'low', threatType: 'New Device Joined', description: 'A previously unseen device connected to the network and was assigned a DHCP lease.', mitigation: 'Confirm the device is authorized; add it to inventory if legitimate.' },
    { severity: 'low', threatType: 'Session Anomaly', description: 'A session lasted longer than the expected range for its service type.', mitigation: 'No action required unless the pattern repeats across multiple sessions.' }
  ];

  function buildAlert() {
    const t = templates[randInt(0, templates.length - 1)];
    const isInbound = t.severity === 'critical' || t.severity === 'high';

    return {
      id: nextAlertId(),
      threatType: t.threatType,
      severity: t.severity,
      sourceIp: isInbound ? externalIp() : internalIp(),
      destIp: internalIp(),
      status: 'active',
      time: new Date(),
      description: t.description,
      mitigation: t.mitigation,
      riskScore: t.severity === 'critical' ? randInt(85, 99) :
                 t.severity === 'high' ? randInt(60, 84) :
                 t.severity === 'medium' ? randInt(35, 59) : randInt(5, 34)
    };
  }

  /* ---------- State ---------- */

  let alerts = [];
  let activeFilter = 'all';
  let searchTerm = '';

  const MAX_ALERTS = 120;
  const MAX_TABLE_ROWS = 40;
  const MAX_ACTIVITY_ITEMS = 8;

  /* ---------- DOM refs ---------- */

  const tableBody = document.getElementById('alerts-table-body');
  const emptyNote = document.getElementById('alerts-empty-note');
  const countHint = document.getElementById('alerts-count-hint');
  const searchInput = document.getElementById('alert-search');
  const filterChips = document.querySelectorAll('.chip');
  const sidebarAlertBadge = document.getElementById('sidebar-alert-badge');

  const statTotalEl = document.getElementById('stat-total-value');
  const statCriticalEl = document.getElementById('stat-critical-value');
  const statHighEl = document.getElementById('stat-high-value');
  const statResolvedEl = document.getElementById('stat-resolved-value');

  /* ---------- Matching ---------- */

  function matchesFilter(alert) {
    let matchesChip;
    if (activeFilter === 'all') matchesChip = true;
    else if (activeFilter === 'resolved') matchesChip = alert.status === 'resolved';
    else matchesChip = alert.severity === activeFilter;

    const term = searchTerm;
    const matchesSearch = term === '' ||
      alert.id.toLowerCase().indexOf(term) !== -1 ||
      alert.sourceIp.indexOf(term) !== -1 ||
      alert.destIp.indexOf(term) !== -1 ||
      alert.threatType.toLowerCase().indexOf(term) !== -1;

    return matchesChip && matchesSearch;
  }

  /* ---------- Stats ---------- */

  function renderStats() {
    const total = alerts.length;
    const critical = alerts.filter(function (a) { return a.severity === 'critical'; }).length;
    const high = alerts.filter(function (a) { return a.severity === 'high'; }).length;
    const resolved = alerts.filter(function (a) { return a.status === 'resolved'; }).length;
    const activeCount = alerts.filter(function (a) { return a.status === 'active'; }).length;

    statTotalEl.textContent = total.toLocaleString('en-US');
    statCriticalEl.textContent = critical.toLocaleString('en-US');
    statHighEl.textContent = high.toLocaleString('en-US');
    statResolvedEl.textContent = resolved.toLocaleString('en-US');
    sidebarAlertBadge.textContent = activeCount;
  }

  /* ---------- Severity donut ---------- */

  const donut = document.getElementById('donut-chart');
  const donutTotal = document.getElementById('donut-total');
  const legend = document.getElementById('severity-legend');
  const R = 48;
  const CIRC = 2 * Math.PI * R;

  const severityMeta = [
    { key: 'critical', label: 'Critical', color: '#A33030' },
    { key: 'high', label: 'High', color: '#C58A00' },
    { key: 'medium', label: 'Medium', color: '#2E8BFF' },
    { key: 'low', label: 'Low', color: '#2D8C45' }
  ];

  function renderDonut() {
    donut.querySelectorAll('.donut-seg').forEach(function (el) { el.remove(); });
    legend.innerHTML = '';

    const counts = severityMeta.map(function (s) {
      return { meta: s, value: alerts.filter(function (a) { return a.severity === s.key; }).length };
    });

    const total = counts.reduce(function (sum, c) { return sum + c.value; }, 0) || 1;
    let cumulative = 0;

    counts.forEach(function (c) {
      const fraction = c.value / total;
      const len = fraction * CIRC;

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '60');
      circle.setAttribute('cy', '60');
      circle.setAttribute('r', String(R));
      circle.setAttribute('class', 'donut-seg');
      circle.style.stroke = c.meta.color;
      circle.setAttribute('stroke-dasharray', '0 ' + CIRC);
      circle.setAttribute('stroke-dashoffset', String(-cumulative));
      donut.appendChild(circle);

      window.requestAnimationFrame(function () {
        circle.setAttribute('stroke-dasharray', len.toFixed(1) + ' ' + (CIRC - len).toFixed(1));
      });

      cumulative += len;

      const li = document.createElement('li');
      li.innerHTML =
        '<span class="dot" style="background:' + c.meta.color + '"></span>' +
        c.meta.label +
        '<span class="mono">' + c.value.toLocaleString('en-US') + '</span>';
      legend.appendChild(li);
    });

    donutTotal.textContent = alerts.length.toLocaleString('en-US');
  }

  /* ---------- Recent activity ---------- */

  const activityList = document.getElementById('activity-list');
  const activityIcon = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9L2.9 17a2 2 0 001.7 3h14.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>';

  function renderActivity() {
    activityList.innerHTML = '';
    const recent = alerts.slice(-MAX_ACTIVITY_ITEMS).reverse();

    recent.forEach(function (alert) {
      const li = document.createElement('li');
      li.className = 'event-item';
      const statusNote = alert.status === 'resolved' ? 'Resolved' : alert.status === 'ignored' ? 'Ignored' : 'Detected';
      li.innerHTML =
        '<span class="event-item__icon event-item__icon--' + alert.severity + '">' + activityIcon + '</span>' +
        '<span class="event-item__body">' +
          '<p class="event-item__title">' + statusNote + ' — ' + alert.threatType + '</p>' +
          '<span class="event-item__meta"><span class="mono">' + alert.sourceIp + '</span><span>' + relativeTime(alert.time) + '</span></span>' +
        '</span>';
      activityList.appendChild(li);
    });
  }

  /* ---------- Table ---------- */

  function levelBadge(severity) {
    return '<span class="level-badge level-badge--' + severity + '">' + severity + '</span>';
  }

  function statusTag(status) {
    const dotClass = status === 'active' ? 'dot--danger' : status === 'resolved' ? 'dot--ok' : 'dot--warn';
    const label = status.charAt(0).toUpperCase() + status.slice(1);
    return '<span class="status-tag"><span class="dot ' + dotClass + '"></span>' + label + '</span>';
  }

  function tableRowHtml(alert) {
    return '<tr class="alert-row" tabindex="0" role="button" aria-label="View details for ' + alert.id + '" data-id="' + alert.id + '">' +
      '<td class="mono" data-label="Alert ID">' + alert.id + '</td>' +
      '<td data-label="Threat Type">' + alert.threatType + '</td>' +
      '<td class="mono" data-label="Source IP">' + alert.sourceIp + '</td>' +
      '<td class="mono dim" data-label="Destination IP">' + alert.destIp + '</td>' +
      '<td data-label="Severity">' + levelBadge(alert.severity) + '</td>' +
      '<td class="mono dim" data-label="Time">' + formatTime(alert.time) + '</td>' +
      '<td data-label="Status">' + statusTag(alert.status) + '</td>' +
      '<td data-label="Action"><button type="button" class="action-view-btn" data-id="' + alert.id + '">View</button></td>' +
    '</tr>';
  }

  function renderTable() {
    const filtered = alerts.filter(matchesFilter).slice(-MAX_TABLE_ROWS).reverse();
    tableBody.innerHTML = filtered.map(tableRowHtml).join('');
    emptyNote.hidden = filtered.length !== 0;
    countHint.textContent = filtered.length + ' of ' + alerts.length + ' entries';

    tableBody.querySelectorAll('.alert-row').forEach(function (row) {
      row.addEventListener('click', function (e) {
        if (e.target.closest('.action-view-btn')) return;
        openAlertModal(row.getAttribute('data-id'));
      });
      row.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openAlertModal(row.getAttribute('data-id')); }
      });
    });

    tableBody.querySelectorAll('.action-view-btn').forEach(function (btn) {
      btn.addEventListener('click', function () { openAlertModal(btn.getAttribute('data-id')); });
    });
  }

  function renderAll() {
    renderStats();
    renderDonut();
    renderActivity();
    renderTable();
  }

  /* ---------- Search + filter ---------- */

  searchInput.addEventListener('input', function () {
    searchTerm = searchInput.value.trim().toLowerCase();
    renderTable();
  });

  filterChips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      filterChips.forEach(function (c) { c.classList.remove('is-active'); });
      chip.classList.add('is-active');
      activeFilter = chip.getAttribute('data-filter');
      renderTable();
    });
  });

  /* ---------- Alert detail modal ---------- */

  const modalBackdrop = document.getElementById('alert-modal-backdrop');
  const modalMeta = document.getElementById('alert-modal-meta');
  const modalDescription = document.getElementById('alert-modal-description');
  const modalMitigation = document.getElementById('alert-modal-mitigation');
  const modalClose = document.getElementById('alert-modal-close');
  const modalResolveBtn = document.getElementById('modal-resolve-btn');
  const modalIgnoreBtn = document.getElementById('modal-ignore-btn');

  let activeAlertId = null;

  function findAlert(id) {
    return alerts.find(function (a) { return a.id === id; });
  }

  function openAlertModal(id) {
    const alert = findAlert(id);
    if (!alert) return;
    activeAlertId = id;

    modalMeta.innerHTML =
      '<li class="status-row"><span class="status-row__key">Alert ID</span><span class="status-row__val mono">' + alert.id + '</span></li>' +
      '<li class="status-row"><span class="status-row__key">Threat Type</span><span class="status-row__val">' + alert.threatType + '</span></li>' +
      '<li class="status-row"><span class="status-row__key">Attack Source</span><span class="status-row__val mono">' + alert.sourceIp + '</span></li>' +
      '<li class="status-row"><span class="status-row__key">Risk Score</span><span class="status-row__val">' + levelBadge(alert.severity) + '<span class="mono" style="margin-left:6px">' + alert.riskScore + ' / 100</span></span></li>' +
      '<li class="status-row"><span class="status-row__key">First Detected</span><span class="status-row__val mono dim">' + formatTime(alert.time) + ' &middot; ' + relativeTime(alert.time) + '</span></li>' +
      '<li class="status-row"><span class="status-row__key">Status</span><span class="status-row__val">' + statusTag(alert.status) + '</span></li>';

    modalDescription.textContent = alert.description;
    modalMitigation.textContent = alert.mitigation;

    const isResolved = alert.status !== 'active';
    modalResolveBtn.disabled = isResolved;
    modalIgnoreBtn.disabled = isResolved;

    modalBackdrop.hidden = false;
    modalClose.focus();
    document.addEventListener('keydown', onModalKeydown);
  }

  function closeAlertModal() {
    modalBackdrop.hidden = true;
    activeAlertId = null;
    document.removeEventListener('keydown', onModalKeydown);
  }

  function onModalKeydown(e) {
    if (e.key === 'Escape') closeAlertModal();
  }

  modalClose.addEventListener('click', closeAlertModal);
  modalBackdrop.addEventListener('click', function (e) {
    if (e.target === modalBackdrop) closeAlertModal();
  });

  modalResolveBtn.addEventListener('click', function () {
    const alert = findAlert(activeAlertId);
    if (!alert) return;
    alert.status = 'resolved';
    renderAll();
    closeAlertModal();
    showToast(null, 'Alert ' + alert.id + ' marked as resolved.');
  });

  modalIgnoreBtn.addEventListener('click', function () {
    const alert = findAlert(activeAlertId);
    if (!alert) return;
    alert.status = 'ignored';
    renderAll();
    closeAlertModal();
    showToast(null, 'Alert ' + alert.id + ' ignored.');
  });

  /* ---------- Toast notifications ---------- */

  const toastStack = document.getElementById('toast-stack');

  function showToast(alertOrNull, plainMessage) {
    const toast = document.createElement('div');

    if (alertOrNull) {
      toast.className = 'toast toast--' + alertOrNull.severity;
      toast.innerHTML =
        '<span class="toast__body">' +
          '<p class="toast__title">New ' + alertOrNull.severity + ' alert — ' + alertOrNull.threatType + '</p>' +
          '<span class="toast__meta">' + alertOrNull.sourceIp + ' &middot; ' + alertOrNull.id + '</span>' +
        '</span>' +
        '<button type="button" class="toast__close" aria-label="Dismiss">' +
          '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.9"><line x1="5" y1="5" x2="19" y2="19"/><line x1="19" y1="5" x2="5" y2="19"/></svg>' +
        '</button>';
    } else {
      toast.className = 'toast';
      toast.innerHTML =
        '<span class="toast__body"><p class="toast__title">' + plainMessage + '</p></span>' +
        '<button type="button" class="toast__close" aria-label="Dismiss">' +
          '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.9"><line x1="5" y1="5" x2="19" y2="19"/><line x1="19" y1="5" x2="5" y2="19"/></svg>' +
        '</button>';
    }

    function dismiss() {
      toast.classList.add('is-leaving');
      window.setTimeout(function () { toast.remove(); }, 240);
    }

    toast.querySelector('.toast__close').addEventListener('click', dismiss);
    toastStack.appendChild(toast);

    window.setTimeout(dismiss, 5000);

    while (toastStack.children.length > 3) {
      toastStack.removeChild(toastStack.firstChild);
    }
  }

  /* ---------- Export CSV ---------- */

  document.getElementById('export-csv-btn').addEventListener('click', function () {
    const rows = alerts.filter(matchesFilter);
    const header = ['Alert ID', 'Threat Type', 'Source IP', 'Destination IP', 'Severity', 'Time', 'Status', 'Risk Score'];
    const lines = [header.join(',')];

    rows.forEach(function (a) {
      lines.push([
        a.id, '"' + a.threatType + '"', a.sourceIp, a.destIp, a.severity, formatTime(a.time), a.status, a.riskScore
      ].join(','));
    });

    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinelai-x-alerts.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast(null, 'Exported ' + rows.length + ' alerts to CSV.');
  });

  /* ---------- Export PDF (browser print) ---------- */

  document.getElementById('export-pdf-btn').addEventListener('click', function () {
    window.print();
  });

  /* ---------- Seed + real-time stream ---------- */

  for (let i = 0; i < 22; i++) {
    const alert = buildAlert();
    alert.time = new Date(Date.now() - (22 - i) * 5 * 60000);
    if (Math.random() < 0.35) alert.status = 'resolved';
    alerts.push(alert);
  }

  renderAll();

  window.setInterval(function () {
    const alert = buildAlert();
    alerts.push(alert);
    if (alerts.length > MAX_ALERTS) alerts.shift();

    renderAll();

    if (alert.severity === 'critical' || alert.severity === 'high') {
      showToast(alert, null);
    }
  }, 9000);

})();