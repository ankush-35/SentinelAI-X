/* =====================================================
   SentinelAI-X — Threat Summary logic
   Vanilla JS: simulated data, client-side search/filter
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
    clockDate.textContent = now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
  }

  updateClock();
  window.setInterval(updateClock, 1000);

  /* ---------- Stat card count-up ---------- */

  document.querySelectorAll('.stat-card__value').forEach(function (el) {
    const target = parseInt(el.getAttribute('data-count'), 10) || 0;
    const duration = 750;
    const start = performance.now();

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 2);
      el.textContent = Math.round(eased * target).toLocaleString('en-US');
      if (progress < 1) window.requestAnimationFrame(tick);
    }

    window.requestAnimationFrame(tick);
  });

  /* ---------- Threat categories ---------- */

  const categories = [
    { name: 'DDoS', count: 412, color: 'var(--danger)' },
    { name: 'Phishing', count: 587, color: 'var(--blue-focus)' },
    { name: 'Port Scan', count: 356, color: 'var(--blue-select)' },
    { name: 'Brute Force', count: 289, color: 'var(--warning)' },
    { name: 'Malware', count: 198, color: '#D97A7A' }
  ];

  const categoryList = document.getElementById('category-list');
  const maxCategory = Math.max.apply(null, categories.map(function (c) { return c.count; }));

  categories.forEach(function (cat) {
    const li = document.createElement('li');
    li.className = 'category-row';
    li.innerHTML =
      '<div class="category-row__top">' +
        '<span class="category-row__name"><span class="dot" style="background:' + cat.color + '"></span>' + cat.name + '</span>' +
        '<span class="category-row__count mono">' + cat.count.toLocaleString('en-US') + '</span>' +
      '</div>' +
      '<div class="category-row__track"><div class="category-row__fill" style="background:' + cat.color + '"></div></div>';
    categoryList.appendChild(li);

    const fill = li.querySelector('.category-row__fill');
    window.requestAnimationFrame(function () {
      fill.style.width = ((cat.count / maxCategory) * 100).toFixed(0) + '%';
    });
  });

  /* ---------- Severity distribution donut ---------- */

  const severity = [
    { key: 'critical', label: 'Critical', value: 34, color: '#A33030' },
    { key: 'high', label: 'High', value: 211, color: '#C58A00' },
    { key: 'medium', label: 'Medium', value: 640, color: '#2E8BFF' },
    { key: 'low', label: 'Low', value: 957, color: '#2D8C45' }
  ];

  const total = severity.reduce(function (sum, s) { return sum + s.value; }, 0);
  const donut = document.getElementById('donut-chart');
  const donutTotal = document.getElementById('donut-total');
  const legend = document.getElementById('severity-legend');

  const R = 48;
  const CIRC = 2 * Math.PI * R;
  let cumulative = 0;

  severity.forEach(function (seg) {
    const fraction = seg.value / total;
    const len = fraction * CIRC;

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', '60');
    circle.setAttribute('cy', '60');
    circle.setAttribute('r', String(R));
    circle.setAttribute('class', 'donut-seg');
    circle.style.stroke = seg.color;
    circle.setAttribute('stroke-dasharray', '0 ' + CIRC);
    circle.setAttribute('stroke-dashoffset', String(-cumulative));
    donut.appendChild(circle);

    window.requestAnimationFrame(function () {
      circle.setAttribute('stroke-dasharray', len.toFixed(1) + ' ' + (CIRC - len).toFixed(1));
    });

    cumulative += len;

    const li = document.createElement('li');
    li.innerHTML =
      '<span class="dot" style="background:' + seg.color + '"></span>' +
      seg.label +
      '<span class="mono">' + seg.value.toLocaleString('en-US') + '</span>';
    legend.appendChild(li);
  });

  let donutCount = 0;
  const donutStart = performance.now();
  function tickDonutTotal(now) {
    const progress = Math.min((now - donutStart) / 750, 1);
    donutCount = Math.round(progress * total);
    donutTotal.textContent = donutCount.toLocaleString('en-US');
    if (progress < 1) window.requestAnimationFrame(tickDonutTotal);
  }
  window.requestAnimationFrame(tickDonutTotal);

  /* ---------- Recent security events ---------- */

  const events = [
    { level: 'critical', title: 'Multi-vector DDoS attack mitigated', source: '203.0.113.44', time: '2m ago' },
    { level: 'high', title: 'Brute-force SSH attempt blocked', source: '198.51.100.9', time: '11m ago' },
    { level: 'medium', title: 'Unusual outbound traffic flagged', source: '10.0.4.18', time: '27m ago' },
    { level: 'high', title: 'Malware signature detected in payload', source: '192.0.2.77', time: '48m ago' },
    { level: 'low', title: 'New device fingerprint recorded', source: '10.0.4.52', time: '1h ago' },
    { level: 'critical', title: 'Phishing domain communication blocked', source: '203.0.113.19', time: '1h 40m ago' }
  ];

  const eventList = document.getElementById('event-list');
  const eventIcon = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9L2.9 17a2 2 0 001.7 3h14.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>';

  events.forEach(function (ev) {
    const li = document.createElement('li');
    li.className = 'event-item';
    li.innerHTML =
      '<span class="event-item__icon event-item__icon--' + ev.level + '">' + eventIcon + '</span>' +
      '<span class="event-item__body">' +
        '<p class="event-item__title">' + ev.title + '</p>' +
        '<span class="event-item__meta"><span class="mono">' + ev.source + '</span><span>' + ev.time + '</span></span>' +
      '</span>';
    eventList.appendChild(li);
  });

  /* ---------- Threat timeline (24h) ---------- */

  const timelineChart = document.getElementById('timeline-chart');
  const hourlyData = [
    12, 8, 6, 5, 4, 6, 14, 26, 38, 44, 41, 47,
    52, 49, 45, 50, 58, 63, 55, 42, 33, 27, 19, 15
  ];
  const maxHourly = Math.max.apply(null, hourlyData);

  hourlyData.forEach(function (value, i) {
    const bar = document.createElement('div');
    bar.className = 'timeline-bar';

    const hourLabel = i % 3 === 0 ? (i === 0 ? '12a' : i === 12 ? '12p' : (i > 12 ? i - 12 : i) + (i > 12 ? 'p' : 'a')) : '';

    bar.innerHTML =
      '<div class="timeline-bar__col" title="' + value + ' events"></div>' +
      '<span class="timeline-bar__label">' + hourLabel + '</span>';

    timelineChart.appendChild(bar);

    const col = bar.querySelector('.timeline-bar__col');
    window.requestAnimationFrame(function () {
      col.style.height = Math.max(4, (value / maxHourly) * 100).toFixed(0) + '%';
    });
  });

  /* ---------- Top attacking IPs ---------- */

  const ipData = [
    { ip: '203.0.113.44', level: 'critical', count: 342, lastSeen: '2 minutes ago' },
    { ip: '203.0.113.19', level: 'critical', count: 298, lastSeen: '34 minutes ago' },
    { ip: '198.51.100.9', level: 'high', count: 210, lastSeen: '11 minutes ago' },
    { ip: '192.0.2.77', level: 'high', count: 187, lastSeen: '26 minutes ago' },
    { ip: '198.51.100.63', level: 'high', count: 145, lastSeen: '3 hours ago' },
    { ip: '198.51.100.201', level: 'medium', count: 94, lastSeen: '52 minutes ago' },
    { ip: '192.0.2.153', level: 'medium', count: 76, lastSeen: '1 hour ago' },
    { ip: '203.0.113.132', level: 'medium', count: 61, lastSeen: '6 hours ago' },
    { ip: '203.0.113.88', level: 'low', count: 22, lastSeen: '2 hours ago' },
    { ip: '192.0.2.41', level: 'low', count: 18, lastSeen: '5 hours ago' }
  ];

  const ipTableBody = document.getElementById('ip-table-body');
  const ipEmptyNote = document.getElementById('ip-empty-note');
  const ipCountHint = document.getElementById('ip-count-hint');
  const searchInput = document.getElementById('ip-search');
  const filterChips = document.querySelectorAll('.chip');

  let activeLevel = 'all';
  let searchTerm = '';

  function renderIpTable() {
    const filtered = ipData.filter(function (row) {
      const matchesLevel = activeLevel === 'all' || row.level === activeLevel;
      const matchesSearch = searchTerm === '' || row.ip.toLowerCase().indexOf(searchTerm) !== -1;
      return matchesLevel && matchesSearch;
    });

    ipTableBody.innerHTML = '';

    filtered.forEach(function (row) {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="mono">' + row.ip + '</td>' +
        '<td><span class="level-badge level-badge--' + row.level + '">' + row.level + '</span></td>' +
        '<td class="mono">' + row.count.toLocaleString('en-US') + '</td>' +
        '<td class="mono dim">' + row.lastSeen + '</td>';
      ipTableBody.appendChild(tr);
    });

    ipEmptyNote.hidden = filtered.length !== 0;
    ipCountHint.textContent = filtered.length + ' of ' + ipData.length + ' entries';
  }

  searchInput.addEventListener('input', function () {
    searchTerm = searchInput.value.trim().toLowerCase();
    renderIpTable();
  });

  filterChips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      filterChips.forEach(function (c) { c.classList.remove('is-active'); });
      chip.classList.add('is-active');
      activeLevel = chip.getAttribute('data-level');
      renderIpTable();
    });
  });

  renderIpTable();

})();