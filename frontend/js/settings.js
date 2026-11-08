/* =====================================================
   SentinelAI-X — Settings logic
   Vanilla JS: tabs, form controls, save/reset,
   confirmation dialogs, dynamic module/service tables
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

  /* ---------- Toast notifications ---------- */

  const toastStack = document.getElementById('toast-stack');

  function showToast(message, kind) {
    const toast = document.createElement('div');
    toast.className = 'toast' + (kind ? ' toast--' + kind : '');
    toast.innerHTML =
      '<span class="toast__body"><p class="toast__title">' + message + '</p></span>' +
      '<button type="button" class="toast__close" aria-label="Dismiss">' +
        '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.9"><line x1="5" y1="5" x2="19" y2="19"/><line x1="19" y1="5" x2="5" y2="19"/></svg>' +
      '</button>';

    function dismiss() {
      toast.classList.add('is-leaving');
      window.setTimeout(function () { toast.remove(); }, 240);
    }

    toast.querySelector('.toast__close').addEventListener('click', dismiss);
    toastStack.appendChild(toast);
    window.setTimeout(dismiss, 4000);

    while (toastStack.children.length > 3) toastStack.removeChild(toastStack.firstChild);
  }

  /* ---------- Confirm dialog ---------- */

  const confirmBackdrop = document.getElementById('confirm-modal-backdrop');
  const confirmText = document.getElementById('confirm-modal-text');
  const confirmClose = document.getElementById('confirm-modal-close');
  const confirmCancel = document.getElementById('confirm-modal-cancel');
  const confirmConfirm = document.getElementById('confirm-modal-confirm');

  let pendingAction = null;

  function askConfirm(message, onConfirm) {
    confirmText.textContent = message;
    pendingAction = onConfirm;
    confirmBackdrop.hidden = false;
    confirmConfirm.focus();
    document.addEventListener('keydown', onConfirmKeydown);
  }

  function closeConfirm() {
    confirmBackdrop.hidden = true;
    pendingAction = null;
    document.removeEventListener('keydown', onConfirmKeydown);
  }

  function onConfirmKeydown(e) {
    if (e.key === 'Escape') closeConfirm();
  }

  confirmClose.addEventListener('click', closeConfirm);
  confirmCancel.addEventListener('click', closeConfirm);
  confirmBackdrop.addEventListener('click', function (e) {
    if (e.target === confirmBackdrop) closeConfirm();
  });

  confirmConfirm.addEventListener('click', function () {
    const action = pendingAction;
    closeConfirm();
    if (action) action();
  });

  /* ---------- Tabs ---------- */

  const tabs = document.querySelectorAll('.settings-tab');
  const panels = document.querySelectorAll('.settings-panel');

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      tabs.forEach(function (t) { t.classList.remove('is-active'); });
      panels.forEach(function (p) { p.classList.remove('is-active'); });

      tab.classList.add('is-active');
      const target = document.querySelector('.settings-panel[data-panel="' + tab.getAttribute('data-tab') + '"]');
      if (target) target.classList.add('is-active');

      tab.scrollIntoView({ block: 'nearest', inline: 'center', behavior: 'smooth' });
    });
  });

  /* ---------- Pill groups (radio-style) ---------- */

  document.querySelectorAll('.pill-group').forEach(function (group) {
    group.addEventListener('click', function (e) {
      const btn = e.target.closest('.pill');
      if (!btn) return;
      group.querySelectorAll('.pill').forEach(function (p) { p.classList.remove('is-active'); });
      btn.classList.add('is-active');

      if (group.id === 'sensitivity-group') {
        const customRow = document.getElementById('sensitivity-custom-row');
        customRow.hidden = btn.getAttribute('data-value') !== 'custom';
      }
    });
  });

  /* ---------- Sliders ---------- */

  function wireSlider(inputId, valueId, suffix) {
    const input = document.getElementById(inputId);
    const value = document.getElementById(valueId);
    if (!input || !value) return;
    input.addEventListener('input', function () {
      value.textContent = input.value + (suffix || '');
    });
  }

  wireSlider('sensitivity-slider', 'sensitivity-slider-value', '%');
  wireSlider('ai-confidence', 'ai-confidence-value', '%');
  wireSlider('worker-threads', 'worker-threads-value', '');

  /* ---------- Module manager ---------- */

  const modules = [
    { name: 'Packet Sniffer', desc: 'Captures raw traffic from monitored interfaces', enabled: true },
    { name: 'Signature Engine', desc: 'Matches traffic against the threat signature database', enabled: true },
    { name: 'AI Classifier', desc: 'Machine-learning based anomaly detection', enabled: true },
    { name: 'Report Generator', desc: 'Builds scheduled and on-demand PDF/CSV reports', enabled: true },
    { name: 'Notification Service', desc: 'Dispatches alerts to configured channels', enabled: false }
  ];

  const moduleList = document.getElementById('module-list');

  modules.forEach(function (mod, i) {
    const row = document.createElement('div');
    row.className = 'module-row';
    row.innerHTML =
      '<span class="module-row__name"><span>' + mod.name + '</span><span>' + mod.desc + '</span></span>' +
      '<label class="switch"><input type="checkbox" id="module-toggle-' + i + '" ' + (mod.enabled ? 'checked' : '') + '><span class="switch__track"><span class="switch__thumb"></span></span></label>';
    moduleList.appendChild(row);
  });

  /* ---------- Service status table ---------- */

  const services = [
    { name: 'sentinel-core', status: 'running', cpu: '3.2%', mem: '412 MB' },
    { name: 'sentinel-capture', status: 'running', cpu: '8.7%', mem: '260 MB' },
    { name: 'sentinel-api', status: 'running', cpu: '1.4%', mem: '188 MB' },
    { name: 'sentinel-scheduler', status: 'running', cpu: '0.6%', mem: '94 MB' },
    { name: 'sentinel-notify', status: 'stopped', cpu: '0.0%', mem: '0 MB' }
  ];

  const serviceTableBody = document.getElementById('service-table-body');

  services.forEach(function (svc) {
    const tr = document.createElement('tr');
    const dotClass = svc.status === 'running' ? 'dot--ok' : 'dot--warn';
    const label = svc.status.charAt(0).toUpperCase() + svc.status.slice(1);
    tr.innerHTML =
      '<td class="mono" data-label="Service">' + svc.name + '</td>' +
      '<td data-label="Status"><span class="dot ' + dotClass + '"></span> ' + label + '</td>' +
      '<td class="mono" data-label="CPU">' + svc.cpu + '</td>' +
      '<td class="mono" data-label="Memory">' + svc.mem + '</td>';
    serviceTableBody.appendChild(tr);
  });

  /* ---------- User permissions table ---------- */

  const roles = [
    { name: 'Admin', view: true, edit: true, del: true },
    { name: 'Analyst', view: true, edit: true, del: false },
    { name: 'Viewer', view: true, edit: false, del: false }
  ];

  const permissionsBody = document.getElementById('permissions-table-body');

  roles.forEach(function (role, i) {
    const tr = document.createElement('tr');
    function cell(label, checked, disabled) {
      return '<td data-label="' + label + '"><label class="switch"><input type="checkbox" ' + (checked ? 'checked' : '') + (disabled ? ' disabled' : '') + '><span class="switch__track"><span class="switch__thumb"></span></span></label></td>';
    }
    tr.innerHTML =
      '<td data-label="Role">' + role.name + '</td>' +
      cell('View', role.view, role.name === 'Admin') +
      cell('Edit', role.edit, role.name === 'Admin') +
      cell('Delete', role.del, role.name === 'Admin');
    permissionsBody.appendChild(tr);
  });

  /* ---------- Signature update check ---------- */

  document.getElementById('check-signatures-btn').addEventListener('click', function (e) {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'Checking…';
    window.setTimeout(function () {
      document.getElementById('signature-last-updated').textContent = 'Last synced just now · 48,206 signatures loaded';
      btn.disabled = false;
      btn.textContent = 'Check for Updates';
      showToast('Signature database is up to date.', 'success');
    }, 1000);
  });

  /* ---------- Platform update check ---------- */

  document.getElementById('check-platform-update-btn').addEventListener('click', function (e) {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'Checking…';
    window.setTimeout(function () {
      btn.disabled = false;
      btn.textContent = 'Check Now';
      showToast('SentinelAI-X Core v2.4.1 is the latest version.', 'success');
    }, 900);
  });

  /* ---------- Backup now ---------- */

  document.getElementById('backup-now-btn').addEventListener('click', function (e) {
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = 'Backing up…';
    window.setTimeout(function () {
      document.getElementById('last-backup-note').textContent = 'Just now · 4.0 GB';
      btn.disabled = false;
      btn.textContent = 'Backup Now';
      showToast('Database backup completed successfully.', 'success');
    }, 1200);
  });

  /* ---------- Export logs (both buttons on this page) ---------- */

  function exportLogsCsv() {
    const header = ['Timestamp', 'Level', 'Message'];
    const lines = [header.join(',')];
    const now = new Date();
    for (let i = 0; i < 20; i++) {
      const t = new Date(now.getTime() - i * 60000);
      lines.push([t.toISOString(), 'INFO', '"Placeholder log entry ' + (i + 1) + '"'].join(','));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentinelai-x-logs-export.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('Log export downloaded.', 'success');
  }

  document.getElementById('export-logs-btn').addEventListener('click', exportLogsCsv);
  document.getElementById('export-logs-btn-2').addEventListener('click', exportLogsCsv);

  /* ---------- Import data ---------- */

  document.getElementById('import-data-input').addEventListener('change', function (e) {
    if (e.target.files && e.target.files.length > 0) {
      showToast('Imported "' + e.target.files[0].name + '" successfully.', 'success');
      e.target.value = '';
    }
  });

  /* ---------- Clear database (dangerous) ---------- */

  document.getElementById('clear-db-btn').addEventListener('click', function () {
    askConfirm('This will permanently delete all stored alerts, logs, and threat history. This action cannot be undone.', function () {
      showToast('Database cleared.', 'danger');
    });
  });

  /* ---------- Update password ---------- */

  document.getElementById('update-password-btn').addEventListener('click', function () {
    const current = document.getElementById('password-current');
    const next = document.getElementById('password-new');
    if (!current.value || !next.value) {
      showToast('Enter both your current and new password.', 'danger');
      return;
    }
    current.value = '';
    next.value = '';
    showToast('Password updated successfully.', 'success');
  });

  /* ---------- Clear cache ---------- */

  document.getElementById('clear-cache-btn').addEventListener('click', function () {
    showToast('Cache cleared (612 MB freed).', 'success');
  });

  /* ---------- Run diagnostics ---------- */

  document.getElementById('run-diagnostics-btn').addEventListener('click', function (e) {
    const btn = e.currentTarget;
    const resultPanel = document.getElementById('diagnostics-result');

    btn.disabled = true;
    btn.textContent = 'Running…';
    resultPanel.hidden = true;
    resultPanel.innerHTML = '';

    window.setTimeout(function () {
      const checks = [
        { label: 'CPU', ok: true },
        { label: 'Memory', ok: true },
        { label: 'Disk I/O', ok: true },
        { label: 'Network Connectivity', ok: true },
        { label: 'Database Connection', ok: true }
      ];

      checks.forEach(function (c, i) {
        const row = document.createElement('div');
        row.className = 'diagnostics-result__row';
        row.style.animationDelay = (i * 80) + 'ms';
        row.innerHTML =
          '<span>' + c.label + '</span>' +
          '<span class="mono" style="color:' + (c.ok ? 'var(--success)' : 'var(--danger)') + '">' + (c.ok ? 'PASS' : 'FAIL') + '</span>';
        resultPanel.appendChild(row);
      });

      resultPanel.hidden = false;
      btn.disabled = false;
      btn.textContent = 'Run Diagnostics';
      showToast('Diagnostics complete — all systems nominal.', 'success');
    }, 1100);
  });

  /* ---------- Reset configuration (dangerous) ---------- */

  document.getElementById('reset-config-btn').addEventListener('click', function () {
    askConfirm('This will restore every setting on this page to its factory default value.', function () {
      resetAllToDefaults();
      showToast('Configuration reset to factory defaults.', 'danger');
    });
  });

  /* ---------- Save / Reset bar ---------- */

  const saveBarStatus = document.getElementById('save-bar-status');
  let statusTimer = null;

  function flashStatus(message) {
    saveBarStatus.textContent = message;
    saveBarStatus.classList.add('is-visible');
    window.clearTimeout(statusTimer);
    statusTimer = window.setTimeout(function () {
      saveBarStatus.classList.remove('is-visible');
    }, 2600);
  }

  document.getElementById('save-settings-btn').addEventListener('click', function () {
    flashStatus('All changes saved.');
    showToast('Settings saved successfully.', 'success');
  });

  document.getElementById('reset-defaults-btn').addEventListener('click', function () {
    askConfirm('Reset every field on this page back to its default value?', function () {
      resetAllToDefaults();
      flashStatus('Settings reset to defaults.');
      showToast('Settings reset to defaults.', 'success');
    });
  });

  function resetAllToDefaults() {
    // text/select inputs with a data-default attribute
    document.querySelectorAll('input.text-input[data-default], select.select-input[data-default]').forEach(function (el) {
      el.value = el.getAttribute('data-default');
    });

    // sliders
    document.querySelectorAll('input.slider[data-default]').forEach(function (el) {
      el.value = el.getAttribute('data-default');
      el.dispatchEvent(new Event('input'));
    });

    // toggles
    document.querySelectorAll('.switch input[type="checkbox"][data-default]').forEach(function (el) {
      el.checked = el.getAttribute('data-default') === 'true';
    });

    // pill groups
    document.querySelectorAll('.pill-group[data-default]').forEach(function (group) {
      const def = group.getAttribute('data-default');
      group.querySelectorAll('.pill').forEach(function (p) {
        p.classList.toggle('is-active', p.getAttribute('data-value') === def);
      });
      if (group.id === 'sensitivity-group') {
        document.getElementById('sensitivity-custom-row').hidden = def !== 'custom';
      }
    });
  }

})();