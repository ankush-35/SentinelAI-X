/* =====================================================
   SentinelAI-X — Login logic
   Vanilla JS: validation, password toggle, submit flow
===================================================== */

(function () {
  'use strict';

  const form = document.getElementById('login-form');
  const agentField = document.getElementById('field-agent');
  const agentInput = document.getElementById('agent-id');
  const passwordField = document.getElementById('field-password');
  const passwordInput = document.getElementById('password');
  const toggleBtn = document.getElementById('toggle-password');
  const eyeIcon = toggleBtn.querySelector('.icon-eye');
  const eyeOffIcon = toggleBtn.querySelector('.icon-eye-off');
  const loginBtn = document.getElementById('login-btn');
  const formStatus = document.getElementById('form-status');

  /* ---------- Password visibility toggle ---------- */

  toggleBtn.addEventListener('click', function () {
    const isHidden = passwordInput.type === 'password';

    passwordInput.type = isHidden ? 'text' : 'password';
    toggleBtn.setAttribute('aria-pressed', String(isHidden));
    toggleBtn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');

    eyeIcon.style.display = isHidden ? 'none' : 'block';
    eyeOffIcon.style.display = isHidden ? 'block' : 'none';
  });

  /* ---------- Field-level validation helpers ---------- */

  function setError(fieldEl, hasError) {
    fieldEl.classList.toggle('has-error', hasError);
  }

  function clearErrorOnInput(inputEl, fieldEl) {
    inputEl.addEventListener('input', function () {
      if (fieldEl.classList.contains('has-error') && inputEl.value.trim() !== '') {
        setError(fieldEl, false);
      }
    });
  }

  clearErrorOnInput(agentInput, agentField);
  clearErrorOnInput(passwordInput, passwordField);

  function validateForm() {
    let isValid = true;

    if (agentInput.value.trim() === '') {
      setError(agentField, true);
      isValid = false;
    } else {
      setError(agentField, false);
    }

    if (passwordInput.value.trim() === '') {
      setError(passwordField, true);
      isValid = false;
    } else {
      setError(passwordField, false);
    }

    return isValid;
  }

  /* ---------- Submit handling ---------- */

  function setLoading(isLoading) {
    loginBtn.classList.toggle('is-loading', isLoading);
    loginBtn.disabled = isLoading;
    agentInput.disabled = isLoading;
    passwordInput.disabled = isLoading;
  }

  function showStatus(message, isSuccess) {
    formStatus.textContent = message;
    formStatus.classList.toggle('is-success', Boolean(isSuccess));
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault(); // prevent page reload

    showStatus('');

    const isValid = validateForm();

    if (!isValid) { 
      showStatus('Please fill in all required fields.', false);

      const firstInvalid = form.querySelector('.has-error input');
      if (firstInvalid) firstInvalid.focus();

      return;
    }

    // Simulate authentication request
    setLoading(true);

    window.setTimeout(function () {
      showStatus('Access granted. Redirecting…', true);

      window.setTimeout(function () {
        window.location.href = 'dashboard.html';
      }, 500);x
    }, 1100);
  });

})();