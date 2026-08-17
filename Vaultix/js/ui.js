/**
 * ui.js
 * Presentation helpers only: toasts, modal plumbing, formatting,
 * DOM escaping. Holds no application state and never touches
 * crypto.js or storage.js directly — app.js is the only caller.
 */
(function (global) {
  'use strict';

  const toastRegion = document.getElementById('toast-region');

  function toast(message, type) {
    const el = document.createElement('div');
    el.className = 'toast' + (type ? ' toast-' + type : '');
    el.setAttribute('role', 'status');
    el.innerHTML = '<span class="toast-dot" aria-hidden="true"></span><span></span>';
    el.querySelector('span:last-child').textContent = message;
    toastRegion.appendChild(el);

    setTimeout(function () {
      el.classList.add('toast-out');
      setTimeout(function () { el.remove(); }, 180);
    }, 2600);
  }

  let lastFocusedBeforeModal = null;

  function openModal(backdropEl) {
    lastFocusedBeforeModal = document.activeElement;
    backdropEl.classList.remove('hidden');
    const focusable = backdropEl.querySelector('input, select, textarea, button');
    if (focusable) focusable.focus();

    function onKeydown(e) {
      if (e.key === 'Escape') {
        closeModal(backdropEl);
      }
      if (e.key === 'Tab') {
        trapFocus(backdropEl, e);
      }
    }
    backdropEl._keydownHandler = onKeydown;
    document.addEventListener('keydown', onKeydown);
  }

  function closeModal(backdropEl) {
    backdropEl.classList.add('hidden');
    if (backdropEl._keydownHandler) {
      document.removeEventListener('keydown', backdropEl._keydownHandler);
      backdropEl._keydownHandler = null;
    }
    if (lastFocusedBeforeModal && typeof lastFocusedBeforeModal.focus === 'function') {
      lastFocusedBeforeModal.focus();
    }
  }

  function trapFocus(container, e) {
    const focusables = container.querySelectorAll(
      'input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled])'
    );
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];

    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  function escapeHTML(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function initialsFor(name) {
    if (!name) return '?';
    const trimmed = name.trim();
    return trimmed.charAt(0).toUpperCase();
  }

  function maskPassword(password) {
    if (!password) return '';
    const len = Math.min(password.length, 16);
    return '•'.repeat(Math.max(len, 8));
  }

  function formatDate(isoString) {
    if (!isoString) return '';
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function setStrengthMeter(meterEl, labelEl, password) {
    const result = global.PasswordGenerator.estimateStrength(password);
    meterEl.setAttribute('data-score', String(result.score));
    if (labelEl) labelEl.textContent = password ? result.label : 'At least 8 characters';
    return result;
  }

  global.VaultUI = {
    toast: toast,
    openModal: openModal,
    closeModal: closeModal,
    escapeHTML: escapeHTML,
    initialsFor: initialsFor,
    maskPassword: maskPassword,
    formatDate: formatDate,
    setStrengthMeter: setStrengthMeter,
  };
})(window);
