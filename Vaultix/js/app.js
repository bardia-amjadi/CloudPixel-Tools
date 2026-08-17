/**
 * app.js
 * The only module that holds application state. Orchestrates
 * VaultCrypto (encryption), VaultStorage (persistence), VaultUI
 * (presentation helpers) and PasswordGenerator. Decrypted entries
 * live only in memory here and are wiped on lock.
 */
(function () {
  'use strict';

  const CATEGORIES = ['Websites', 'Email', 'Social', 'Gaming', 'Work', 'Finance', 'Other'];

  // ---- In-memory state (cleared on lock) --------------------------------
  let vaultKey = null;       // CryptoKey, null when locked
  let vaultSalt = null;
  let vaultIterations = null;
  let entries = [];          // decrypted entries, [] when locked

  let currentView = 'all';   // 'all' | 'favorites' | 'categories' | 'settings'
  let categoryFilter = '';
  let searchQuery = '';
  let sortMode = 'updated-desc';
  let revealedIds = new Set();

  let editingEntryId = null;
  let confirmCallback = null;
  let settings = window.VaultStorage.loadSettings();

  let autoLockHandle = null;
  let activityListenersAttached = false;

  // ---- DOM references -----------------------------------------------------
  const $ = (id) => document.getElementById(id);

  const lockScreen = $('lock-screen');
  const appRoot = $('app');
  const unlockForm = $('unlock-form');
  const setupForm = $('setup-form');
  const unlockError = $('unlock-error');
  const setupError = $('setup-error');

  // =========================================================================
  // Init
  // =========================================================================
  function init() {
    applyTheme(settings.theme);
    wireStaticEvents();
    populateCategorySelects();

    if (window.VaultStorage.hasVault()) {
      unlockForm.classList.remove('hidden');
      setupForm.classList.add('hidden');
      $('unlock-password').focus();
    } else {
      unlockForm.classList.add('hidden');
      setupForm.classList.remove('hidden');
      $('setup-password').focus();
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme === 'dim' ? 'dim' : 'dark');
  }

  // =========================================================================
  // Setup / Unlock / Lock
  // =========================================================================
  async function handleSetupSubmit(e) {
    e.preventDefault();
    setupError.textContent = '';

    const password = $('setup-password').value;
    const confirm = $('setup-password-confirm').value;

    if (password.length < 8) {
      setupError.textContent = 'Password must be at least 8 characters.';
      return;
    }
    if (password !== confirm) {
      setupError.textContent = 'Passwords do not match.';
      return;
    }

    const submitBtn = setupForm.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-label').textContent = 'Creating vault…';

    try {
      const salt = window.VaultCrypto.generateSalt();
      const iterations = window.VaultCrypto.PBKDF2_ITERATIONS;
      const key = await window.VaultCrypto.deriveKey(password, salt, iterations);
      const payload = await window.VaultCrypto.encryptData(key, []);

      window.VaultStorage.saveVaultBlob({
        salt: salt,
        iv: payload.iv,
        ciphertext: payload.ciphertext,
        iterations: iterations,
      });

      vaultKey = key;
      vaultSalt = salt;
      vaultIterations = iterations;
      entries = [];

      enterApp();
      window.VaultUI.toast('Vault created. Welcome to Vault.', 'success');
    } catch (err) {
      setupError.textContent = 'Something went wrong creating your vault. Please try again.';
    } finally {
      submitBtn.disabled = false;
      submitBtn.querySelector('.btn-label').textContent = 'Create vault';
    }
  }

  async function handleUnlockSubmit(e) {
    e.preventDefault();
    unlockError.textContent = '';

    const password = $('unlock-password').value;
    const blob = window.VaultStorage.loadVaultBlob();

    if (!blob) {
      unlockError.textContent = 'No vault found on this device.';
      return;
    }

    const submitBtn = $('unlock-submit');
    submitBtn.disabled = true;
    submitBtn.querySelector('.btn-label').textContent = 'Unlocking…';

    try {
      const key = await window.VaultCrypto.deriveKey(password, blob.salt, blob.iterations);
      const decrypted = await window.VaultCrypto.decryptData(key, {
        iv: blob.iv,
        ciphertext: blob.ciphertext,
      });

      vaultKey = key;
      vaultSalt = blob.salt;
      vaultIterations = blob.iterations;
      entries = Array.isArray(decrypted) ? decrypted : [];

      $('unlock-password').value = '';
      enterApp();
    } catch (err) {
      unlockError.textContent = 'Incorrect master password.';
    } finally {
      submitBtn.disabled = false;
      submitBtn.querySelector('.btn-label').textContent = 'Unlock vault';
    }
  }

  function enterApp() {
    lockScreen.classList.add('hidden');
    appRoot.classList.remove('hidden');
    switchView('all');
    renderAll();
    resetAutoLockTimer();
    attachActivityListeners();
  }

  function lockVault(options) {
    const silent = options && options.silent;

    vaultKey = null;
    vaultSalt = null;
    vaultIterations = null;
    entries = [];
    revealedIds = new Set();
    editingEntryId = null;

    if (autoLockHandle) {
      clearTimeout(autoLockHandle);
      autoLockHandle = null;
    }

    appRoot.classList.add('hidden');
    lockScreen.classList.remove('hidden');

    $('unlock-password').value = '';
    unlockError.textContent = '';

    if (window.VaultStorage.hasVault()) {
      unlockForm.classList.remove('hidden');
      setupForm.classList.add('hidden');
      setTimeout(function () { $('unlock-password').focus(); }, 50);
    } else {
      unlockForm.classList.add('hidden');
      setupForm.classList.remove('hidden');
    }

    if (!silent) window.VaultUI.toast('Vault locked.');
  }

  // ---- Auto-lock ------------------------------------------------------------
  function resetAutoLockTimer() {
    if (autoLockHandle) clearTimeout(autoLockHandle);
    if (!vaultKey) return;
    const minutes = Number(settings.autoLockMinutes) || 0;
    if (minutes <= 0) return;
    autoLockHandle = setTimeout(function () {
      lockVault();
      window.VaultUI.toast('Locked after inactivity.');
    }, minutes * 60 * 1000);
  }

  function attachActivityListeners() {
    if (activityListenersAttached) return;
    activityListenersAttached = true;
    const events = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'];
    let throttleHandle = null;
    events.forEach(function (evt) {
      window.addEventListener(evt, function () {
        if (!vaultKey) return;
        if (throttleHandle) return;
        throttleHandle = setTimeout(function () { throttleHandle = null; }, 1000);
        resetAutoLockTimer();
      }, { passive: true });
    });
  }

  // =========================================================================
  // Persistence
  // =========================================================================
  async function persistVault() {
    const payload = await window.VaultCrypto.encryptData(vaultKey, entries);
    window.VaultStorage.saveVaultBlob({
      salt: vaultSalt,
      iv: payload.iv,
      ciphertext: payload.ciphertext,
      iterations: vaultIterations,
    });
  }

  // =========================================================================
  // View switching / rendering
  // =========================================================================
  function switchView(view) {
    currentView = view;

    document.querySelectorAll('.nav-item[data-view]').forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-view') === view);
    });
    document.querySelectorAll('.bottom-nav-item[data-view]').forEach(function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-view') === view);
    });

    $('view-list').classList.toggle('hidden', view !== 'all' && view !== 'favorites');
    $('view-categories').classList.toggle('hidden', view !== 'categories');
    $('view-settings').classList.toggle('hidden', view !== 'settings');

    $('view-title').textContent = view === 'favorites' ? 'Favorites' : 'All Passwords';

    if (view === 'categories') renderCategoryGrid();
    if (view === 'all' || view === 'favorites') renderEntryList();
  }

  function renderAll() {
    $('count-all').textContent = String(entries.length);
    $('count-favorites').textContent = String(entries.filter((e) => e.favorite).length);

    if (currentView === 'all' || currentView === 'favorites') renderEntryList();
    if (currentView === 'categories') renderCategoryGrid();
  }

  function getFilteredSortedEntries() {
    let list = entries.slice();

    if (currentView === 'favorites') {
      list = list.filter((e) => e.favorite);
    }
    if (categoryFilter) {
      list = list.filter((e) => e.category === categoryFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      list = list.filter(function (e) {
        return (
          (e.name || '').toLowerCase().includes(q) ||
          (e.url || '').toLowerCase().includes(q) ||
          (e.username || '').toLowerCase().includes(q) ||
          (e.category || '').toLowerCase().includes(q) ||
          (e.notes || '').toLowerCase().includes(q)
        );
      });
    }

    list.sort(function (a, b) {
      switch (sortMode) {
        case 'name-asc': return (a.name || '').localeCompare(b.name || '');
        case 'name-desc': return (b.name || '').localeCompare(a.name || '');
        case 'created-desc': return new Date(b.createdAt) - new Date(a.createdAt);
        case 'created-asc': return new Date(a.createdAt) - new Date(b.createdAt);
        case 'updated-desc':
        default: return new Date(b.updatedAt) - new Date(a.updatedAt);
      }
    });

    return list;
  }

  function renderEntryList() {
    const list = getFilteredSortedEntries();
    const container = $('entry-list');
    const emptyState = $('empty-state');
    const noResultsState = $('no-results-state');

    const hasAnyInScope = currentView === 'favorites'
      ? entries.some((e) => e.favorite)
      : entries.length > 0;
    const isFiltering = !!(searchQuery.trim() || categoryFilter);

    if (!hasAnyInScope && !isFiltering) {
      container.innerHTML = '';
      container.classList.add('hidden');
      noResultsState.classList.add('hidden');
      emptyState.classList.remove('hidden');
      $('empty-title').textContent = currentView === 'favorites' ? 'No favorites yet' : 'Your vault is empty';
      $('empty-body').textContent = currentView === 'favorites'
        ? 'Star a password to see it here.'
        : 'Add your first password to get started.';
      $('empty-add-btn').classList.toggle('hidden', currentView === 'favorites');
      return;
    }

    if (list.length === 0) {
      container.innerHTML = '';
      container.classList.add('hidden');
      emptyState.classList.add('hidden');
      noResultsState.classList.remove('hidden');
      return;
    }

    emptyState.classList.add('hidden');
    noResultsState.classList.add('hidden');
    container.classList.remove('hidden');
    container.innerHTML = list.map(renderEntryCardHTML).join('');
  }

  function renderEntryCardHTML(entry) {
    const ui = window.VaultUI;
    const revealed = revealedIds.has(entry.id);
    const passwordDisplay = revealed
      ? ui.escapeHTML(entry.password || '')
      : ui.maskPassword(entry.password || '');

    return (
      '<div class="entry-card" role="listitem" data-id="' + entry.id + '">' +
        '<div class="entry-badge" aria-hidden="true">' + ui.escapeHTML(ui.initialsFor(entry.name)) + '</div>' +
        '<div class="entry-main">' +
          '<div class="entry-name">' +
            (entry.favorite ? '<svg class="fav-star" viewBox="0 0 24 24"><path d="M12 17.3 6.2 21l1.6-6.6L2.5 9.9l6.8-.6L12 3l2.7 6.3 6.8.6-5.3 4.5 1.6 6.6z"/></svg>' : '') +
            '<span>' + ui.escapeHTML(entry.name || 'Untitled') + '</span>' +
          '</div>' +
          '<div class="entry-sub">' + ui.escapeHTML(entry.url || 'No URL') + '</div>' +
        '</div>' +
        '<div class="entry-username" title="' + ui.escapeHTML(entry.username || '') + '">' + ui.escapeHTML(entry.username || '—') + '</div>' +
        '<div class="entry-password-cell">' +
          '<span class="entry-password-mask">' + (entry.password ? passwordDisplay : '—') + '</span>' +
          (entry.password ? (
            '<button class="icon-btn" data-action="reveal" data-id="' + entry.id + '" aria-label="' + (revealed ? 'Hide password' : 'Show password') + '">' +
              (revealed
                ? '<svg viewBox="0 0 24 24"><path d="M3.3 4.7 4.7 3.3l16 16-1.4 1.4-2.9-2.9c-1.4.5-2.9.8-4.4.8-5 0-9.27-3.11-11-7 .8-1.8 2.1-3.35 3.7-4.5zM12 6a6 6 0 0 1 6 6c0 .8-.17 1.55-.47 2.24l-1.5-1.5A4 4 0 0 0 12 8a4 4 0 0 0-1.24.2L9.26 6.7A5.98 5.98 0 0 1 12 6z"/></svg>'
                : '<svg viewBox="0 0 24 24"><path d="M12 5c-5 0-9.27 3.11-11 7 1.73 3.89 6 7 11 7s9.27-3.11 11-7c-1.73-3.89-6-7-11-7zm0 12a5 5 0 1 1 0-10 5 5 0 0 1 0 10zm0-8a3 3 0 1 0 0 6 3 3 0 0 0 0-6z"/></svg>') +
            '</button>' +
            '<button class="icon-btn" data-action="copy" data-id="' + entry.id + '" aria-label="Copy password">' +
              '<svg viewBox="0 0 24 24"><path d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11z"/></svg>' +
            '</button>'
          ) : '') +
        '</div>' +
        '<div class="entry-actions">' +
          '<span class="category-tag">' + ui.escapeHTML(entry.category || 'Other') + '</span>' +
          '<button class="icon-btn" data-action="favorite" data-id="' + entry.id + '" aria-label="' + (entry.favorite ? 'Remove from favorites' : 'Add to favorites') + '">' +
            '<svg viewBox="0 0 24 24"><path d="M12 17.3 6.2 21l1.6-6.6L2.5 9.9l6.8-.6L12 3l2.7 6.3 6.8.6-5.3 4.5 1.6 6.6z"/></svg>' +
          '</button>' +
          '<button class="icon-btn" data-action="edit" data-id="' + entry.id + '" aria-label="Edit ' + ui.escapeHTML(entry.name || 'entry') + '">' +
            '<svg viewBox="0 0 24 24"><path d="M4 20h4l10-10-4-4L4 16zm14.7-14.7 1.3 1.3-2 2-1.3-1.3z"/></svg>' +
          '</button>' +
          '<button class="icon-btn" data-action="delete" data-id="' + entry.id + '" aria-label="Delete ' + ui.escapeHTML(entry.name || 'entry') + '">' +
            '<svg viewBox="0 0 24 24"><path d="M6 7h12l-1 14H7zM9 4h6l1 2H8zM4 7h16"/></svg>' +
          '</button>' +
        '</div>' +
      '</div>'
    );
  }

  function handleEntryListClick(e) {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const id = btn.getAttribute('data-id');
    const action = btn.getAttribute('data-action');
    const entry = entries.find((x) => x.id === id);
    if (!entry) return;

    if (action === 'reveal') {
      if (revealedIds.has(id)) revealedIds.delete(id); else revealedIds.add(id);
      renderEntryList();
    } else if (action === 'copy') {
      copyToClipboard(entry.password, 'Password copied to clipboard.');
    } else if (action === 'favorite') {
      entry.favorite = !entry.favorite;
      entry.updatedAt = new Date().toISOString();
      persistVault();
      renderAll();
    } else if (action === 'edit') {
      openEntryModal(entry);
    } else if (action === 'delete') {
      openConfirmModal(
        'Delete password?',
        'This will permanently delete "' + entry.name + '" from your vault.',
        function () {
          entries = entries.filter((x) => x.id !== id);
          persistVault();
          renderAll();
          window.VaultUI.toast('Password deleted.');
        }
      );
    }
  }

  function copyToClipboard(text, message) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        window.VaultUI.toast(message, 'success');
      }).catch(function () {
        window.VaultUI.toast('Could not copy to clipboard.', 'error');
      });
    } else {
      window.VaultUI.toast('Clipboard is not available in this browser.', 'error');
    }
  }

  // ---- Categories view -----------------------------------------------------
  function renderCategoryGrid() {
    const grid = $('category-grid');
    grid.innerHTML = CATEGORIES.map(function (cat) {
      const count = entries.filter((e) => e.category === cat).length;
      return (
        '<button class="category-card" data-category="' + window.VaultUI.escapeHTML(cat) + '">' +
          '<div class="category-card-count">' + count + '</div>' +
          '<div class="category-card-label">' + window.VaultUI.escapeHTML(cat) + '</div>' +
        '</button>'
      );
    }).join('');
  }

  function handleCategoryGridClick(e) {
    const btn = e.target.closest('.category-card');
    if (!btn) return;
    const cat = btn.getAttribute('data-category');
    categoryFilter = cat;
    $('category-filter').value = cat;
    switchView('all');
  }

  function populateCategorySelects() {
    const filterSelect = $('category-filter');
    CATEGORIES.forEach(function (cat) {
      const opt = document.createElement('option');
      opt.value = cat;
      opt.textContent = cat;
      filterSelect.appendChild(opt);
    });
  }

  // =========================================================================
  // Entry form modal
  // =========================================================================
  function openEntryModal(entry) {
    editingEntryId = entry ? entry.id : null;
    $('entry-modal-title').textContent = entry ? 'Edit Password' : 'Add Password';
    $('entry-id').value = entry ? entry.id : '';
    $('entry-name').value = entry ? entry.name || '' : '';
    $('entry-url').value = entry ? entry.url || '' : '';
    $('entry-username').value = entry ? entry.username || '' : '';
    $('entry-category').value = entry ? entry.category || 'Websites' : 'Websites';
    $('entry-password').value = entry ? entry.password || '' : '';
    $('entry-notes').value = entry ? entry.notes || '' : '';
    $('entry-favorite').checked = entry ? !!entry.favorite : false;
    $('entry-password').setAttribute('type', 'password');
    $('entry-form').querySelector('.toggle-visibility').setAttribute('aria-label', 'Show password');

    window.VaultUI.setStrengthMeter($('entry-strength'), $('entry-strength-label'), $('entry-password').value);
    window.VaultUI.openModal($('entry-modal-backdrop'));
  }

  async function handleEntryFormSubmit(e) {
    e.preventDefault();
    const name = $('entry-name').value.trim();
    if (!name) {
      $('entry-name').focus();
      return;
    }

    const now = new Date().toISOString();

    if (editingEntryId) {
      const entry = entries.find((x) => x.id === editingEntryId);
      if (entry) {
        entry.name = name;
        entry.url = $('entry-url').value.trim();
        entry.username = $('entry-username').value.trim();
        entry.category = $('entry-category').value;
        entry.password = $('entry-password').value;
        entry.notes = $('entry-notes').value;
        entry.favorite = $('entry-favorite').checked;
        entry.updatedAt = now;
      }
    } else {
      entries.push({
        id: (crypto.randomUUID ? crypto.randomUUID() : 'id-' + Date.now() + '-' + Math.random().toString(16).slice(2)),
        name: name,
        url: $('entry-url').value.trim(),
        username: $('entry-username').value.trim(),
        password: $('entry-password').value,
        notes: $('entry-notes').value,
        category: $('entry-category').value,
        favorite: $('entry-favorite').checked,
        createdAt: now,
        updatedAt: now,
      });
    }

    await persistVault();
    window.VaultUI.closeModal($('entry-modal-backdrop'));
    renderAll();
    window.VaultUI.toast(editingEntryId ? 'Password updated.' : 'Password saved.', 'success');
    editingEntryId = null;
  }

  // =========================================================================
  // Password generator modal
  // =========================================================================
  function currentGeneratorOptions() {
    return {
      length: Number($('gen-length').value),
      uppercase: $('gen-uppercase').checked,
      lowercase: $('gen-lowercase').checked,
      numbers: $('gen-numbers').checked,
      symbols: $('gen-symbols').checked,
    };
  }

  function regenerate() {
    const pwd = window.PasswordGenerator.generate(currentGeneratorOptions());
    $('generated-password').textContent = pwd;
    window.VaultUI.setStrengthMeter($('generator-strength'), $('generator-strength-label'), pwd);
  }

  function openGeneratorModal() {
    $('gen-length-value').textContent = $('gen-length').value;
    regenerate();
    window.VaultUI.openModal($('generator-modal-backdrop'));
  }

  // =========================================================================
  // Change master password
  // =========================================================================
  async function handleChangePasswordSubmit(e) {
    e.preventDefault();
    const errorEl = $('change-password-error');
    errorEl.textContent = '';

    const current = $('current-password').value;
    const next = $('new-password').value;
    const confirm = $('new-password-confirm').value;

    if (next.length < 8) {
      errorEl.textContent = 'New password must be at least 8 characters.';
      return;
    }
    if (next !== confirm) {
      errorEl.textContent = 'New passwords do not match.';
      return;
    }

    try {
      // Re-verify the current password against the live vault key by
      // attempting a fresh derivation + decrypt of what's on disk.
      const blob = window.VaultStorage.loadVaultBlob();
      const checkKey = await window.VaultCrypto.deriveKey(current, blob.salt, blob.iterations);
      await window.VaultCrypto.decryptData(checkKey, { iv: blob.iv, ciphertext: blob.ciphertext });

      const newSalt = window.VaultCrypto.generateSalt();
      const newIterations = window.VaultCrypto.PBKDF2_ITERATIONS;
      const newKey = await window.VaultCrypto.deriveKey(next, newSalt, newIterations);
      const payload = await window.VaultCrypto.encryptData(newKey, entries);

      window.VaultStorage.saveVaultBlob({
        salt: newSalt,
        iv: payload.iv,
        ciphertext: payload.ciphertext,
        iterations: newIterations,
      });

      vaultKey = newKey;
      vaultSalt = newSalt;
      vaultIterations = newIterations;

      $('change-password-form').reset();
      window.VaultUI.closeModal($('change-password-modal-backdrop'));
      window.VaultUI.toast('Master password updated.', 'success');
    } catch (err) {
      errorEl.textContent = 'Current password is incorrect.';
    }
  }

  // =========================================================================
  // Confirm modal (generic)
  // =========================================================================
  function openConfirmModal(title, body, onConfirm) {
    $('confirm-modal-title').textContent = title;
    $('confirm-modal-body').textContent = body;
    confirmCallback = onConfirm;
    window.VaultUI.openModal($('confirm-modal-backdrop'));
  }

  // =========================================================================
  // Import / Export
  // =========================================================================
  function handleExport() {
    const blob = window.VaultStorage.loadVaultBlob();
    if (!blob) {
      window.VaultUI.toast('No vault to export.', 'error');
      return;
    }
    const json = JSON.stringify(blob, null, 2);
    const fileBlob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(fileBlob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = 'vault-export-' + stamp + '.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    window.VaultUI.toast('Vault exported.', 'success');
  }

  function handleImportFile(e) {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function () {
      let parsed;
      try {
        parsed = JSON.parse(reader.result);
      } catch (err) {
        window.VaultUI.toast('That file is not valid JSON.', 'error');
        return;
      }
      if (!window.VaultStorage.isValidVaultBlob(parsed)) {
        window.VaultUI.toast('That file is not a valid Vault export.', 'error');
        return;
      }

      openConfirmModal(
        'Replace current vault?',
        'Importing will overwrite the vault currently stored in this browser. This can\'t be undone.',
        function () {
          window.VaultStorage.saveVaultBlob(parsed);
          window.VaultUI.toast('Vault imported. Unlock it with its master password.', 'success');
          lockVault({ silent: true });
        }
      );
    };
    reader.readAsText(file);
  }

  // =========================================================================
  // Clear vault
  // =========================================================================
  function handleClearVault() {
    openConfirmModal(
      'Clear local vault?',
      'This permanently deletes all data stored in this browser. This can\'t be undone.',
      function () {
        window.VaultStorage.clearVault();
        lockVault({ silent: true });
        window.VaultUI.toast('Vault cleared from this device.');
      }
    );
  }

  // =========================================================================
  // Event wiring
  // =========================================================================
  function wireStaticEvents() {
    setupForm.addEventListener('submit', handleSetupSubmit);
    unlockForm.addEventListener('submit', handleUnlockSubmit);

    $('show-reset-vault').addEventListener('click', function () {
      openConfirmModal(
        'Reset this vault?',
        'If you\'ve forgotten your master password, the vault cannot be decrypted. You can clear it from this browser and start fresh, but all saved passwords will be lost.',
        function () {
          window.VaultStorage.clearVault();
          window.location.reload();
        }
      );
    });

    // Password visibility toggles (delegated — covers lock screen + modal)
    document.addEventListener('click', function (e) {
      const btn = e.target.closest('.toggle-visibility');
      if (!btn) return;
      const targetId = btn.getAttribute('data-target');
      const input = $(targetId);
      const showing = input.getAttribute('type') === 'text';
      input.setAttribute('type', showing ? 'password' : 'text');
      btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
    });

    // Strength meters live-update
    $('setup-password').addEventListener('input', function () {
      window.VaultUI.setStrengthMeter($('setup-strength'), $('setup-strength-label'), this.value);
    });
    $('entry-password').addEventListener('input', function () {
      window.VaultUI.setStrengthMeter($('entry-strength'), $('entry-strength-label'), this.value);
    });

    // Sidebar + bottom nav
    document.querySelectorAll('[data-view]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        switchView(btn.getAttribute('data-view'));
      });
    });
    $('bottom-search-btn').addEventListener('click', function () {
      switchView('all');
      $('search-input').focus();
    });

    $('lock-btn').addEventListener('click', function () { lockVault(); });
    $('lock-now-btn').addEventListener('click', function () { lockVault(); });

    // Search / filter / sort
    $('search-input').addEventListener('input', function () {
      searchQuery = this.value;
      renderEntryList();
    });
    $('category-filter').addEventListener('change', function () {
      categoryFilter = this.value;
      renderEntryList();
    });
    $('sort-select').addEventListener('change', function () {
      sortMode = this.value;
      renderEntryList();
    });

    // Entry list delegation
    $('entry-list').addEventListener('click', handleEntryListClick);
    $('category-grid').addEventListener('click', handleCategoryGridClick);

    // Add password entry points
    $('add-btn-top').addEventListener('click', function () { openEntryModal(null); });
    $('fab-add').addEventListener('click', function () { openEntryModal(null); });
    $('empty-add-btn').addEventListener('click', function () { openEntryModal(null); });

    // Entry modal
    $('entry-form').addEventListener('submit', handleEntryFormSubmit);
    $('entry-cancel-btn').addEventListener('click', function () { window.VaultUI.closeModal($('entry-modal-backdrop')); });
    $('entry-modal-close').addEventListener('click', function () { window.VaultUI.closeModal($('entry-modal-backdrop')); });
    $('entry-modal-backdrop').addEventListener('click', function (e) {
      if (e.target === this) window.VaultUI.closeModal(this);
    });

    // Generator modal
    $('open-generator-btn').addEventListener('click', openGeneratorModal);
    $('generator-cancel-btn').addEventListener('click', function () { window.VaultUI.closeModal($('generator-modal-backdrop')); });
    $('generator-modal-close').addEventListener('click', function () { window.VaultUI.closeModal($('generator-modal-backdrop')); });
    $('generator-modal-backdrop').addEventListener('click', function (e) {
      if (e.target === this) window.VaultUI.closeModal(this);
    });
    $('gen-length').addEventListener('input', function () {
      $('gen-length-value').textContent = this.value;
      regenerate();
    });
    ['gen-uppercase', 'gen-lowercase', 'gen-numbers', 'gen-symbols'].forEach(function (id) {
      $(id).addEventListener('change', regenerate);
    });
    $('regenerate-btn').addEventListener('click', regenerate);
    $('copy-generated-btn').addEventListener('click', function () {
      copyToClipboard($('generated-password').textContent, 'Generated password copied.');
    });
    $('use-generated-btn').addEventListener('click', function () {
      $('entry-password').value = $('generated-password').textContent;
      $('entry-password').setAttribute('type', 'text');
      window.VaultUI.setStrengthMeter($('entry-strength'), $('entry-strength-label'), $('entry-password').value);
      window.VaultUI.closeModal($('generator-modal-backdrop'));
    });

    // Settings
    $('theme-select').addEventListener('change', function () {
      settings.theme = this.value;
      window.VaultStorage.saveSettings(settings);
      applyTheme(settings.theme);
    });
    $('autolock-select').addEventListener('change', function () {
      settings.autoLockMinutes = Number(this.value);
      window.VaultStorage.saveSettings(settings);
      resetAutoLockTimer();
    });
    $('theme-select').value = settings.theme;
    $('autolock-select').value = String(settings.autoLockMinutes);

    $('change-password-btn').addEventListener('click', function () {
      $('change-password-form').reset();
      $('change-password-error').textContent = '';
      window.VaultUI.openModal($('change-password-modal-backdrop'));
    });
    $('change-password-form').addEventListener('submit', handleChangePasswordSubmit);
    $('change-password-cancel-btn').addEventListener('click', function () { window.VaultUI.closeModal($('change-password-modal-backdrop')); });
    $('change-password-modal-close').addEventListener('click', function () { window.VaultUI.closeModal($('change-password-modal-backdrop')); });

    $('export-btn').addEventListener('click', handleExport);
    $('import-btn').addEventListener('click', function () { $('import-file-input').click(); });
    $('import-file-input').addEventListener('change', handleImportFile);
    $('clear-vault-btn').addEventListener('click', handleClearVault);

    // Confirm modal
    $('confirm-modal-cancel').addEventListener('click', function () {
      confirmCallback = null;
      window.VaultUI.closeModal($('confirm-modal-backdrop'));
    });
    $('confirm-modal-confirm').addEventListener('click', function () {
      const cb = confirmCallback;
      confirmCallback = null;
      window.VaultUI.closeModal($('confirm-modal-backdrop'));
      if (cb) cb();
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
