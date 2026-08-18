/**
 * storage.js
 * Thin wrapper around localStorage. This module never sees plaintext
 * password entries — only the encrypted blob produced by crypto.js,
 * plus non-sensitive app settings (theme, auto-lock duration).
 */
(function (global) {
  'use strict';

  const KEYS = {
    VAULT: 'vault.blob',
    SETTINGS: 'vault.settings',
    PASSKEY: 'vault.passkey',
  };

  const SCHEMA_VERSION = 1;

  function hasVault() {
    return localStorage.getItem(KEYS.VAULT) !== null;
  }

  /**
   * @param {{salt:string, iv:string, ciphertext:string, iterations:number}} blob
   */
  function saveVaultBlob(blob) {
    const record = {
      version: SCHEMA_VERSION,
      salt: blob.salt,
      iv: blob.iv,
      ciphertext: blob.ciphertext,
      iterations: blob.iterations,
      updatedAt: new Date().toISOString(),
    };
    localStorage.setItem(KEYS.VAULT, JSON.stringify(record));
    return record;
  }

  function loadVaultBlob() {
    const raw = localStorage.getItem(KEYS.VAULT);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch (e) {
      return null;
    }
  }

  function clearVault() {
    localStorage.removeItem(KEYS.VAULT);
  }

  function loadSettings() {
    const raw = localStorage.getItem(KEYS.SETTINGS);
    const defaults = {
      theme: 'dark',
      autoLockMinutes: 15,
    };
    if (!raw) return defaults;
    try {
      return Object.assign(defaults, JSON.parse(raw));
    } catch (e) {
      return defaults;
    }
  }

  function saveSettings(settings) {
    localStorage.setItem(KEYS.SETTINGS, JSON.stringify(settings));
  }

  /**
   * Validates the shape of an imported vault file before it's allowed
   * anywhere near the app state.
   */
  function isValidVaultBlob(obj) {
    return (
      obj &&
      typeof obj === 'object' &&
      typeof obj.salt === 'string' &&
      typeof obj.iv === 'string' &&
      typeof obj.ciphertext === 'string' &&
      typeof obj.iterations === 'number'
    );
  }

  // ---- Passkey metadata ----------------------------------------------------
  // Only non-sensitive data lives here: a WebAuthn credential ID (not a
  // secret — see passkey.js), the wrapping mode, and the vault key
  // wrapped (encrypted) under key material that only the physical
  // passkey can reproduce. The master password and the unwrapped vault
  // key never appear in this file or in localStorage at all.

  function hasPasskey() {
    return localStorage.getItem(KEYS.PASSKEY) !== null;
  }

  function savePasskeyMeta(meta) {
    localStorage.setItem(KEYS.PASSKEY, JSON.stringify(meta));
    return meta;
  }

  function loadPasskeyMeta() {
    const raw = localStorage.getItem(KEYS.PASSKEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch (e) {
      return null;
    }
  }

  function clearPasskeyMeta() {
    localStorage.removeItem(KEYS.PASSKEY);
  }

  global.VaultStorage = {
    hasVault: hasVault,
    saveVaultBlob: saveVaultBlob,
    loadVaultBlob: loadVaultBlob,
    clearVault: clearVault,
    loadSettings: loadSettings,
    saveSettings: saveSettings,
    isValidVaultBlob: isValidVaultBlob,
    hasPasskey: hasPasskey,
    savePasskeyMeta: savePasskeyMeta,
    loadPasskeyMeta: loadPasskeyMeta,
    clearPasskeyMeta: clearPasskeyMeta,
    SCHEMA_VERSION: SCHEMA_VERSION,
  };
})(window);
