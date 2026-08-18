/**
 * pwa.js
 * Registers the service worker and manages the "Install Vault" affordance.
 * Holds no vault state and never touches crypto.js or storage.js's vault
 * keys — only the app's own non-sensitive settings file.
 */
(function (global) {
  'use strict';

  let deferredInstallPrompt = null;
  let onAvailabilityChange = function () {};

  function isStandalone() {
    return (
      window.matchMedia('(display-mode: standalone)').matches ||
      window.navigator.standalone === true // iOS Safari
    );
  }

  function isIOS() {
    return /iphone|ipad|ipod/i.test(navigator.userAgent) ||
      (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1); // iPadOS 13+
  }

  function registerServiceWorker() {
    if (!('serviceWorker' in navigator)) return;
    if (window.location.protocol !== 'https:' && window.location.hostname !== 'localhost') {
      // Service workers require a secure context; silently skip on
      // plain http/file so the rest of the app still works.
      return;
    }
    window.addEventListener('load', function () {
      navigator.serviceWorker.register('./service-worker.js').catch(function () {
        // Non-fatal — the app works fine online without it, it just
        // won't be available offline.
      });
    });
  }

  function wireInstallPrompt() {
    window.addEventListener('beforeinstallprompt', function (e) {
      e.preventDefault();
      deferredInstallPrompt = e;
      onAvailabilityChange(getInstallState());
    });

    window.addEventListener('appinstalled', function () {
      deferredInstallPrompt = null;
      onAvailabilityChange(getInstallState());
    });
  }

  /**
   * @returns {{state: 'installed'|'promptable'|'ios-manual'|'unavailable'}}
   */
  function getInstallState() {
    if (isStandalone()) return { state: 'installed' };
    if (deferredInstallPrompt) return { state: 'promptable' };
    if (isIOS()) return { state: 'ios-manual' };
    return { state: 'unavailable' };
  }

  async function promptInstall() {
    if (!deferredInstallPrompt) return { outcome: 'unavailable' };
    deferredInstallPrompt.prompt();
    const choice = await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    onAvailabilityChange(getInstallState());
    return choice; // { outcome: 'accepted' | 'dismissed' }
  }

  function onInstallStateChange(callback) {
    onAvailabilityChange = callback;
  }

  registerServiceWorker();
  wireInstallPrompt();

  global.VaultPWA = {
    getInstallState: getInstallState,
    promptInstall: promptInstall,
    onInstallStateChange: onInstallStateChange,
    isStandalone: isStandalone,
  };
})(window);
