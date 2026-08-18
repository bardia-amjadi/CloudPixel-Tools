/**
 * service-worker.js
 *
 * Caches the static application shell (HTML/CSS/JS/icons/manifest) so
 * Vault can launch offline once it's been opened at least once.
 *
 * This file NEVER sees vault contents. The encrypted vault lives only
 * in localStorage, which service workers cannot read or intercept —
 * there is nothing vault-related for this file to cache, by construction.
 * It only ever caches responses to fetch() requests, and Vault makes no
 * network requests involving vault data (there is no server to talk to).
 */
'use strict';

const CACHE_VERSION = 'v1';
const CACHE_NAME = 'vault-shell-' + CACHE_VERSION;

// Paths are relative so this works whether the app is served from a
// domain root or a GitHub Pages project path (/repo-name/).
const APP_SHELL = [
  './',
  './index.html',
  './css/style.css',
  './js/crypto.js',
  './js/storage.js',
  './js/password-generator.js',
  './js/passkey.js',
  './js/ui.js',
  './js/pwa.js',
  './js/app.js',
  './manifest.json',
  './assets/icons/icon-72.png',
  './assets/icons/icon-96.png',
  './assets/icons/icon-128.png',
  './assets/icons/icon-144.png',
  './assets/icons/icon-152.png',
  './assets/icons/icon-192.png',
  './assets/icons/icon-384.png',
  './assets/icons/icon-512.png',
  './assets/icons/icon-maskable-192.png',
  './assets/icons/icon-maskable-512.png',
  './assets/icons/apple-touch-icon.png',
];

self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function (cache) {
        // Fetch app-shell files individually so one bad request (e.g. a
        // font blocked offline on first install) doesn't fail the whole
        // install — best-effort caching, not all-or-nothing.
        return Promise.all(
          APP_SHELL.map(function (url) {
            return cache.add(url).catch(function () { /* ignore */ });
          })
        );
      })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(
          keys
            .filter(function (key) { return key.startsWith('vault-shell-') && key !== CACHE_NAME; })
            .map(function (key) { return caches.delete(key); })
        );
      })
      .then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (event) {
  const request = event.request;

  // Only handle safe, cacheable GET requests. Everything else (there is
  // no vault-related network traffic, but be defensive) passes through
  // untouched.
  if (request.method !== 'GET') return;

  event.respondWith(staleWhileRevalidate(request));
});

/**
 * Serves from cache immediately when available while updating the cache
 * in the background, so the app opens instantly and stays fresh on the
 * next launch. Falls back to network, then to the cached app shell for
 * navigations if everything else fails (fully offline, nothing cached
 * yet for this exact URL).
 */
function staleWhileRevalidate(request) {
  return caches.open(CACHE_NAME).then(function (cache) {
    return cache.match(request).then(function (cachedResponse) {
      const networkFetch = fetch(request)
        .then(function (networkResponse) {
          if (networkResponse && networkResponse.ok) {
            cache.put(request, networkResponse.clone());
          }
          return networkResponse;
        })
        .catch(function () {
          if (request.mode === 'navigate') {
            return cache.match('./index.html');
          }
          return cachedResponse;
        });

      return cachedResponse || networkFetch;
    });
  });
}
