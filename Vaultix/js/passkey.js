/**
 * passkey.js
 * WebAuthn integration for unlocking the vault with a device passkey
 * (fingerprint, face, or PIN) instead of typing the master password.
 *
 * Design: a passkey alone cannot decrypt anything — WebAuthn produces
 * proof of user presence/verification, not a symmetric secret, by
 * itself. To make passkey unlock cryptographically real (not just a UI
 * gate) this module uses the WebAuthn PRF extension where available
 * (falling back to the largeBlob extension) to derive key material that
 * only this exact passkey, on this exact device, can reproduce. That
 * derived key is used purely to WRAP (encrypt) the vault's real AES-GCM
 * key — the same key that a correct master password would derive via
 * PBKDF2. The wrapped copy is harmless to store: without the physical
 * passkey it cannot be unwrapped.
 *
 * If a device/browser doesn't support either extension, passkey unlock
 * is refused rather than faked — see registerPasskey().
 *
 * This module never sees the master password, never stores a private
 * key, and never touches biometric data — that's all handled by the
 * platform authenticator via the browser's native WebAuthn APIs.
 */
(function (global) {
  'use strict';

  function PasskeyError(code, message) {
    this.name = 'PasskeyError';
    this.code = code;
    this.message = message;
  }
  PasskeyError.prototype = Object.create(Error.prototype);
  PasskeyError.prototype.constructor = PasskeyError;

  function bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function base64ToBuf(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function randomBytes(len) {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return arr;
  }

  function isSupported() {
    return !!(global.PublicKeyCredential && navigator.credentials &&
      navigator.credentials.create && navigator.credentials.get);
  }

  function isSecureContext() {
    return global.isSecureContext === true;
  }

  async function isPlatformAuthenticatorAvailable() {
    if (!isSupported()) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (e) {
      return false;
    }
  }

  function friendlyMessage(err) {
    const name = err && err.name;
    switch (name) {
      case 'NotAllowedError':
        return 'Passkey authentication was cancelled or timed out.';
      case 'InvalidStateError':
        return 'A passkey for this device may already be registered.';
      case 'SecurityError':
        return 'This page can\'t use passkeys in this context. Passkeys require HTTPS.';
      case 'NotSupportedError':
        return 'Your browser doesn\'t support the passkey options Vault needs.';
      case 'AbortError':
        return 'The passkey request was interrupted. Please try again.';
      case 'ConstraintError':
        return 'No suitable device passkey (fingerprint, face, or PIN) is available.';
      default:
        return 'Passkey authentication failed. Please try again or use your master password.';
    }
  }

  function wrapError(err) {
    if (err instanceof PasskeyError) return err;
    return new PasskeyError(err && err.name ? err.name : 'unknown', friendlyMessage(err));
  }

  /**
   * Creates a platform passkey and returns non-sensitive metadata plus
   * the vault's AES-GCM key wrapped under key material derived from the
   * passkey. Throws PasskeyError on any failure, including when the
   * device supports WebAuthn but not the extensions Vault needs.
   *
   * @param {CryptoKey} vaultKey - the current, extractable vault AES-GCM key
   */
  async function registerPasskey(vaultKey) {
    if (!isSupported()) throw new PasskeyError('unsupported', 'Passkeys aren\'t supported in this browser.');
    if (!isSecureContext()) {
      throw new PasskeyError(
        'insecure-context',
        'Passkeys require a secure context (HTTPS). This won\'t work when opening the file directly — try a local HTTPS server or your deployed GitHub Pages URL.'
      );
    }
    const platformAvailable = await isPlatformAuthenticatorAvailable();
    if (!platformAvailable) {
      throw new PasskeyError('unsupported', 'No device passkey (fingerprint, face, or PIN) is available on this device.');
    }

    const prfSalt = randomBytes(32);
    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: {
          challenge: randomBytes(32),
          rp: { name: 'Vault', id: global.location.hostname },
          user: { id: randomBytes(16), name: 'vault-user', displayName: 'Vault User' },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256
            { type: 'public-key', alg: -257 }, // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred',
          },
          extensions: {
            prf: { eval: { first: prfSalt } },
            largeBlob: { support: 'preferred' },
          },
          attestation: 'none',
          timeout: 60000,
        },
      });
    } catch (err) {
      throw wrapError(err);
    }
    if (!credential) throw new PasskeyError('cancelled', 'Passkey creation was cancelled.');

    const creationExt = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
    const prfEnabled = !!(creationExt.prf && creationExt.prf.enabled);
    const largeBlobSupported = !!(creationExt.largeBlob && creationExt.largeBlob.supported);

    const credentialId = bufToBase64(credential.rawId);
    const transports = (credential.response && credential.response.getTransports)
      ? credential.response.getTransports() : [];

    if (prfEnabled) {
      return finishPrfRegistration(credential, credentialId, transports, prfSalt, vaultKey);
    }
    if (largeBlobSupported) {
      return finishLargeBlobRegistration(credential, credentialId, transports, vaultKey);
    }

    throw new PasskeyError(
      'unsupported',
      'This device created a passkey, but doesn\'t support the extra security extension Vault needs to use it for encryption, so passkey unlock isn\'t available here. The passkey itself is harmless — you can remove it from your device\'s passkey settings if you don\'t want it to linger.'
    );
  }

  async function finishPrfRegistration(credential, credentialId, transports, prfSalt, vaultKey) {
    // The PRF extension only reports "enabled" at creation time — the
    // actual derived secret comes back from a get() assertion.
    let assertion;
    try {
      assertion = await navigator.credentials.get({
        publicKey: {
          challenge: randomBytes(32),
          rpId: global.location.hostname,
          allowCredentials: [{ id: credential.rawId, type: 'public-key', transports: transports }],
          userVerification: 'required',
          extensions: { prf: { eval: { first: prfSalt } } },
          timeout: 60000,
        },
      });
    } catch (err) {
      throw wrapError(err);
    }

    const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
    const prfOutput = ext.prf && ext.prf.results && ext.prf.results.first;
    if (!prfOutput) {
      throw new PasskeyError('unsupported', 'This device didn\'t return a passkey encryption key. Please use your master password.');
    }

    const wrappingKey = await crypto.subtle.importKey('raw', prfOutput, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);
    const wrapped = await wrapVaultKey(vaultKey, wrappingKey);

    return {
      credentialId: credentialId,
      transports: transports,
      mode: 'prf',
      prfSalt: bufToBase64(prfSalt),
      wrappedKey: wrapped,
      createdAt: new Date().toISOString(),
    };
  }

  async function finishLargeBlobRegistration(credential, credentialId, transports, vaultKey) {
    const wrappingKeyBytes = randomBytes(32);
    let assertion;
    try {
      assertion = await navigator.credentials.get({
        publicKey: {
          challenge: randomBytes(32),
          rpId: global.location.hostname,
          allowCredentials: [{ id: credential.rawId, type: 'public-key', transports: transports }],
          userVerification: 'required',
          extensions: { largeBlob: { write: wrappingKeyBytes.buffer } },
          timeout: 60000,
        },
      });
    } catch (err) {
      throw wrapError(err);
    }

    const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
    if (!ext.largeBlob || ext.largeBlob.written !== true) {
      throw new PasskeyError('unsupported', 'This device couldn\'t store passkey key material. Please use your master password.');
    }

    const wrappingKey = await crypto.subtle.importKey('raw', wrappingKeyBytes, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);
    const wrapped = await wrapVaultKey(vaultKey, wrappingKey);

    return {
      credentialId: credentialId,
      transports: transports,
      mode: 'largeBlob',
      wrappedKey: wrapped,
      createdAt: new Date().toISOString(),
    };
  }

  async function wrapVaultKey(vaultKey, wrappingKey) {
    const iv = randomBytes(12);
    const wrapped = await crypto.subtle.wrapKey('raw', vaultKey, wrappingKey, { name: 'AES-GCM', iv: iv });
    return { iv: bufToBase64(iv), ciphertext: bufToBase64(wrapped) };
  }

  /**
   * Prompts for the passkey and, on success, returns the unwrapped
   * vault AES-GCM CryptoKey. Throws PasskeyError otherwise.
   * @param {object} meta - stored passkey metadata (see storage.js)
   */
  async function unlockWithPasskey(meta) {
    if (!isSupported()) throw new PasskeyError('unsupported', 'Passkeys aren\'t supported in this browser.');
    if (!isSecureContext()) {
      throw new PasskeyError('insecure-context', 'Passkeys require a secure context (HTTPS).');
    }

    const wrappingKeyMaterial = await getWrappingKeyMaterial(meta);
    const wrappingKey = await crypto.subtle.importKey('raw', wrappingKeyMaterial, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);

    try {
      return await crypto.subtle.unwrapKey(
        'raw',
        base64ToBuf(meta.wrappedKey.ciphertext),
        wrappingKey,
        { name: 'AES-GCM', iv: base64ToBuf(meta.wrappedKey.iv) },
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
    } catch (err) {
      throw new PasskeyError('mismatch', 'This passkey couldn\'t unlock the vault. Please use your master password.');
    }
  }

  /**
   * Re-wraps a newly-derived vault key (e.g. after a master password
   * change) under the same existing passkey. Requires one more
   * passkey ceremony. Returns updated metadata to persist.
   */
  async function rewrapForPasskey(meta, newVaultKey) {
    const wrappingKeyMaterial = await getWrappingKeyMaterial(meta);
    const wrappingKey = await crypto.subtle.importKey('raw', wrappingKeyMaterial, { name: 'AES-GCM' }, false, ['wrapKey', 'unwrapKey']);
    const wrapped = await wrapVaultKey(newVaultKey, wrappingKey);
    return Object.assign({}, meta, { wrappedKey: wrapped });
  }

  async function getWrappingKeyMaterial(meta) {
    const extensions = meta.mode === 'prf'
      ? { prf: { eval: { first: base64ToBuf(meta.prfSalt) } } }
      : { largeBlob: { read: true } };

    let assertion;
    try {
      assertion = await navigator.credentials.get({
        publicKey: {
          challenge: randomBytes(32),
          rpId: global.location.hostname,
          allowCredentials: [{ id: base64ToBuf(meta.credentialId), type: 'public-key', transports: meta.transports || [] }],
          userVerification: 'required',
          extensions: extensions,
          timeout: 60000,
        },
      });
    } catch (err) {
      throw wrapError(err);
    }
    if (!assertion) throw new PasskeyError('cancelled', 'Passkey authentication was cancelled.');

    const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
    const material = meta.mode === 'prf'
      ? (ext.prf && ext.prf.results && ext.prf.results.first)
      : (ext.largeBlob && ext.largeBlob.blob);

    if (!material) {
      throw new PasskeyError('unsupported', 'This device didn\'t return the expected passkey data. Please use your master password.');
    }
    return material;
  }

  global.VaultPasskey = {
    PasskeyError: PasskeyError,
    isSupported: isSupported,
    isSecureContext: isSecureContext,
    isPlatformAuthenticatorAvailable: isPlatformAuthenticatorAvailable,
    registerPasskey: registerPasskey,
    unlockWithPasskey: unlockWithPasskey,
    rewrapForPasskey: rewrapForPasskey,
  };
})(window);
