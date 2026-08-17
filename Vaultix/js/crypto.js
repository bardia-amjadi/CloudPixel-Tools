/**
 * crypto.js
 * All cryptography for Vault lives here, isolated from storage and UI logic.
 *
 * Key derivation: PBKDF2 (SHA-256, 250,000 iterations) from the master password.
 * Encryption: AES-GCM 256-bit, random 12-byte IV per encryption operation.
 * Nothing here ever touches localStorage or the DOM.
 */
(function (global) {
  'use strict';

  const PBKDF2_ITERATIONS = 250000;
  const KEY_LENGTH_BITS = 256;
  const SALT_LENGTH_BYTES = 16;
  const IV_LENGTH_BYTES = 12;

  function bufToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBuf(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function randomBytes(length) {
    const arr = new Uint8Array(length);
    crypto.getRandomValues(arr);
    return arr;
  }

  function generateSalt() {
    return bufToBase64(randomBytes(SALT_LENGTH_BYTES));
  }

  function generateIV() {
    return randomBytes(IV_LENGTH_BYTES);
  }

  /**
   * Derives an AES-GCM CryptoKey from a master password and salt using PBKDF2.
   * @param {string} password
   * @param {string} saltBase64
   * @param {number} [iterations]
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKey(password, saltBase64, iterations) {
    const enc = new TextEncoder();
    const passKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    const salt = base64ToBuf(saltBase64);

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations || PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      passKey,
      { name: 'AES-GCM', length: KEY_LENGTH_BITS },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypts a JS value with AES-GCM under the given key.
   * @param {CryptoKey} key
   * @param {any} data - JSON-serializable value
   * @returns {Promise<{iv: string, ciphertext: string}>} base64-encoded parts
   */
  async function encryptData(key, data) {
    const iv = generateIV();
    const enc = new TextEncoder();
    const plaintext = enc.encode(JSON.stringify(data));

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      plaintext
    );

    return {
      iv: bufToBase64(iv),
      ciphertext: bufToBase64(ciphertext),
    };
  }

  /**
   * Decrypts an AES-GCM payload back into a JS value.
   * Throws if the key/password is wrong or the data was tampered with.
   * @param {CryptoKey} key
   * @param {{iv: string, ciphertext: string}} payload
   * @returns {Promise<any>}
   */
  async function decryptData(key, payload) {
    const iv = new Uint8Array(base64ToBuf(payload.iv));
    const ciphertextBuf = base64ToBuf(payload.ciphertext);

    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertextBuf
    );

    const dec = new TextDecoder();
    return JSON.parse(dec.decode(plaintextBuf));
  }

  global.VaultCrypto = {
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    generateSalt: generateSalt,
    deriveKey: deriveKey,
    encryptData: encryptData,
    decryptData: decryptData,
  };
})(window);
