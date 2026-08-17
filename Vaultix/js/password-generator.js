/**
 * password-generator.js
 * Generates passwords from configurable character sets and estimates
 * their strength. No dependency on storage or UI.
 */
(function (global) {
  'use strict';

  const SETS = {
    uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
    lowercase: 'abcdefghijkmnpqrstuvwxyz',
    numbers: '23456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  };
  // Note: ambiguous characters (I, l, 1, O, 0) are intentionally excluded
  // to keep generated passwords easy to read back when needed.

  /**
   * @param {{length:number, uppercase:boolean, lowercase:boolean, numbers:boolean, symbols:boolean}} opts
   * @returns {string}
   */
  function generate(opts) {
    const options = Object.assign(
      { length: 16, uppercase: true, lowercase: true, numbers: true, symbols: true },
      opts
    );

    let pool = '';
    const guaranteed = [];

    if (options.uppercase) { pool += SETS.uppercase; guaranteed.push(pick(SETS.uppercase)); }
    if (options.lowercase) { pool += SETS.lowercase; guaranteed.push(pick(SETS.lowercase)); }
    if (options.numbers) { pool += SETS.numbers; guaranteed.push(pick(SETS.numbers)); }
    if (options.symbols) { pool += SETS.symbols; guaranteed.push(pick(SETS.symbols)); }

    if (!pool) {
      // Fall back to lowercase+numbers so the function never throws on
      // an all-false configuration.
      pool = SETS.lowercase + SETS.numbers;
      guaranteed.push(pick(SETS.lowercase));
    }

    const length = Math.max(options.length, guaranteed.length);
    const chars = guaranteed.slice();

    while (chars.length < length) {
      chars.push(pick(pool));
    }

    return shuffle(chars).join('');
  }

  function pick(str) {
    const idx = secureRandomInt(str.length);
    return str[idx];
  }

  function secureRandomInt(max) {
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    return arr[0] % max;
  }

  function shuffle(arr) {
    const copy = arr.slice();
    for (let i = copy.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }

  /**
   * Rough strength estimate based on character-set entropy and length.
   * Returns { score: 0-4, label: string }.
   */
  function estimateStrength(password) {
    if (!password) return { score: 0, label: 'Empty' };

    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;
    if (poolSize === 0) poolSize = 10;

    const entropy = Math.log2(poolSize) * password.length;

    let score, label;
    if (entropy < 28) { score = 0; label = 'Very weak'; }
    else if (entropy < 45) { score = 1; label = 'Weak'; }
    else if (entropy < 60) { score = 2; label = 'Fair'; }
    else if (entropy < 80) { score = 3; label = 'Strong'; }
    else { score = 4; label = 'Very strong'; }

    // Penalize short passwords even if the character set is wide.
    if (password.length < 8 && score > 1) score = 1;

    return { score: score, label: label };
  }

  global.PasswordGenerator = {
    generate: generate,
    estimateStrength: estimateStrength,
  };
})(window);
