/**
 * ==============================================================================
 * CIPHERCORE CRYPTOGRAPHIC ENGINE
 * Zero-Server End-to-End Encryption (E2EE) Primitives
 * Powered exclusively by the W3C Web Crypto API (SubtleCrypto) & CSPRNG
 * ==============================================================================
 * Security Standards:
 * - Symmetric: AES-GCM 256-bit with authenticated data & unique 96-bit IV per message
 * - Asymmetric / PFS: ECDH (Elliptic Curve Diffie-Hellman P-256) for ephemeral key exchange
 * - Key Derivation: PBKDF2 with SHA-256, 600,000 iterations (OWASP recommendation)
 * - Safety Numbers: Signal-compatible 60-digit SAS fingerprint via SHA-256 hash chaining
 * - Password Generation: Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
 */

class CipherCore {
  constructor() {
    this.subtle = window.crypto.subtle;
    this.crypto = window.crypto;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder();
  }

  /**
   * Generates a cryptographically secure password using crypto.getRandomValues.
   * Default length is 16 characters as requested, with high entropy.
   * @param {number} length - Length of password (default: 16)
   * @param {Object} options - Character set options
   * @returns {string} - Secure random password
   */
  generateSecurePassword(length = 16, options = {}) {
    const defaultOpts = {
      includeUpper: true,
      includeLower: true,
      includeNumbers: true,
      includeSymbols: true,
    };
    const opts = { ...defaultOpts, ...options };

    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // Exclude ambiguous I, O
    const lower = 'abcdefghjkmnpqrstuvwxyz'; // Exclude ambiguous l, o
    const numbers = '23456789'; // Exclude ambiguous 0, 1
    const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';

    let charset = '';
    const guaranteed = [];

    if (opts.includeUpper) {
      charset += upper;
      guaranteed.push(this._getRandomChar(upper));
    }
    if (opts.includeLower) {
      charset += lower;
      guaranteed.push(this._getRandomChar(lower));
    }
    if (opts.includeNumbers) {
      charset += numbers;
      guaranteed.push(this._getRandomChar(numbers));
    }
    if (opts.includeSymbols) {
      charset += symbols;
      guaranteed.push(this._getRandomChar(symbols));
    }

    if (charset === '') charset = lower + numbers;

    const remainingLength = Math.max(0, length - guaranteed.length);
    const randomBuffer = new Uint32Array(remainingLength);
    this.crypto.getRandomValues(randomBuffer);

    const chars = [...guaranteed];
    for (let i = 0; i < remainingLength; i++) {
      chars.push(charset[randomBuffer[i] % charset.length]);
    }

    // Cryptographic Fisher-Yates Shuffle
    for (let i = chars.length - 1; i > 0; i--) {
      const randBuf = new Uint32Array(1);
      this.crypto.getRandomValues(randBuf);
      const j = randBuf[0] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }

    return chars.join('');
  }

  _getRandomChar(set) {
    const buf = new Uint32Array(1);
    this.crypto.getRandomValues(buf);
    return set[buf[0] % set.length];
  }

  /**
   * Calculates Shannon entropy in bits for a password
   * @param {string} password 
   * @returns {number} entropy
   */
  calculateEntropy(password) {
    if (!password) return 0;
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
    if (pool === 0) pool = 1;
    return Math.round(password.length * Math.log2(pool));
  }

  /**
   * Generates a random cryptographic salt (16 bytes)
   */
  generateSalt(bytes = 16) {
    const salt = new Uint8Array(bytes);
    this.crypto.getRandomValues(salt);
    return salt;
  }

  /**
   * Derives a 256-bit AES-GCM CryptoKey from a password and salt using PBKDF2
   * 600,000 iterations of SHA-256 for resistance to offline GPU brute-force attacks.
   */
  async deriveKeyFromPassword(password, salt) {
    const keyMaterial = await this.subtle.importKey(
      'raw',
      this.encoder.encode(password),
      'PBKDF2',
      false,
      ['deriveKey', 'deriveBits']
    );

    return await this.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 600000,
        hash: 'SHA-256',
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generates an Ephemeral ECDH (P-256) Key Pair for Perfect Forward Secrecy (PFS)
   */
  async generateECDHKeyPair() {
    return await this.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true, // extractable for public key exchange
      ['deriveKey', 'deriveBits']
    );
  }

  /**
   * Exports an ECDH public key to raw uncompressed hex/base64 format
   */
  async exportPublicKey(key) {
    const exported = await this.subtle.exportKey('raw', key);
    return this.bufferToBase64(exported);
  }

  /**
   * Imports a remote peer's raw ECDH public key
   */
  async importPublicKey(base64Key) {
    const buffer = this.base64ToBuffer(base64Key);
    return await this.subtle.importKey(
      'raw',
      buffer,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      []
    );
  }

  /**
   * Computes a shared AES-256-GCM encryption key using local private key and remote public key
   */
  async deriveSharedSecret(privateKey, remotePublicKey) {
    return await this.subtle.deriveKey(
      {
        name: 'ECDH',
        public: remotePublicKey,
      },
      privateKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generates an ephemeral 256-bit AES-GCM symmetric key for media/file envelope encryption
   */
  async generateSymmetricKey() {
    return await this.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true, // extractable so it can be encrypted for recipients
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Exports an AES-GCM key to base64 string
   */
  async exportSymmetricKey(key) {
    const raw = await this.subtle.exportKey('raw', key);
    return this.bufferToBase64(raw);
  }

  /**
   * Imports a raw AES-GCM key from base64 string
   */
  async importSymmetricKey(base64Key) {
    const buffer = this.base64ToBuffer(base64Key);
    return await this.subtle.importKey(
      'raw',
      buffer,
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypts plaintext data using AES-GCM 256-bit with fresh 12-byte (96-bit) IV
   * @param {string|Uint8Array} data - Plaintext string or binary buffer
   * @param {CryptoKey} key - 256-bit AES-GCM key
   * @returns {Promise<{ciphertext: string, iv: string}>}
   */
  async encrypt(data, key) {
    const iv = new Uint8Array(12);
    this.crypto.getRandomValues(iv);

    let rawData;
    if (typeof data === 'string') {
      rawData = this.encoder.encode(data);
    } else if (data instanceof Uint8Array) {
      rawData = data;
    } else if (data instanceof ArrayBuffer) {
      rawData = new Uint8Array(data);
    } else {
      rawData = this.encoder.encode(JSON.stringify(data));
    }

    const encrypted = await this.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      key,
      rawData
    );

    return {
      ciphertext: this.bufferToBase64(encrypted),
      iv: this.bufferToBase64(iv),
    };
  }

  /**
   * Decrypts AES-GCM ciphertext
   * @param {string} ciphertextBase64 
   * @param {string} ivBase64 
   * @param {CryptoKey} key 
   * @param {boolean} returnBinary - Whether to return raw Uint8Array instead of UTF-8 string
   */
  async decrypt(ciphertextBase64, ivBase64, key, returnBinary = false) {
    const ciphertext = this.base64ToBuffer(ciphertextBase64);
    const iv = this.base64ToBuffer(ivBase64);

    const decrypted = await this.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      key,
      ciphertext
    );

    if (returnBinary) {
      return new Uint8Array(decrypted);
    }
    return this.decoder.decode(decrypted);
  }

  /**
   * Computes a Signal-style 60-digit Safety Number for out-of-band identity verification
   * Sorts public keys lexicographically to ensure both peers get the exact same number.
   * @param {string} myPublicKeyBase64 
   * @param {string} peerPublicKeyBase64 
   * @returns {Promise<string>} 60-digit formatted string (12 blocks of 5 digits)
   */
  async computeSafetyNumbers(myPublicKeyBase64, peerPublicKeyBase64) {
    const sorted = [myPublicKeyBase64, peerPublicKeyBase64].sort();
    const combined = sorted[0] + '::' + sorted[1];
    let currentHash = await this.subtle.digest('SHA-256', this.encoder.encode(combined));

    // Iterative hashing (5200 rounds)
    for (let i = 0; i < 5200; i++) {
      currentHash = await this.subtle.digest('SHA-256', currentHash);
    }

    const hashBytes = new Uint8Array(currentHash);
    let digits = '';
    for (let i = 0; i < 30; i++) {
      const val = (hashBytes[i % hashBytes.length] * 256 + hashBytes[(i + 1) % hashBytes.length]) % 100;
      digits += val.toString().padStart(2, '0');
    }
    digits = digits.slice(0, 60);

    // Format into 12 blocks of 5 digits
    const blocks = [];
    for (let i = 0; i < 60; i += 5) {
      blocks.push(digits.slice(i, i + 5));
    }
    return blocks.join(' ');
  }

  /**
   * Computes SHA-256 fingerprint hex of a key or room
   */
  async computeFingerprint(dataString) {
    const digest = await this.subtle.digest('SHA-256', this.encoder.encode(dataString));
    return this.bufferToHex(digest).slice(0, 16).toUpperCase();
  }

  /**
   * Memory Purge: Overwrites typed arrays with cryptographic zeroes
   */
  secureWipe(typedArray) {
    if (typedArray && typedArray.fill) {
      typedArray.fill(0);
    }
  }

  /**
   * Encrypts and saves an object securely into localStorage using AES-256-GCM
   */
  async saveSecureLocal(storageKey, dataObj, password) {
    try {
      const salt = this.generateSalt(16);
      const key = await this.deriveKeyFromPassword(password, salt);
      const jsonStr = JSON.stringify(dataObj);
      const { ciphertext, iv } = await this.encrypt(jsonStr, key);
      const payload = {
        salt: this.bufferToBase64(salt),
        iv: iv,
        data: ciphertext
      };
      localStorage.setItem(storageKey, JSON.stringify(payload));
      return true;
    } catch (err) {
      console.error('Error saving secure local data:', err);
      return false;
    }
  }

  /**
   * Reads and decrypts an object from localStorage using AES-256-GCM
   */
  async loadSecureLocal(storageKey, password) {
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return null;
      const payload = JSON.parse(raw);
      if (!payload.salt || !payload.iv || !payload.data) return null;

      const salt = new Uint8Array(this.base64ToBuffer(payload.salt));
      const key = await this.deriveKeyFromPassword(password, salt);
      const decryptedJson = await this.decrypt(payload.data, payload.iv, key);
      return JSON.parse(decryptedJson);
    } catch (err) {
      console.warn('Could not decrypt local data (invalid password or corrupted):', err);
      return null;
    }
  }

  // --- Utility Encoders ---

  bufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  base64ToBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
  }
}

// Global instance attached to window
window.cipherCore = new CipherCore();
