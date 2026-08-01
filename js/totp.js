/**
 * TOTP (Time-based One-Time Password) Implementation (RFC 6238)
 * Uses native Web Crypto API (crypto.subtle) for HMAC-SHA1 calculations.
 */

const TOTP = {
  // Alphabet for Base32 encoding
  base32Chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',

  /**
   * Generates a random Base32 secret string (default 16 chars = 80 bits of entropy)
   */
  generateSecret(length = 16) {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    let secret = '';
    for (let i = 0; i < length; i++) {
      secret += this.base32Chars[array[i] % 32];
    }
    return secret;
  },

  /**
   * Converts Base32 string to Uint8Array
   */
  base32ToBytes(base32) {
    const cleaned = base32.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
    const bits = [];
    for (let i = 0; i < cleaned.length; i++) {
      const val = this.base32Chars.indexOf(cleaned[i]);
      if (val === -1) continue;
      for (let b = 4; b >= 0; b--) {
        bits.push((val >> b) & 1);
      }
    }
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
      let byteVal = 0;
      for (let b = 0; b < 8; b++) {
        byteVal = (byteVal << 1) | bits[i * 8 + b];
      }
      bytes[i] = byteVal;
    }
    return bytes;
  },

  /**
   * Generates 6-digit TOTP pin for a given Base32 secret and timestamp
   */
  async generateCode(secret, timeOffsetSeconds = 0) {
    try {
      const keyBytes = this.base32ToBytes(secret);
      if (keyBytes.length === 0) return '000000';

      const epoch = Math.floor((Date.now() / 1000 + timeOffsetSeconds) / 30);
      
      // Convert counter to 8-byte big-endian buffer
      const buffer = new ArrayBuffer(8);
      const view = new DataView(buffer);
      view.setUint32(0, 0, false);
      view.setUint32(4, epoch, false);

      // Web Crypto HMAC-SHA1
      const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
      );

      const hmacSignature = await window.crypto.subtle.sign('HMAC', cryptoKey, buffer);
      const hmac = new Uint8Array(hmacSignature);

      // Dynamic Truncation
      const offset = hmac[hmac.length - 1] & 0x0f;
      const codeInt =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

      const otp = (codeInt % 1000000).toString().padStart(6, '0');
      return otp;
    } catch (err) {
      console.error('TOTP generation error:', err);
      return '000000';
    }
  },

  /**
   * Verifies user input OTP code against current and adjacent time windows (tolerates ±30s clock skew)
   */
  async verifyCode(secret, inputCode, windowSize = 1) {
    const cleanInput = inputCode.toString().trim();
    if (cleanInput.length !== 6 || !/^\d{6}$/.test(cleanInput)) return false;

    // Check current time window, previous (-30s), and next (+30s)
    for (let offset = -windowSize * 30; offset <= windowSize * 30; offset += 30) {
      const generated = await this.generateCode(secret, offset);
      if (generated === cleanInput) {
        return true;
      }
    }
    return false;
  },

  /**
   * Returns standard otpauth:// URL for QR code generation
   */
  getOTPAuthURL(username, secret, issuer = 'SecureAuth') {
    const encodedUser = encodeURIComponent(username);
    const encodedIssuer = encodeURIComponent(issuer);
    return `otpauth://totp/${encodedIssuer}:${encodedUser}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
  },

  /**
   * Generates emergency backup single-use codes
   */
  generateBackupCodes(count = 8) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      const rand = new Uint8Array(4);
      window.crypto.getRandomValues(rand);
      const code = Array.from(rand).map(b => b.toString(16).padStart(2, '0')).join('');
      codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
    }
    return codes;
  }
};
