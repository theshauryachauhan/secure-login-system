/**
 * Password Hashing & Validation Engine
 * Uses Web Crypto PBKDF2 / SHA-256 with 100,000 iterations & 128-bit salt
 * Format: $pbkdf2-sha256$i=100000$<salt_hex>$<hash_hex>
 */

const PasswordHasher = {
  iterations: 100000,

  /**
   * Generates a secure random salt (16 bytes)
   */
  generateSaltHex() {
    const saltBytes = new Uint8Array(16);
    window.crypto.getRandomValues(saltBytes);
    return Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Hashes a password string with salt using PBKDF2-HMAC-SHA256
   */
  async hashPassword(password, saltHex = null) {
    if (!saltHex) {
      saltHex = this.generateSaltHex();
    }

    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    // Convert salt hex to Uint8Array
    const saltBytes = new Uint8Array(
      saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
    );

    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      passwordBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: this.iterations,
        hash: 'SHA-256'
      },
      baseKey,
      256 // 256 bits = 32 bytes
    );

    const hashArray = new Uint8Array(derivedBits);
    const hashHex = Array.from(hashArray).map(b => b.toString(16).padStart(2, '0')).join('');

    return `$pbkdf2-sha256$i=${this.iterations}$${saltHex}$${hashHex}`;
  },

  /**
   * Verifies an unhashed password input against a stored hash string
   */
  async verifyPassword(password, storedHashString) {
    try {
      const parts = storedHashString.split('$');
      if (parts.length !== 5 || parts[1] !== 'pbkdf2-sha256') {
        return false;
      }

      const saltHex = parts[3];
      const computedHashString = await this.hashPassword(password, saltHex);
      
      // Constant-time string comparison to prevent timing attacks
      return this.constantTimeCompare(computedHashString, storedHashString);
    } catch (err) {
      console.error('Password verification error:', err);
      return false;
    }
  },

  /**
   * Constant-time comparison to mitigate side-channel timing attacks
   */
  constantTimeCompare(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  },

  /**
   * Analyzes password strength and returns entropy score (0 to 100) & criteria breakdown
   */
  evaluateStrength(password) {
    let score = 0;
    const checks = {
      length: password.length >= 8,
      strongLength: password.length >= 12,
      hasUpper: /[A-Z]/.test(password),
      hasLower: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecial: /[^A-Za-z0-9]/.test(password)
    };

    if (checks.length) score += 20;
    if (checks.strongLength) score += 15;
    if (checks.hasUpper) score += 15;
    if (checks.hasLower) score += 15;
    if (checks.hasNumber) score += 15;
    if (checks.hasSpecial) score += 20;

    let label = 'Very Weak';
    let color = '#ef4444'; // Red

    if (score >= 80) {
      label = 'Strong';
      color = '#10b981'; // Green
    } else if (score >= 60) {
      label = 'Medium';
      color = '#f59e0b'; // Amber/Yellow
    } else if (score >= 40) {
      label = 'Weak';
      color = '#f97316'; // Orange
    }

    return {
      score,
      label,
      color,
      checks
    };
  }
};
