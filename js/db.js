/**
 * Database & Security Engine
 * Embedded persistent database simulation with Parameterized Prepared Statements,
 * SQL Injection protection, Rate-Limiting Brute Force Shield, Session Store, and Audit Logs.
 */

class SecureDatabase {
  constructor() {
    this.storageKey = 'SECURE_AUTH_APP_DB_V1';
    this.initDatabase();
  }

  initDatabase() {
    const existing = localStorage.getItem(this.storageKey);
    if (!existing) {
      // Seed database with default structure & demo admin user
      const initialData = {
        users: [],
        sessions: [],
        auditLogs: [],
        failedAttempts: {} // ip/username -> { count, lockUntil }
      };
      localStorage.setItem(this.storageKey, JSON.stringify(initialData));
      
      // Create default admin user asynchronously
      this.seedDefaultUser();
    }
  }

  async seedDefaultUser() {
    const db = this.getData();
    if (db.users.length === 0) {
      const passwordHash = await PasswordHasher.hashPassword('Admin@123456');
      const defaultUser = {
        id: 'usr_' + Math.random().toString(36).substr(2, 9),
        username: 'admin',
        email: 'admin@secureauth.io',
        passwordHash: passwordHash,
        is2faEnabled: false,
        totpSecret: null,
        backupCodes: [],
        createdAt: new Date().toISOString()
      };
      db.users.push(defaultUser);
      this.saveData(db);
      this.logAudit(defaultUser.id, 'USER_REGISTER', 'System initialized with default demo account', 'SUCCESS');
    }
  }

  getData() {
    try {
      return JSON.parse(localStorage.getItem(this.storageKey)) || { users: [], sessions: [], auditLogs: [], failedAttempts: {} };
    } catch {
      return { users: [], sessions: [], auditLogs: [], failedAttempts: {} };
    }
  }

  saveData(data) {
    localStorage.setItem(this.storageKey, JSON.stringify(data));
  }

  // --- Input Validation & Sanitization ---
  validateRegistrationInput(username, email, password) {
    const errors = [];

    // Username validation (alphanumeric, 3-20 chars)
    if (!username || typeof username !== 'string') {
      errors.push('Username is required.');
    } else if (!/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
      errors.push('Username must be 3-20 characters long and contain only letters, numbers, underscores, or hyphens.');
    }

    // Email validation
    if (!email || typeof email !== 'string') {
      errors.push('Email address is required.');
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.push('Please enter a valid email address.');
    }

    // Password strength check
    if (!password || password.length < 8) {
      errors.push('Password must be at least 8 characters long.');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  // --- User Registration ---
  async registerUser(username, email, password) {
    const validation = this.validateRegistrationInput(username, email, password);
    if (!validation.isValid) {
      return { success: false, message: validation.errors.join(' ') };
    }

    const db = this.getData();
    
    // Parameterized search check for existing user
    const existingUser = db.users.find(
      u => u.username.toLowerCase() === username.toLowerCase() || u.email.toLowerCase() === email.toLowerCase()
    );

    if (existingUser) {
      return { success: false, message: 'Username or email address is already registered.' };
    }

    // Hash password with salt
    const passwordHash = await PasswordHasher.hashPassword(password);
    const newUser = {
      id: 'usr_' + Math.random().toString(36).substr(2, 9),
      username: username.trim(),
      email: email.trim().toLowerCase(),
      passwordHash: passwordHash,
      is2faEnabled: false,
      totpSecret: null,
      backupCodes: [],
      createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    this.saveData(db);

    this.logAudit(newUser.id, 'USER_REGISTER', `New user registered: ${username}`, 'SUCCESS');

    return { success: true, user: newUser };
  }

  // --- Rate Limiting & Lockout ---
  checkRateLimit(key) {
    const db = this.getData();
    const attempt = db.failedAttempts[key];
    if (!attempt) return { locked: false };

    if (attempt.lockUntil && Date.now() < attempt.lockUntil) {
      const remainingSec = Math.ceil((attempt.lockUntil - Date.now()) / 1000);
      return {
        locked: true,
        message: `Too many failed attempts. Account temporarily locked for ${remainingSec}s.`
      };
    }
    return { locked: false };
  }

  recordFailedAttempt(key) {
    const db = this.getData();
    if (!db.failedAttempts[key]) {
      db.failedAttempts[key] = { count: 0, lockUntil: null };
    }
    db.failedAttempts[key].count += 1;

    if (db.failedAttempts[key].count >= 5) {
      // Lock for 30 seconds
      db.failedAttempts[key].lockUntil = Date.now() + 30000;
    }
    this.saveData(db);
  }

  resetFailedAttempts(key) {
    const db = this.getData();
    delete db.failedAttempts[key];
    this.saveData(db);
  }

  // --- Parameterized vs Vulnerable SQL Authentication ---
  /**
   * PARAMETERIZED SAFE QUERY (Standard Protected Method)
   */
  async authenticateUserParameterized(usernameOrEmail, password, ipAddress = '127.0.0.1') {
    const rateCheck = this.checkRateLimit(usernameOrEmail);
    if (rateCheck.locked) {
      this.logAudit(null, 'LOGIN_ATTEMPT', `Rate limited attempt for ${usernameOrEmail}`, 'BLOCKED');
      return { success: false, message: rateCheck.message };
    }

    const db = this.getData();
    
    // Parameterized binding query (Treats input as pure string value)
    const user = db.users.find(
      u => u.username.toLowerCase() === usernameOrEmail.toLowerCase() || u.email.toLowerCase() === usernameOrEmail.toLowerCase()
    );

    if (!user) {
      this.recordFailedAttempt(usernameOrEmail);
      this.logAudit(null, 'LOGIN_FAILED', `Invalid credentials for ${usernameOrEmail}`, 'FAILED');
      return { success: false, message: 'Invalid username or password.' };
    }

    // Verify hashed password
    const isPasswordValid = await PasswordHasher.verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      this.recordFailedAttempt(usernameOrEmail);
      this.logAudit(user.id, 'LOGIN_FAILED', `Failed password attempt for user ${user.username}`, 'FAILED');
      return { success: false, message: 'Invalid username or password.' };
    }

    // Reset rate limit on success
    this.resetFailedAttempts(usernameOrEmail);

    if (user.is2faEnabled) {
      this.logAudit(user.id, 'LOGIN_2FA_REQUIRED', `2FA verification required for ${user.username}`, 'PENDING');
      return {
        success: true,
        requires2FA: true,
        user: { id: user.id, username: user.username, email: user.email }
      };
    }

    // Create session
    const session = this.createSession(user.id, ipAddress);
    this.logAudit(user.id, 'LOGIN_SUCCESS', `User ${user.username} logged in successfully`, 'SUCCESS');

    return {
      success: true,
      requires2FA: false,
      user,
      session
    };
  }

  /**
   * VULNERABLE SQL QUERY DEMONSTRATION (Educational Purpose)
   * Simulates unfiltered string concatenation: `SELECT * FROM users WHERE username = '` + input + `'`
   */
  simulateVulnerableSQL(usernameInput, passwordInput) {
    const rawQuery = `SELECT * FROM users WHERE username = '${usernameInput}' AND password = '${passwordInput}'`;
    const db = this.getData();

    let sqlBypassed = false;
    let matchedUsers = [];

    // Check if input contains SQL injection bypass syntax like `' OR '1'='1` or `' OR 1=1 --`
    const lowerUser = usernameInput.toLowerCase();
    const hasSqliPattern = lowerUser.includes("' or '") || lowerUser.includes("' or 1=1") || lowerUser.includes("' or '1'='1");

    if (hasSqliPattern) {
      sqlBypassed = true;
      matchedUsers = db.users; // Returns all users!
    } else {
      matchedUsers = db.users.filter(u => u.username === usernameInput);
    }

    return {
      rawQuery,
      executedSQL: rawQuery,
      parameterizedEquivalent: `SELECT * FROM users WHERE username = ? AND password = ?`,
      parameters: [usernameInput, '[HASHED_PASSWORD_VALUE]'],
      sqliDetectedInPayload: hasSqliPattern,
      isBypassed: sqlBypassed,
      resultCount: matchedUsers.length,
      explanation: sqlBypassed
        ? '⚠️ CRITICAL VULNERABILITY! Unsanitized string concatenation allowed SQL injection payload to alter the SQL logic tree, bypassing password verification entirely!'
        : 'Protected: Input was processed literally without SQL control character injection.'
    };
  }

  // --- Session Store Management ---
  createSession(userId, ipAddress = '127.0.0.1', userAgent = navigator.userAgent) {
    const db = this.getData();
    
    // Generate secure 32-byte session token
    const tokenBytes = new Uint8Array(24);
    window.crypto.getRandomValues(tokenBytes);
    const token = 'sess_' + Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    const session = {
      id: 'sid_' + Math.random().toString(36).substr(2, 9),
      userId,
      token,
      ipAddress,
      userAgent: userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
    };

    db.sessions.push(session);
    this.saveData(db);
    return session;
  }

  getUserActiveSessions(userId) {
    const db = this.getData();
    const now = new Date().toISOString();
    return db.sessions.filter(s => s.userId === userId && s.expiresAt > now);
  }

  revokeSession(sessionId, currentUserId) {
    const db = this.getData();
    const idx = db.sessions.findIndex(s => s.id === sessionId && s.userId === currentUserId);
    if (idx !== -1) {
      const revoked = db.sessions.splice(idx, 1)[0];
      this.saveData(db);
      this.logAudit(currentUserId, 'SESSION_REVOKED', `Revoked session ${sessionId}`, 'SUCCESS');
      return true;
    }
    return false;
  }

  // --- 2FA Functions ---
  async setup2FA(userId) {
    const db = this.getData();
    const user = db.users.find(u => u.id === userId);
    if (!user) return null;

    const secret = TOTP.generateSecret(16);
    const backupCodes = TOTP.generateBackupCodes(8);
    const otpauthURL = TOTP.getOTPAuthURL(user.username, secret, 'SecureAuth App');

    user.tempTotpSecret = secret;
    user.tempBackupCodes = backupCodes;
    this.saveData(db);

    return {
      secret,
      otpauthURL,
      backupCodes
    };
  }

  async confirm2FA(userId, verificationCode) {
    const db = this.getData();
    const user = db.users.find(u => u.id === userId);
    if (!user || !user.tempTotpSecret) return { success: false, message: 'Invalid 2FA setup state.' };

    const isValid = await TOTP.verifyCode(user.tempTotpSecret, verificationCode);
    if (!isValid) {
      return { success: false, message: 'Invalid 6-digit TOTP code. Please try again.' };
    }

    user.is2faEnabled = true;
    user.totpSecret = user.tempTotpSecret;
    user.backupCodes = user.tempBackupCodes || [];
    delete user.tempTotpSecret;
    delete user.tempBackupCodes;

    this.saveData(db);
    this.logAudit(userId, '2FA_ENABLED', 'Two-Factor Authentication activated', 'SUCCESS');

    return { success: true, backupCodes: user.backupCodes };
  }

  async disable2FA(userId, verificationCode) {
    const db = this.getData();
    const user = db.users.find(u => u.id === userId);
    if (!user || !user.is2faEnabled) return { success: false, message: '2FA is not enabled.' };

    const isValid = await TOTP.verifyCode(user.totpSecret, verificationCode);
    if (!isValid) {
      return { success: false, message: 'Invalid 6-digit verification code.' };
    }

    user.is2faEnabled = false;
    user.totpSecret = null;
    user.backupCodes = [];

    this.saveData(db);
    this.logAudit(userId, '2FA_DISABLED', 'Two-Factor Authentication deactivated', 'WARNING');

    return { success: true };
  }

  async verify2FAAndLogin(userId, code, ipAddress = '127.0.0.1') {
    const db = this.getData();
    const user = db.users.find(u => u.id === userId);
    if (!user || !user.is2faEnabled) return { success: false, message: 'User not found or 2FA disabled.' };

    // Check TOTP code
    let isValid = await TOTP.verifyCode(user.totpSecret, code);

    // Check backup codes if TOTP pin failed
    let usedBackupCode = false;
    if (!isValid && user.backupCodes && user.backupCodes.includes(code.trim())) {
      isValid = true;
      usedBackupCode = true;
      // Remove used backup code
      user.backupCodes = user.backupCodes.filter(c => c !== code.trim());
      this.saveData(db);
    }

    if (!isValid) {
      this.logAudit(userId, '2FA_FAILED', 'Invalid 2FA code supplied', 'FAILED');
      return { success: false, message: 'Invalid 2FA pin or backup code.' };
    }

    const session = this.createSession(user.id, ipAddress);
    this.logAudit(user.id, 'LOGIN_SUCCESS', `2FA verified successfully${usedBackupCode ? ' (using backup code)' : ''}`, 'SUCCESS');

    return {
      success: true,
      user,
      session
    };
  }

  // --- Audit Logging ---
  logAudit(userId, action, description, status = 'INFO') {
    const db = this.getData();
    const entry = {
      id: 'log_' + Math.random().toString(36).substr(2, 9),
      userId: userId || 'anonymous',
      action,
      description,
      status,
      timestamp: new Date().toISOString()
    };
    db.auditLogs.unshift(entry);
    // Keep max 100 log entries
    if (db.auditLogs.length > 100) db.auditLogs.pop();
    this.saveData(db);
    return entry;
  }

  getAuditLogs(userId = null) {
    const db = this.getData();
    if (!userId) return db.auditLogs;
    return db.auditLogs.filter(log => log.userId === userId);
  }
}

// Global instance
const db = new SecureDatabase();
