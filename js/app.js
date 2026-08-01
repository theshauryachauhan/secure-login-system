/**
 * Secure Login System - Application Orchestrator & UI Controller
 */

class AppController {
  constructor() {
    this.currentUser = null;
    this.currentSession = null;
    this.pending2FAUser = null;

    this.initElements();
    this.initEventListeners();
    this.checkExistingSession();
    this.runSQLiDemo(); // Run initial SQLi sandbox demonstration
  }

  initElements() {
    // Navigation & Views
    this.navBtns = document.querySelectorAll('.nav-btn');
    this.viewSections = document.querySelectorAll('.view-section');
    this.navDashboardBtn = document.getElementById('nav-dashboard-btn');

    // Header User Elements
    this.userStatusText = document.getElementById('user-status-text');
    this.logoutHeaderBtn = document.getElementById('logout-header-btn');

    // Auth Tabs & Forms
    this.tabLoginBtn = document.getElementById('tab-login-btn');
    this.tabRegisterBtn = document.getElementById('tab-register-btn');
    this.loginForm = document.getElementById('login-form');
    this.registerForm = document.getElementById('register-form');

    // Login Inputs
    this.loginUsernameInput = document.getElementById('login-username');
    this.loginPasswordInput = document.getElementById('login-password');
    this.fillDemoBtn = document.getElementById('fill-demo-btn');

    // Register Inputs
    this.regUsernameInput = document.getElementById('reg-username');
    this.regEmailInput = document.getElementById('reg-email');
    this.regPasswordInput = document.getElementById('reg-password');
    this.meterFill = document.getElementById('meter-fill');
    this.meterLabel = document.getElementById('meter-label');
    this.meterScore = document.getElementById('meter-score');

    // 2FA Verification Modal
    this.modal2FAVerify = document.getElementById('modal-2fa-verify');
    this.form2FAVerify = document.getElementById('form-2fa-verify');
    this.input2FACode = document.getElementById('input-2fa-code');

    // 2FA Setup Modal
    this.modal2FASetup = document.getElementById('modal-2fa-setup');
    this.form2FAConfirm = document.getElementById('form-2fa-confirm');
    this.setupSecretKey = document.getElementById('setup-secret-key');
    this.setupBackupCodes = document.getElementById('setup-backup-codes');
    this.setupConfirmCode = document.getElementById('setup-confirm-code');
    this.close2FASetupBtn = document.getElementById('close-2fa-setup-btn');
    this.qrCanvas = document.getElementById('qr-canvas');

    // Dashboard Elements
    this.dashUsername = document.getElementById('dash-username');
    this.dashEmail = document.getElementById('dash-email');
    this.dashSecurityScore = document.getElementById('dash-security-score');
    this.twoFAStatusText = document.getElementById('2fa-status-text');
    this.toggle2FABtn = document.getElementById('toggle-2fa-btn');
    this.activeSessionsList = document.getElementById('active-sessions-list');

    // SQLi Sandbox Elements
    this.sqliInputUser = document.getElementById('sqli-input-user');
    this.sqliInputPass = document.getElementById('sqli-input-pass');
    this.runSQLiDemoBtn = document.getElementById('run-sqli-demo-btn');
    this.presetSQLiBtn = document.getElementById('preset-sqli-btn');
    this.sqliVulnConsole = document.getElementById('sqli-vuln-console');
    this.sqliSafeConsole = document.getElementById('sqli-safe-console');
    this.sqliVulnStatus = document.getElementById('sqli-vuln-status');
    this.sqliSafeStatus = document.getElementById('sqli-safe-status');

    // Audit Logs
    this.auditLogsTbody = document.getElementById('audit-logs-tbody');
    this.refreshLogsBtn = document.getElementById('refresh-logs-btn');

    // Toast Container
    this.toastContainer = document.getElementById('toast-container');
  }

  initEventListeners() {
    // Section Navigation
    this.navBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const targetView = btn.getAttribute('data-view');
        this.switchView(targetView);
      });
    });

    // Auth Tab Switchers
    this.tabLoginBtn.addEventListener('click', () => this.switchAuthTab('login'));
    this.tabRegisterBtn.addEventListener('click', () => this.switchAuthTab('register'));

    // Password Visibility Toggle
    document.querySelectorAll('.toggle-password').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        const input = document.getElementById(targetId);
        if (input.type === 'password') {
          input.type = 'text';
          btn.innerHTML = '<i data-lucide="eye-off"></i>';
        } else {
          input.type = 'password';
          btn.innerHTML = '<i data-lucide="eye"></i>';
        }
        if (window.lucide) lucide.createIcons();
      });
    });

    // Auto-fill Demo Account
    this.fillDemoBtn.addEventListener('click', () => {
      this.loginUsernameInput.value = 'admin';
      this.loginPasswordInput.value = 'Admin@123456';
      this.showToast('Demo admin credentials filled!', 'info');
    });

    // Real-time Password Strength Meter
    this.regPasswordInput.addEventListener('input', () => {
      const val = this.regPasswordInput.value;
      if (!val) {
        this.meterFill.style.width = '0%';
        this.meterLabel.textContent = 'None';
        this.meterScore.textContent = '0%';
        return;
      }

      const evalResult = PasswordHasher.evaluateStrength(val);
      this.meterFill.style.width = `${evalResult.score}%`;
      this.meterFill.style.backgroundColor = evalResult.color;
      this.meterLabel.textContent = evalResult.label;
      this.meterLabel.style.color = evalResult.color;
      this.meterScore.textContent = `${evalResult.score}%`;
    });

    // Login Form Submit
    this.loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = this.loginUsernameInput.value.trim();
      const password = this.loginPasswordInput.value;

      const result = await db.authenticateUserParameterized(username, password);
      
      if (!result.success) {
        this.showToast(result.message, 'danger');
        return;
      }

      if (result.requires2FA) {
        this.pending2FAUser = result.user;
        this.modal2FAVerify.classList.add('active');
        this.input2FACode.focus();
        this.showToast('Two-Factor Authentication required.', 'warning');
        return;
      }

      // Successful Login
      this.handleLoginSuccess(result.user, result.session);
    });

    // 2FA Verification Form Submit
    this.form2FAVerify.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!this.pending2FAUser) return;

      const code = this.input2FACode.value.trim();
      const result = await db.verify2FAAndLogin(this.pending2FAUser.id, code);

      if (!result.success) {
        this.showToast(result.message, 'danger');
        return;
      }

      this.modal2FAVerify.classList.remove('active');
      this.input2FACode.value = '';
      this.pending2FAUser = null;
      this.handleLoginSuccess(result.user, result.session);
    });

    // Registration Form Submit
    this.registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = this.regUsernameInput.value.trim();
      const email = this.regEmailInput.value.trim();
      const password = this.regPasswordInput.value;

      const result = await db.registerUser(username, email, password);
      if (!result.success) {
        this.showToast(result.message, 'danger');
        return;
      }

      this.showToast('Registration successful! You can now log in.', 'success');
      this.registerForm.reset();
      this.meterFill.style.width = '0%';
      this.meterLabel.textContent = 'None';
      this.meterScore.textContent = '0%';
      
      this.switchAuthTab('login');
      this.loginUsernameInput.value = username;
      this.loginPasswordInput.focus();
    });

    // Logout Button
    this.logoutHeaderBtn.addEventListener('click', () => {
      this.logout();
    });

    // 2FA Toggle/Setup Button in Dashboard
    this.toggle2FABtn.addEventListener('click', async () => {
      if (!this.currentUser) return;

      if (this.currentUser.is2faEnabled) {
        // Disable 2FA prompt
        const confirmCode = prompt('Enter 6-digit TOTP code to confirm disabling 2FA:');
        if (confirmCode) {
          const res = await db.disable2FA(this.currentUser.id, confirmCode);
          if (res.success) {
            this.currentUser.is2faEnabled = false;
            this.updateDashboard();
            this.showToast('2FA has been disabled.', 'warning');
          } else {
            this.showToast(res.message, 'danger');
          }
        }
      } else {
        // Open 2FA Setup Modal
        const setupData = await db.setup2FA(this.currentUser.id);
        if (setupData) {
          this.setupSecretKey.textContent = setupData.secret;
          QRCode.renderToCanvas(this.qrCanvas, setupData.otpauthURL);
          
          this.setupBackupCodes.innerHTML = setupData.backupCodes
            .map(code => `<span>${code}</span>`)
            .join('');

          this.modal2FASetup.classList.add('active');
          this.setupConfirmCode.focus();
        }
      }
    });

    // Confirm 2FA Setup Form
    this.form2FAConfirm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!this.currentUser) return;

      const code = this.setupConfirmCode.value.trim();
      const res = await db.confirm2FA(this.currentUser.id, code);

      if (!res.success) {
        this.showToast(res.message, 'danger');
        return;
      }

      this.currentUser.is2faEnabled = true;
      this.modal2FASetup.classList.remove('active');
      this.setupConfirmCode.value = '';
      this.updateDashboard();
      this.showToast('Two-Factor Authentication is now active on your account!', 'success');
    });

    // Close 2FA Setup Modal
    this.close2FASetupBtn.addEventListener('click', () => {
      this.modal2FASetup.classList.remove('active');
    });

    // SQLi Sandbox Listeners
    this.runSQLiDemoBtn.addEventListener('click', () => this.runSQLiDemo());
    this.presetSQLiBtn.addEventListener('click', () => {
      this.sqliInputUser.value = "' OR '1'='1";
      this.sqliInputPass.value = "' OR '1'='1";
      this.runSQLiDemo();
    });

    // Refresh Audit Logs
    this.refreshLogsBtn.addEventListener('click', () => {
      this.renderAuditLogs();
      this.showToast('Audit logs refreshed', 'info');
    });
  }

  // --- View & Navigation Management ---
  switchView(viewId) {
    this.navBtns.forEach(b => {
      if (b.getAttribute('data-view') === viewId) {
        b.classList.add('active');
      } else {
        b.classList.remove('active');
      }
    });

    this.viewSections.forEach(sec => {
      if (sec.id === viewId) {
        sec.classList.add('active');
      } else {
        sec.classList.remove('active');
      }
    });

    if (viewId === 'audit-section') {
      this.renderAuditLogs();
    }
    if (viewId === 'dashboard-section') {
      this.updateDashboard();
    }
  }

  switchAuthTab(tab) {
    if (tab === 'login') {
      this.tabLoginBtn.classList.add('active');
      this.tabRegisterBtn.classList.remove('active');
      this.loginForm.style.display = 'block';
      this.registerForm.style.display = 'none';
    } else {
      this.tabRegisterBtn.classList.add('active');
      this.tabLoginBtn.classList.remove('active');
      this.registerForm.style.display = 'block';
      this.loginForm.style.display = 'none';
    }
  }

  // --- Session & Login State ---
  handleLoginSuccess(user, session) {
    this.currentUser = user;
    this.currentSession = session;

    sessionStorage.setItem('CURRENT_USER_ID', user.id);
    sessionStorage.setItem('SESSION_TOKEN', session.token);

    this.userStatusText.textContent = `${user.username} (Authenticated)`;
    this.logoutHeaderBtn.style.display = 'inline-flex';
    this.navDashboardBtn.style.display = 'inline-flex';

    this.showToast(`Welcome back, ${user.username}!`, 'success');
    this.switchView('dashboard-section');
    if (window.lucide) lucide.createIcons();
  }

  checkExistingSession() {
    const userId = sessionStorage.getItem('CURRENT_USER_ID');
    const token = sessionStorage.getItem('SESSION_TOKEN');

    if (userId && token) {
      const data = db.getData();
      const user = data.users.find(u => u.id === userId);
      const session = data.sessions.find(s => s.token === token && s.userId === userId);

      if (user && session && new Date(session.expiresAt) > new Date()) {
        this.handleLoginSuccess(user, session);
      } else {
        this.logout(false);
      }
    }
  }

  logout(showNotice = true) {
    if (this.currentUser && this.currentSession) {
      db.revokeSession(this.currentSession.id, this.currentUser.id);
    }

    this.currentUser = null;
    this.currentSession = null;
    sessionStorage.removeItem('CURRENT_USER_ID');
    sessionStorage.removeItem('SESSION_TOKEN');

    this.userStatusText.textContent = 'Guest Mode';
    this.logoutHeaderBtn.style.display = 'none';
    this.navDashboardBtn.style.display = 'none';

    this.switchView('auth-section');
    if (showNotice) this.showToast('Logged out successfully.', 'info');
  }

  // --- Dashboard Manager ---
  updateDashboard() {
    if (!this.currentUser) return;

    // Refresh user object from storage
    const data = db.getData();
    this.currentUser = data.users.find(u => u.id === this.currentUser.id) || this.currentUser;

    this.dashUsername.textContent = this.currentUser.username;
    this.dashEmail.textContent = this.currentUser.email;

    // Calculate Security Score
    let score = 55;
    if (this.currentUser.is2faEnabled) score += 35;
    if (this.currentUser.passwordHash && this.currentUser.passwordHash.startsWith('$pbkdf2')) score += 10;
    this.dashSecurityScore.textContent = `${score}%`;

    // 2FA status
    if (this.currentUser.is2faEnabled) {
      this.twoFAStatusText.textContent = 'Enabled (Protected with TOTP App)';
      this.twoFAStatusText.style.color = 'var(--success)';
      this.toggle2FABtn.textContent = 'Disable 2FA';
      this.toggle2FABtn.className = 'btn btn-secondary';
    } else {
      this.twoFAStatusText.textContent = 'Disabled (Recommended to enable)';
      this.twoFAStatusText.style.color = 'var(--warning)';
      this.toggle2FABtn.textContent = 'Enable 2FA';
      this.toggle2FABtn.className = 'btn btn-primary';
    }

    // Render Active Sessions
    this.renderActiveSessions();
  }

  renderActiveSessions() {
    if (!this.currentUser) return;
    const sessions = db.getUserActiveSessions(this.currentUser.id);

    if (sessions.length === 0) {
      this.activeSessionsList.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No active sessions found.</div>';
      return;
    }

    this.activeSessionsList.innerHTML = sessions.map(sess => {
      const isCurrent = this.currentSession && this.currentSession.id === sess.id;
      const createdDate = new Date(sess.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      return `
        <div class="session-item">
          <div class="session-info">
            <i data-lucide="laptop" class="session-icon"></i>
            <div>
              <div style="font-weight: 600; font-size: 0.9rem;">
                Windows Workstation ${isCurrent ? '<span class="current-badge">CURRENT SESSION</span>' : ''}
              </div>
              <div class="session-meta">
                IP: <span style="font-family: var(--font-mono);">${sess.ipAddress}</span> • Created: ${createdDate}
              </div>
            </div>
          </div>
          ${!isCurrent ? `
            <button class="btn btn-danger revoke-sess-btn" data-id="${sess.id}" style="width: auto; padding: 0.3rem 0.6rem; font-size: 0.75rem;">
              Revoke
            </button>
          ` : ''}
        </div>
      `;
    }).join('');

    // Attach revoke handlers
    document.querySelectorAll('.revoke-sess-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const sessId = btn.getAttribute('data-id');
        db.revokeSession(sessId, this.currentUser.id);
        this.renderActiveSessions();
        this.showToast('Session revoked instantly.', 'warning');
      });
    });

    if (window.lucide) lucide.createIcons();
  }

  // --- SQL Injection Playground Engine ---
  runSQLiDemo() {
    const userVal = this.sqliInputUser.value;
    const passVal = this.sqliInputPass.value;

    const demo = db.simulateVulnerableSQL(userVal, passVal);

    // Render Vulnerable Result
    if (demo.isBypassed) {
      this.sqliVulnStatus.textContent = 'CRITICAL BYPASS!';
      this.sqliVulnStatus.className = 'badge badge-failed';
      this.sqliVulnConsole.innerHTML = `
<span class="sql-error-highlight">-- VULNERABLE STRING CONCATENATION QUERY --</span>
${demo.rawQuery}

<span class="sql-error-highlight">[SYSTEM EXPLOITED]:</span> SQL syntax alteration detected! 
Password authentication was completely bypassed. 
Database returned <strong>${demo.resultCount} user record(s)</strong> without verifying password hash!
      `.trim();
    } else {
      this.sqliVulnStatus.textContent = 'No Bypass';
      this.sqliVulnStatus.className = 'badge badge-info';
      this.sqliVulnConsole.innerHTML = `
<span class="sql-query-highlight">-- VULNERABLE STRING CONCATENATION QUERY --</span>
${demo.rawQuery}

Result: ${demo.resultCount} matching record(s).
      `.trim();
    }

    // Render Parameterized Safe Result
    this.sqliSafeStatus.textContent = 'PROTECTED (0 Bypassed)';
    this.sqliSafeStatus.className = 'badge badge-success';
    this.sqliSafeConsole.innerHTML = `
<span class="sql-query-highlight">-- PARAMETERIZED PREPARED STATEMENT --</span>
<span class="sql-param-highlight">PREPARE stmt FROM</span> 'SELECT * FROM users WHERE username = ? AND password = ?';
<span class="sql-param-highlight">EXECUTE stmt USING</span> '${userVal.replace(/'/g, "\\'")}', '[HASHED_PASSWORD]';

<span style="color: var(--success);">[SECURITY SYSTEM SAFE]:</span> Query parameter placeholders strictly treat user input as literal scalar text. 
SQL injection control tokens (' OR '1'='1) were ignored.
Returned <strong>0 unauthorized records</strong>.
    `.trim();
  }

  // --- Audit Log Table Viewer ---
  renderAuditLogs() {
    const logs = db.getAuditLogs();

    if (logs.length === 0) {
      this.auditLogsTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No audit log events found.</td></tr>';
      return;
    }

    this.auditLogsTbody.innerHTML = logs.map(log => {
      let badgeClass = 'badge-info';
      if (log.status === 'SUCCESS') badgeClass = 'badge-success';
      if (log.status === 'FAILED' || log.status === 'BLOCKED') badgeClass = 'badge-failed';
      if (log.status === 'WARNING' || log.status === 'PENDING') badgeClass = 'badge-warning';

      const timeStr = new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      return `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${timeStr}</td>
          <td><strong style="color: var(--text-main); font-size: 0.8rem;">${log.action}</strong></td>
          <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--primary);">${log.userId}</td>
          <td><span class="badge ${badgeClass}">${log.status}</span></td>
          <td style="color: var(--text-muted); font-size: 0.85rem;">${log.description}</td>
        </tr>
      `;
    }).join('');
  }

  // --- Toast Notification Manager ---
  showToast(message, type = 'info', duration = 3500) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconName = 'info';
    if (type === 'success') iconName = 'check-circle';
    if (type === 'danger') iconName = 'alert-triangle';
    if (type === 'warning') iconName = 'shield-alert';

    toast.innerHTML = `
      <i data-lucide="${iconName}"></i>
      <span>${message}</span>
    `;

    this.toastContainer.appendChild(toast);
    if (window.lucide) lucide.createIcons();

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
}

// Instantiate application controller on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  window.app = new AppController();
});
