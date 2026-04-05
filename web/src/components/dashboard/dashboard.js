import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';
import env from '../../env.js';

customElements.define('web-dashboard',
  class extends LWElement {  // LWElement extends HTMLElement
    constructor() {
      super(ast);
    }

    page = location.hash.slice(1) || 'profile';
    email = '';
    userName = '';
    userDisplayName = '';
    credentials = [];
    credentialsLoaded = false;
    ssoSessions = [];
    sessionsLoaded = false;
    isAdmin = false;
    ssoClients = [];
    clientsLoaded = false;
    users = [];
    usersLoaded = false;
    clientForm = { id: '', client_secret: '', redirect_uri: '', name: '' };
    clientEditMode = false;
    clientDialogTitle = '';
    userForm = { id: '', email: '', name: '', display_name: '', is_active: false, is_admin: false };
    logoutLoading = false;
    profileLoading = false;
    registerLoading = false;
    confirmTitle = '';
    confirmMessage = '';
    confirmAction = '';
    confirmDanger = false;
    _confirmResolve = null;

    navigate(page) {
      this.page = page;
      if (page === 'sessions') {
        this.loadSSOSessions();
      } else if (page === 'clients') {
        this.loadClients();
      } else if (page === 'users') {
        this.loadUsers();
      }
    }

    showToast(text, type = 'success', duration = 3000) {
      const container = this.querySelector('.ui-toast-container');
      const toast = document.createElement('div');
      toast.className = 'ui-toast ' + type;
      toast.innerHTML = `<span class="ui-toast-body">${text}</span><button class="ui-toast-close" onclick="this.parentElement.remove()">&times;</button>`;
      container.appendChild(toast);
      setTimeout(() => toast.remove(), duration);
    }

    onResizeStart(e) {
      e.preventDefault();
      const sidebar = this.querySelector('.sidebar');
      const handle = this.querySelector('.resize-handle');
      handle.classList.add('active');
      const onMove = (e) => {
        const width = Math.min(400, Math.max(140, e.clientX));
        sidebar.style.width = width + 'px';
      };
      const onUp = () => {
        handle.classList.remove('active');
        document.removeEventListener('mousemove', onMove);
        document.removeEventListener('mouseup', onUp);
        localStorage.setItem('sidebar-width', sidebar.style.width);
      };
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
    }

    aaguids = {};

    dataLoaded = false;

    async domReady() {
      const savedWidth = localStorage.getItem('sidebar-width');
      if (savedWidth) this.querySelector('.sidebar').style.width = savedWidth;

      fetch('resources/aaguids.json').then(r => r.json()).then(data => {
        this.aaguids = data;
        this.update();
      });
      await this.loadUserData();
      if (this.page === 'sessions') {
        this.loadSSOSessions();
      } else if (this.page === 'clients' && this.isAdmin) {
        this.loadClients();
      } else if (this.page === 'users' && this.isAdmin) {
        this.loadUsers();
      }
    }

    parseUserAgent(ua) {
      if (!ua) return 'Unknown';
      let os = 'Unknown';
      if (ua.includes('Macintosh')) os = 'macOS';
      else if (ua.includes('Windows')) os = 'Windows';
      else if (ua.includes('Android')) os = 'Android';
      else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
      else if (ua.includes('CrOS')) os = 'ChromeOS';
      else if (ua.includes('Linux')) os = 'Linux';

      let browser = 'Unknown';
      if (ua.includes('Edg/')) browser = 'Edge';
      else if (ua.includes('OPR/') || ua.includes('Opera')) browser = 'Opera';
      else if (ua.includes('Chrome/')) browser = 'Chrome';
      else if (ua.includes('Safari/')) browser = 'Safari';
      else if (ua.includes('Firefox/')) browser = 'Firefox';

      return browser + ' on ' + os;
    }

    aaguidName(aaguid) {
      return this.aaguids[aaguid]?.name || aaguid || '';
    }

    aaguidIcon(aaguid) {
      const info = this.aaguids[aaguid];
      if (!aaguid || !info || !info.icon_ext) return '';
      const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      const suffix = dark ? '_dark' : '';
      return 'resources/aaguid_icons/' + aaguid + suffix + '.' + info.icon_ext;
    }

    async loadUserData() {
      if (this.dataLoaded) return;
      this.dataLoaded = true;
      try {
        const response = await fetch(`${env.apiUrl}me`);

        if (response.ok) {
          const user = await response.json();
          this.email = user.email;
          this.userName = user.name || '';
          this.userDisplayName = user.display_name || '';
          this.isAdmin = !!user.is_admin;
        } else {
          document.cookie = 'sso_logged_in=; Max-Age=0; Path=/';
          this.dispatchEvent(new CustomEvent('logout', { bubbles: true, composed: true }));
          return;
        }
      } catch (error) {
        // Network error during refresh — don't log out, keep current session
        return;
      }
      await this.loadCredentials();
    }

    async loadCredentials() {
      try {
        const response = await fetch(`${env.apiUrl}credentials`);

        if (response.ok) {
          const data = await response.json();
          this.credentials = data || [];
          this.credentialsLoaded = true;
          this.update();
        }
      } catch (error) {
        // silently fail
      }
    }

    showConfirm({ title = 'Confirm', message = '', action = 'Confirm', danger = false } = {}) {
      this.confirmTitle = title;
      this.confirmMessage = message;
      this.confirmAction = action;
      this.confirmDanger = danger;
      this.update();
      const dialog = this.querySelector('.confirm-dialog');
      dialog.showModal();
      return new Promise(resolve => {
        this._confirmResolve = resolve;
      });
    }

    onConfirm(result) {
      const dialog = this.querySelector('.confirm-dialog');
      dialog.close();
      document.activeElement?.blur();
      this.querySelector(':focus')?.blur();
      if (this._confirmResolve) {
        this._confirmResolve(result);
        this._confirmResolve = null;
      }
    }

    async saveProfile() {
      this.profileLoading = true;
      this.update();
      try {
        const response = await fetch(`${env.apiUrl}profile`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: this.userName, display_name: this.userDisplayName })
        });

        const data = await response.json();
        if (response.ok) {
          this.userName = data.name || '';
          this.userDisplayName = data.display_name || '';
          this.showToast('Profile updated');
        } else {
          this.showToast(data, 'danger');
        }
      } catch (error) {
        this.showToast(error.message, 'danger');
      } finally {
        this.profileLoading = false;
      }
    }

    async deleteCredential(credId) {
      const confirmed = await this.showConfirm({
        title: 'Delete Passkey',
        message: 'Are you sure you want to delete this passkey? You will no longer be able to use it to sign in.',
        action: 'Delete',
        danger: true,
      });
      if (!confirmed) return;

      try {
        const response = await fetch(`${env.apiUrl}credentials?id=${encodeURIComponent(credId)}`, {
          method: 'DELETE',
        });

        const msg = await response.json();
        if (response.ok) {
          this.showToast(msg);
          await this.loadCredentials();
        } else {
          this.showToast(msg, 'danger');
        }
      } catch (error) {
        this.showToast(error.message, 'danger');
      }
    }

    async registerPasskey() {
      this.registerLoading = true;
      this.update();
      try {
        const response = await fetch(`${env.pubApiUrl}register_start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email })
        });

        if (!response.ok) {
          const msg = await response.json();
          throw new Error('Failed to get registration options: ' + msg);
        }

        const registerSid = response.headers.get('register_sid');
        if (!registerSid) {
          throw new Error('No register_sid in response header');
        }

        const options = await response.json();

        const attestationResponse = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options.publicKey });
        const verificationResponse = await fetch(`${env.pubApiUrl}register_finish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'register_sid': registerSid },
          body: JSON.stringify(attestationResponse)
        });

        const result = await verificationResponse.json();
        if (!verificationResponse.ok) {
          this.showToast(result, 'danger');
        } else if (result.status === 'duplicate') {
          const confirmed = await this.showConfirm({
            title: 'Replace Passkey',
            message: result.message,
            action: 'Replace',
            danger: true,
          });
          if (confirmed) {
            const confirmResponse = await fetch(`${env.pubApiUrl}register_confirm`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ confirm_token: result.confirm_token })
            });
            const confirmResult = await confirmResponse.json();
            this.showToast(confirmResult.message || confirmResult);
          } else {
            this.showToast('Registration cancelled', 'warning');
          }
          await this.loadCredentials();
        } else {
          this.showToast(result.message || result);
          await this.loadCredentials();
        }
      } catch (error) {
        this.showToast(error.message, 'danger');
      } finally {
        this.registerLoading = false;
      }
    }

    async loadSSOSessions() {
      this.ssoSessions = [];
      this.sessionsLoaded = false;
      this.update();
      try {
        const response = await fetch(`${env.apiUrl}sso/sessions`);

        if (response.ok) {
          const data = await response.json();
          this.ssoSessions = data || [];
          this.sessionsLoaded = true;
          this.update();
        }
      } catch (error) {
        // silently fail
      }
    }

    async revokeSession(token) {
      const confirmed = await this.showConfirm({
        title: 'Kick Out Session',
        message: 'Are you sure you want to revoke this session? The client will be logged out immediately.',
        action: 'Kick Out',
        danger: true,
      });
      if (!confirmed) return;

      try {
        const response = await fetch(`${env.apiUrl}sso/session?token=${encodeURIComponent(token)}`, {
          method: 'DELETE',
        });

        const msg = await response.json();
        if (response.ok) {
          this.showToast(msg);
          await this.loadSSOSessions();
        } else {
          this.showToast(msg, 'danger');
        }
      } catch (error) {
        this.showToast(error.message, 'danger');
      }
    }

    async loadClients() {
      try {
        const response = await fetch(`${env.apiUrl}admin/clients`);
        if (response.ok) {
          this.ssoClients = (await response.json()) || [];
          this.clientsLoaded = true;
          this.update();
        }
      } catch (e) {}
    }

    openClientDialog(client) {
      if (client) {
        this.clientForm = { id: client.id, client_secret: client.client_secret, redirect_uri: client.redirect_uri, name: client.name || '' };
        this.clientEditMode = true;
        this.clientDialogTitle = 'Edit Client';
      } else {
        this.clientForm = { id: '', client_secret: '', redirect_uri: '', name: '' };
        this.clientEditMode = false;
        this.clientDialogTitle = 'Add Client';
      }
      this.update();
      this.querySelector('.client-dialog').showModal();
    }

    closeClientDialog() {
      this.querySelector('.client-dialog').close();
    }

    async saveClient() {
      const url = this.clientEditMode
        ? `${env.apiUrl}admin/client?id=${encodeURIComponent(this.clientForm.id)}`
        : `${env.apiUrl}admin/clients`;
      const method = this.clientEditMode ? 'PUT' : 'POST';
      try {
        const response = await fetch(url, {
          method,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.clientForm),
        });
        const msg = await response.json();
        if (response.ok) {
          this.closeClientDialog();
          this.showToast(msg);
          await this.loadClients();
        } else {
          this.showToast(msg, 'danger');
        }
      } catch (e) {
        this.showToast(e.message, 'danger');
      }
    }

    async deleteClient(clientID) {
      const confirmed = await this.showConfirm({
        title: 'Delete Client',
        message: `Delete SSO client "${clientID}"? Existing sessions will continue until they expire.`,
        action: 'Delete',
        danger: true,
      });
      if (!confirmed) return;
      try {
        const response = await fetch(`${env.apiUrl}admin/client?id=${encodeURIComponent(clientID)}`, { method: 'DELETE' });
        const msg = await response.json();
        if (response.ok) {
          this.showToast(msg);
          await this.loadClients();
        } else {
          this.showToast(msg, 'danger');
        }
      } catch (e) {
        this.showToast(e.message, 'danger');
      }
    }

    async loadUsers() {
      try {
        const response = await fetch(`${env.apiUrl}admin/users`);
        if (response.ok) {
          this.users = (await response.json()) || [];
          this.usersLoaded = true;
          this.update();
        }
      } catch (e) {}
    }

    openUserDialog(user) {
      this.userForm = {
        id: user.id,
        email: user.email,
        name: user.name || '',
        display_name: user.display_name || '',
        is_active: !!user.is_active,
        is_admin: !!user.is_admin,
      };
      this.update();
      this.querySelector('.user-dialog').showModal();
    }

    closeUserDialog() {
      this.querySelector('.user-dialog').close();
    }

    async saveUser() {
      try {
        const response = await fetch(`${env.apiUrl}admin/user?id=${encodeURIComponent(this.userForm.id)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: this.userForm.name,
            display_name: this.userForm.display_name,
            is_active: this.userForm.is_active,
            is_admin: this.userForm.is_admin,
          }),
        });
        const msg = await response.json();
        if (response.ok) {
          this.closeUserDialog();
          this.showToast(msg);
          await this.loadUsers();
        } else {
          this.showToast(msg, 'danger');
        }
      } catch (e) {
        this.showToast(e.message, 'danger');
      }
    }

    async deleteUser(user) {
      const confirmed = await this.showConfirm({
        title: 'Delete User',
        message: `Delete user "${user.email}"? This is a soft delete — the account will be marked inactive.`,
        action: 'Delete',
        danger: true,
      });
      if (!confirmed) return;
      try {
        const response = await fetch(`${env.apiUrl}admin/user?id=${encodeURIComponent(user.id)}`, { method: 'DELETE' });
        const msg = await response.json();
        if (response.ok) {
          this.showToast(msg);
          await this.loadUsers();
        } else {
          this.showToast(msg, 'danger');
        }
      } catch (e) {
        this.showToast(e.message, 'danger');
      }
    }

    async logout() {
      this.logoutLoading = true;
      this.update();
      try {
        const response = await fetch(`${env.apiUrl}logout`, {
          method: 'POST',
        });

        const msg = await response.json();
        if (response.ok) {
          this.dispatchEvent(new CustomEvent('logout', { bubbles: true, composed: true }));
        } else {
          this.showToast(msg, 'danger');
        }
      } catch (error) {
        this.showToast(error.message, 'danger');
      } finally {
        this.logoutLoading = false;
      }
    }
  }
);
