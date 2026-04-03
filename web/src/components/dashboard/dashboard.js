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
    message = '';
    credentials = [];
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
    }

    aaguids = {};

    async domReady() {
      fetch('resources/aaguids.json').then(r => r.json()).then(data => {
        this.aaguids = data;
        this.update();
      });
      await this.loadUserData();
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
      try {
        const sid = localStorage.getItem('sid');
        if (!sid) return;

        const response = await fetch(`${env.apiUrl}me`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json', 'sid': sid }
        });

        if (response.ok) {
          const user = await response.json();
          this.email = user.email;
          this.userName = user.name || '';
          this.userDisplayName = user.display_name || '';
        } else {
          localStorage.removeItem('sid');
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
        const sid = localStorage.getItem('sid');
        if (!sid) return;

        const response = await fetch(`${env.apiUrl}credentials`, {
          headers: { 'Content-Type': 'application/json', 'sid': sid }
        });

        if (response.ok) {
          const data = await response.json();
          this.credentials = data || [];
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
        const sid = localStorage.getItem('sid');
        const response = await fetch(`${env.apiUrl}profile`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'sid': sid },
          body: JSON.stringify({ name: this.userName, display_name: this.userDisplayName })
        });

        const data = await response.json();
        if (response.ok) {
          this.userName = data.name || '';
          this.userDisplayName = data.display_name || '';
          this.message = 'Profile updated';
        } else {
          this.message = 'Error: ' + data;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
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
        const sid = localStorage.getItem('sid');
        const response = await fetch(`${env.apiUrl}credentials?id=${encodeURIComponent(credId)}`, {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json', 'sid': sid }
        });

        const msg = await response.json();
        if (response.ok) {
          this.message = msg;
          await this.loadCredentials();
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async registerPasskey() {
      const sid = localStorage.getItem('sid');
      if (!sid) {
        this.message = 'Not logged in';
        return;
      }

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
          this.message = 'Error: ' + result;
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
            this.message = confirmResult.message || confirmResult;
          } else {
            this.message = 'Registration cancelled';
          }
          await this.loadCredentials();
        } else {
          this.message = result.message || result;
          await this.loadCredentials();
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      } finally {
        this.registerLoading = false;
      }
    }

    async logout() {
      this.logoutLoading = true;
      this.update();
      try {
        const sid = localStorage.getItem('sid');
        const response = await fetch(`${env.apiUrl}logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'sid': sid }
        });

        const msg = await response.json();
        if (response.ok) {
          localStorage.removeItem('sid');
          this.dispatchEvent(new CustomEvent('logout', { bubbles: true, composed: true }));
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      } finally {
        this.logoutLoading = false;
      }
    }
  }
);
