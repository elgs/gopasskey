import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';
import env from '../../env.js';

customElements.define('web-root',
  class extends LWElement {  // LWElement extends HTMLElement
    constructor() {
      super(ast);
    }

    email = '';
    userName = '';
    userDisplayName = '';
    message = '';
    loggedIn = false;
    credentials = [];
    emailLoading = false;
    passkeyLoading = false;
    registerLoading = false;
    logoutLoading = false;
    profileLoading = false;
    confirmTitle = '';
    confirmMessage = '';
    confirmAction = '';
    confirmDanger = false;
    _confirmResolve = null;

    async domReady() {
      const urlParams = new URLSearchParams(window.location.search);
      const sid = urlParams.get('sid');
      if (sid) {
        localStorage.setItem('sid', sid);
        window.history.replaceState({}, document.title, '/');
      }

      const storedSid = localStorage.getItem('sid');
      if (storedSid) {
        await this.checkSession();
      }
    }

    async checkSession() {
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
          this.loggedIn = true;
          this.message = `Logged in as ${user.email}`;
          await this.loadCredentials();
        } else {
          localStorage.removeItem('sid');
          this.loggedIn = false;
        }
      } catch (error) {
        localStorage.removeItem('sid');
        this.loggedIn = false;
      }
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
      const dialog = this.shadowRoot.querySelector('.confirm-dialog');
      dialog.showModal();
      return new Promise(resolve => {
        this._confirmResolve = resolve;
      });
    }

    onConfirm(result) {
      const dialog = this.shadowRoot.querySelector('.confirm-dialog');
      dialog.close();
      document.activeElement?.blur();
      this.shadowRoot.activeElement?.blur();
      if (this._confirmResolve) {
        this._confirmResolve(result);
        this._confirmResolve = null;
      }
    }

    async onEmailKeydown(event) {
      if (event.key === 'Enter') {
        await this.loginWithEmail();
      }
    }

    async loginWithEmail() {
      if (!this.email) {
        this.message = 'Please enter your email';
        return;
      }

      this.emailLoading = true;
      this.update();
      try {
        const response = await fetch(`${env.pubApiUrl}login_start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email })
        });

        const msg = await response.json();
        if (response.ok) {
          this.message = msg;
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      } finally {
        this.emailLoading = false;
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

    async loginWithPasskey() {
      if (!this.email) {
        this.message = 'Please enter your email';
        return;
      }

      this.passkeyLoading = true;
      this.update();
      try {
        const response = await fetch(`${env.pubApiUrl}passkey_login_start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email })
        });

        if (!response.ok) {
          const msg = await response.json();
          throw new Error('Failed to get login options: ' + msg);
        }

        const loginSid = response.headers.get('login_sid');
        if (!loginSid) {
          throw new Error('No login_sid in response header');
        }

        const options = await response.json();

        const assertionResponse = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options.publicKey });

        const verificationResponse = await fetch(`${env.pubApiUrl}passkey_login_finish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'login_sid': loginSid },
          body: JSON.stringify(assertionResponse)
        });

        const sid = verificationResponse.headers.get('sid');
        if (sid) {
          localStorage.setItem('sid', sid);
        }

        const msg = await verificationResponse.json();
        if (verificationResponse.ok) {
          this.loggedIn = true;
          this.message = msg;
          await this.checkSession();
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      } finally {
        this.passkeyLoading = false;
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
          this.loggedIn = false;
          this.email = '';
          this.userName = '';
          this.userDisplayName = '';
          this.credentials = [];
          this.message = msg;
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
