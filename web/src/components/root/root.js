import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';
import env from '../../env.js';

customElements.define('web-root',
  class extends LWElement {  // LWElement extends HTMLElement
    constructor() {
      super(ast);
    }

    email = '';
    message = '';
    loggedIn = false;
    emailLoading = false;
    passkeyLoading = false;
    registerLoading = false;
    logoutLoading = false;

    async domReady() {
      // Check for sid in URL query params (from magic link redirect)
      const urlParams = new URLSearchParams(window.location.search);
      const sid = urlParams.get('sid');
      if (sid) {
        localStorage.setItem('sid', sid);
        // Clean the URL
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
          this.loggedIn = true;
          this.message = `Logged in as ${user.email}`;
        } else {
          localStorage.removeItem('sid');
          this.loggedIn = false;
        }
      } catch (error) {
        localStorage.removeItem('sid');
        this.loggedIn = false;
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

        const msg = await verificationResponse.json();
        if (verificationResponse.ok) {
          this.message = msg;
        } else {
          this.message = 'Error: ' + msg;
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
