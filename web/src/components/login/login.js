import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';
import env from '../../env.js';

customElements.define('web-login',
  class extends LWElement {  // LWElement extends HTMLElement
    constructor() {
      super(ast);
    }

    email = '';
    savedEmail = '';
    rememberMe = false;
    message = '';
    emailLoading = false;
    passkeyLoading = false;

    async domReady() {
      this.savedEmail = localStorage.getItem('savedEmail') || '';
      if (this.savedEmail) {
        this.email = this.savedEmail;
        this.rememberMe = true;
      }

      const urlParams = new URLSearchParams(window.location.search);
      const sid = urlParams.get('sid');
      if (sid) {
        localStorage.setItem('sid', sid);
        window.history.replaceState({}, document.title, '/');
        this.dispatchEvent(new CustomEvent('login', { bubbles: true, composed: true }));
        return;
      }

      const storedSid = localStorage.getItem('sid');
      if (storedSid) {
        this.dispatchEvent(new CustomEvent('login', { bubbles: true, composed: true }));
      }
    }

    onRememberMeChange() {
      if (!this.rememberMe) {
        localStorage.removeItem('savedEmail');
        this.savedEmail = '';
        this.email = '';
      }
    }

    saveEmailIfRemembered() {
      if (this.rememberMe) {
        localStorage.setItem('savedEmail', this.email);
        this.savedEmail = this.email;
      } else {
        localStorage.removeItem('savedEmail');
        this.savedEmail = '';
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
          this.saveEmailIfRemembered();
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
          this.saveEmailIfRemembered();
          this.dispatchEvent(new CustomEvent('login', { bubbles: true, composed: true }));
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      } finally {
        this.passkeyLoading = false;
      }
    }
  }
);
