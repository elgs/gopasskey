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
    messageType = '';
    emailLoading = false;
    passkeyLoading = false;

    async domReady() {
      this.savedEmail = localStorage.getItem('savedEmail') || '';
      if (this.savedEmail) {
        this.email = this.savedEmail;
        this.rememberMe = true;
      }

    }

    _handleSSORedirect() {
      const clientId = sessionStorage.getItem('sso_client_id');
      if (!clientId) return false;

      const redirectUri = sessionStorage.getItem('sso_redirect_uri') || '';
      const state = sessionStorage.getItem('sso_state') || '';

      sessionStorage.removeItem('sso_client_id');
      sessionStorage.removeItem('sso_redirect_uri');
      sessionStorage.removeItem('sso_state');

      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        state: state,
      });
      window.location.href = `/api/pub/sso/authorize?${params.toString()}`;
      return true;
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
        if (this.savedEmail) {
          await this.loginWithPasskey();
        } else {
          await this.loginWithEmail();
        }
      }
    }

    setMessage(text, type = '') {
      this.message = text;
      this.messageType = type;
    }

    async loginWithEmail() {
      if (!this.email) {
        this.setMessage('Please enter your email', 'danger');
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
          this.setMessage(msg);
        } else {
          this.setMessage(msg, 'danger');
        }
      } catch (error) {
        this.setMessage(error.message, 'danger');
      } finally {
        this.emailLoading = false;
      }
    }

    async loginWithPasskey() {
      if (!this.email) {
        this.setMessage('Please enter your email', 'danger');
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

        const msg = await verificationResponse.json();
        if (verificationResponse.ok) {
          this.saveEmailIfRemembered();
          if (this._handleSSORedirect()) return;
          this.dispatchEvent(new CustomEvent('login', { bubbles: true, composed: true }));
        } else {
          this.setMessage(msg, 'danger');
        }
      } catch (error) {
        this.setMessage(error.message, 'danger');
      } finally {
        this.passkeyLoading = false;
      }
    }
  }
);
