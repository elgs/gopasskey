import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';

const api_url = 'http://localhost:8080/api/passkey/';

customElements.define('web-root',
  class extends LWElement {  // LWElement extends HTMLElement
    constructor() {
      super(ast);
    }

    email = '';
    name = '';
    displayName = '';
    message = '';
    vCode = '';

    async domReady() {
      // console.log('Dom is ready');
      const sid = localStorage.getItem('sid');
      if (sid) {
        await this.private();
      }
    }

    async startSignup() {
      try {
        // Get signup options from your server. Here, we also receive the challenge.
        const response = await fetch(`${api_url}signup_start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email, name: this.name, display_name: this.displayName })
        });

        // Check if the signup options are ok.
        if (!response.ok) {
          const msg = await response.json();
          throw new Error('User already exists or failed to get signup options from server: ' + msg);
        }

        const msg = await response.json();
        this.message = msg;
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async finishSignup() {
      try {
        // Get signup options from your server. Here, we also receive the challenge.
        const response = await fetch(`${api_url}signup_finish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email, code: this.vCode })
        });

        // Check if the signup options are ok.
        if (!response.ok) {
          const msg = await response.json();
          throw new Error('Failed to finish signup on server: ' + msg);
        }

        const msg = await response.json();
        this.message = msg;
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async startLoginWithCode() {
      try {
        // Get login options from your server. Here, we also receive the challenge.
        const response = await fetch(`${api_url}login_with_code_start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email })
        });

        // Check if the login options are ok.
        if (!response.ok) {
          const msg = await response.json();
          throw new Error('Failed to get login options from server: ' + msg);
        }

        const msg = await response.json();
        this.message = msg;
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async finishLoginWithCode() {
      try {
        // Get login options from your server. Here, we also receive the challenge.
        const response = await fetch(`${api_url}login_with_code_finish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email, code: this.vCode })
        });

        // Check if the login options are ok.
        if (!response.ok) {
          const msg = await response.json();
          throw new Error('Failed to finish login with code on server: ' + msg);
        }

        const sid = response.headers.get('sid');
        if (sid) {
          localStorage.setItem('sid', sid);
        }

        const msg = await response.json();
        this.message = msg;
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async registerPasskey() {
      // Retrieve the username from the input field
      try {
        // Get registration options from your server. Here, we also receive the challenge.
        const response = await fetch(`${api_url}register_start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email, name: this.name, display_name: this.displayName })
        });

        // Check if the registration options are ok.
        if (!response.ok) {
          const msg = await response.json();
          throw new Error('User already exists or failed to get registration options from server: ' + msg);
        }

        // read register_sid from response header
        const registerSid = response.headers.get('register_sid');
        if (!registerSid) {
          throw new Error('No register_sid in response header');
        }

        // Convert the registration options to JSON.
        const options = await response.json();

        // This triggers the browser to display the passkey / WebAuthn modal (e.g. Face ID, Touch ID, Windows Hello).
        // A new attestation is created. This also means a new public-private-key pair is created.
        const attestationResponse = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options.publicKey });
        // Send attestationResponse back to server for verification and storage.
        const verificationResponse = await fetch(`${api_url}register_finish`, {
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
      }
    }

    async loginWithPasskey() {
      // Retrieve the username from the input field
      try {
        // Get login options from your server. Here, we also receive the challenge.
        const response = await fetch(`${api_url}login_start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email })
        });
        // Check if the login options are ok.
        if (!response.ok) {
          const msg = await response.json();
          throw new Error('Failed to get login options from server: ' + msg);
        }

        // read login_sid from response header
        const loginSid = response.headers.get('login_sid');
        if (!loginSid) {
          throw new Error('No login_sid in response header');
        }

        // Convert the login options to JSON.
        const options = await response.json();

        // This triggers the browser to display the passkey / WebAuthn modal (e.g. Face ID, Touch ID, Windows Hello).
        // A new assertionResponse is created. This also means that the challenge has been signed.
        const assertionResponse = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options.publicKey });

        // Send assertionResponse back to server for verification.
        const verificationResponse = await fetch(`${api_url}login_finish`, {
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
          this.message = msg;
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async logout() {
      try {
        const sid = localStorage.getItem('sid');
        const response = await fetch(`${api_url}logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'sid': sid }
        });

        const msg = await response.json();
        if (response.ok) {
          localStorage.removeItem('sid');
          this.message = msg;
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async private() {
      try {
        const sid = localStorage.getItem('sid');
        if (!sid) {
          this.message = 'Not logged in';
          return;
        }

        const response = await fetch(`${api_url}private`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json', 'sid': sid }
        });

        const msg = await response.json();
        if (response.ok) {
          this.message = msg;
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }

    async getUserCredentials() {
      try {
        const response = await fetch(`${api_url}credentials`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: this.email })
        });

        const msg = await response.json();
        if (response.ok) {
          this.message = JSON.stringify(msg);
        } else {
          this.message = 'Error: ' + msg;
        }
      } catch (error) {
        this.message = 'Error: ' + error.message;
      }
    }
  }
);
