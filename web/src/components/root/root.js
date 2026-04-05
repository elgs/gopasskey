import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';

customElements.define('web-root',
  class extends LWElement {  // LWElement extends HTMLElement
    constructor() {
      super(ast);
    }

    loggedIn = document.cookie.includes('sso_logged_in=');

    onLogin() {
      this.loggedIn = true;
      this.querySelector('web-dashboard')?.loadUserData();
    }

    onLogout() {
      this.loggedIn = false;
    }
  }
);
