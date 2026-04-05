import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';

customElements.define('web-root',
  class extends LWElement {  // LWElement extends HTMLElement
    loggedIn = document.cookie.includes('sso_logged_in=');

    constructor() {
      super(ast);
      // If SSO params are in URL, store them for later use
      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('sso_client_id')) {
        sessionStorage.setItem('sso_client_id', urlParams.get('sso_client_id'));
        sessionStorage.setItem('sso_redirect_uri', urlParams.get('sso_redirect_uri') || '');
        sessionStorage.setItem('sso_state', urlParams.get('sso_state') || '');
      }
      // If logged in AND SSO params are present, redirect to /authorize immediately
      if (this.loggedIn && sessionStorage.getItem('sso_client_id')) {
        const params = new URLSearchParams({
          client_id: sessionStorage.getItem('sso_client_id'),
          redirect_uri: sessionStorage.getItem('sso_redirect_uri') || '',
          state: sessionStorage.getItem('sso_state') || '',
        });
        sessionStorage.removeItem('sso_client_id');
        sessionStorage.removeItem('sso_redirect_uri');
        sessionStorage.removeItem('sso_state');
        window.location.href = `/api/pub/sso/authorize?${params.toString()}`;
      }
    }

    onLogin() {
      this.loggedIn = true;
      this.querySelector('web-dashboard')?.loadUserData();
    }

    onLogout() {
      this.loggedIn = false;
    }
  }
);
