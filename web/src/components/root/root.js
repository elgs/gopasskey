import LWElement from './../../lib/lw-element.js';
import ast from './ast.js';

customElements.define('web-root',
  class extends LWElement {  // LWElement extends HTMLElement
    constructor() {
      super(ast);
    }

    update() {
      // no-op: prevents TreeWalker from entering child components
    }

    domReady() {
      this.loginEl = document.createElement('web-login');
      this.dashboardEl = document.createElement('web-dashboard');

      this.loginEl.addEventListener('login', () => this.showDashboard());
      this.dashboardEl.addEventListener('logout', () => this.showLogin());

      if (localStorage.getItem('sid')) {
        this.showDashboard();
      } else {
        this.showLogin();
      }
    }

    showLogin() {
      this.dashboardEl.remove();
      this.appendChild(this.loginEl);
    }

    showDashboard() {
      this.loginEl.remove();
      this.appendChild(this.dashboardEl);
    }
  }
);
