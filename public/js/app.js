'use strict';

/**
 * Shared UI behaviour. Everything is wired through data-attributes so the
 * markup stays declarative and there is no inline script anywhere in the app
 * (the Content-Security-Policy forbids it outside the XSS lab).
 *
 *   data-dismiss            close the nearest .ws-banner (flash messages)
 *   data-copy="<selector>"  copy that element's text, or its own if absent
 *   data-fill-user / data-fill-pass   demo credentials → the sign-in form
 *   data-confirm="<text>"   confirm() before the enclosing form submits
 *   data-nav-close          close the mobile navigation drawer
 *
 * The navigation drawer is progressive enhancement: the sidebar is plain markup
 * in the document, and below 900px the CSS parks it off-canvas. Without this
 * script the nav is still reachable through the skip link and the normal tab
 * order once the drawer is opened, so nothing is trapped behind JavaScript.
 */

(function () {
  function onReady(callback) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', callback);
    } else {
      callback();
    }
  }

  /** Dismissible flash messages. */
  function initDismiss() {
    document.querySelectorAll('[data-dismiss]').forEach((button) => {
      button.addEventListener('click', () => {
        const target = button.closest('.ws-banner');
        if (target) target.remove();
      });
    });
  }

  /** Copy-to-clipboard for payloads and hashes. */
  function initCopy() {
    document.querySelectorAll('[data-copy]').forEach((button) => {
      button.addEventListener('click', async () => {
        const selector = button.getAttribute('data-copy');
        const source = selector ? document.querySelector(selector) : button;
        if (!source) return;

        const text = 'value' in source && source.value ? source.value : source.textContent || '';
        const label = button.textContent;

        try {
          await copyText(text.trim());
          button.classList.add('is-copied');
          button.textContent = 'Copied';
          window.setTimeout(() => {
            button.classList.remove('is-copied');
            button.textContent = label;
          }, 1400);
        } catch {
          button.textContent = 'Copy failed';
          window.setTimeout(() => {
            button.textContent = label;
          }, 1400);
        }
      });
    });
  }

  /** navigator.clipboard with a legacy fallback (localhost counts as secure). */
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise((resolve, reject) => {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', 'readonly');
      area.style.position = 'fixed';
      area.style.top = '-1000px';
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand('copy');
        resolve();
      } catch (error) {
        reject(error);
      } finally {
        document.body.removeChild(area);
      }
    });
  }

  /** One-click demo credentials on the sign-in page. */
  function initDemoFill() {
    document.querySelectorAll('[data-fill-user]').forEach((button) => {
      button.addEventListener('click', () => {
        const email = document.getElementById('email');
        const password = document.getElementById('password');
        if (email) email.value = button.getAttribute('data-fill-user') || '';
        if (password) password.value = button.getAttribute('data-fill-pass') || '';
        if (password) password.focus();
      });
    });
  }

  /** Confirmation for consequential submits (mode switch, sign out). */
  function initConfirm() {
    document.querySelectorAll('form[data-confirm]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        if (!window.confirm(form.getAttribute('data-confirm'))) {
          event.preventDefault();
        }
      });
    });
  }

  /**
   * Mobile navigation drawer.
   *
   * Open state lives on <body> so the CSS owns the animation; this only flips
   * the class, keeps aria-expanded honest, traps nothing (Escape, the backdrop
   * and the close button all work) and returns focus to the toggle.
   */
  function initNavDrawer() {
    const toggle = document.getElementById('ws-nav-toggle');
    const drawer = document.getElementById('ws-sidebar');
    if (!toggle || !drawer) return;

    const desktop = window.matchMedia('(min-width: 901px)');

    function isOpen() {
      return document.body.classList.contains('ws-nav-open');
    }

    function open() {
      document.body.classList.add('ws-nav-open');
      toggle.setAttribute('aria-expanded', 'true');
      const firstLink = drawer.querySelector('.ws-nav__link');
      if (firstLink) firstLink.focus({ preventScroll: true });
    }

    function close(restoreFocus) {
      if (!isOpen()) return;
      document.body.classList.remove('ws-nav-open');
      toggle.setAttribute('aria-expanded', 'false');
      if (restoreFocus) toggle.focus({ preventScroll: true });
    }

    toggle.addEventListener('click', () => (isOpen() ? close(false) : open()));

    document.querySelectorAll('[data-nav-close]').forEach((element) => {
      element.addEventListener('click', () => close(true));
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') close(true);
    });

    // Following a link loads a new page, but close anyway so the drawer never
    // appears to be stuck open when a navigation is intercepted or slow.
    drawer.addEventListener('click', (event) => {
      if (event.target.closest('a[href]')) close(false);
    });

    // Grow past the breakpoint while the drawer is open: drop the state, or the
    // body would stay scroll-locked on a layout that has no drawer.
    const onBreakpoint = () => {
      if (desktop.matches) close(false);
    };
    if (typeof desktop.addEventListener === 'function') {
      desktop.addEventListener('change', onBreakpoint);
    } else if (typeof desktop.addListener === 'function') {
      desktop.addListener(onBreakpoint);
    }
  }

  onReady(() => {
    initDismiss();
    initCopy();
    initDemoFill();
    initConfirm();
    initNavDrawer();
  });
})();
