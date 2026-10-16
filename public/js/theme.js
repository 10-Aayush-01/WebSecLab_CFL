'use strict';

/**
 * Theme toggle: light / dark / system.
 *
 * The server already rendered the correct theme from the `ws_theme` cookie, so
 * this script never fights the first paint — it only:
 *   1. syncs the segmented control with the stored choice,
 *   2. writes the cookie and flips the attribute when the user picks a theme,
 *   3. re-applies "system" when the OS preference changes,
 *   4. announces the change on the `themechange` event so charts (and anything
 *      else that cannot be styled with CSS variables) can restyle themselves.
 */

(function () {
  const COOKIE = 'ws_theme';
  const CHOICES = ['light', 'dark', 'system'];
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: dark)');

  function readChoice() {
    const match = document.cookie.match(/(?:^|;\s*)ws_theme=([^;]*)/);
    const value = match ? decodeURIComponent(match[1]) : null;
    return CHOICES.includes(value) ? value : 'system';
  }

  function writeChoice(choice) {
    // Readable by the server on the next request; not httpOnly by design.
    document.cookie = `${COOKIE}=${encodeURIComponent(choice)}; path=/; max-age=31536000; samesite=lax`;
  }

  /** The theme actually painted right now. */
  function effectiveTheme(choice) {
    return choice === 'system' ? (media.matches ? 'dark' : 'light') : choice;
  }

  function syncControls(choice) {
    document.querySelectorAll('[data-theme-choice]').forEach((button) => {
      const isActive = button.getAttribute('data-theme-choice') === choice;
      button.classList.toggle('is-active', isActive);
      button.setAttribute('aria-pressed', String(isActive));
    });
  }

  function apply(choice, persist) {
    if (choice === 'system') {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', choice);
    }

    if (persist) writeChoice(choice);
    syncControls(choice);

    window.dispatchEvent(
      new CustomEvent('themechange', { detail: { choice, theme: effectiveTheme(choice) } })
    );
  }

  function init() {
    const choice = readChoice();
    syncControls(choice);

    document.querySelectorAll('[data-theme-choice]').forEach((button) => {
      button.addEventListener('click', () => apply(button.getAttribute('data-theme-choice'), true));
    });

    // Keep "system" live if the OS switches while the page is open.
    const onSystemChange = () => {
      if (readChoice() === 'system') apply('system', false);
    };
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', onSystemChange);
    } else if (typeof media.addListener === 'function') {
      media.addListener(onSystemChange);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
