'use strict';

/**
 * Theme preference (light / dark / system).
 *
 * This is an interface preference, not a secret, so it is stored in a normal
 * cookie that the browser may read and write directly. Reading it server-side
 * lets the first paint already carry the right `data-theme` attribute, which is
 * what removes the flash of the wrong theme — and it means no inline script is
 * needed, so the strict Content-Security-Policy stays intact.
 *
 * `system` deliberately renders NO data-theme attribute: the OS preference is
 * then resolved by the CSS media query in public/css/tokens.css.
 */

const THEME_COOKIE = 'ws_theme';
const THEMES = Object.freeze(['light', 'dark', 'system']);
const DEFAULT_THEME = 'system';

/**
 * Minimal cookie reader — avoids adding cookie-parser for a single value.
 * @param {string|undefined} header raw Cookie header
 * @param {string} name
 * @returns {string|null}
 */
function readCookie(header, name) {
  if (!header) return null;

  for (const part of String(header).split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    if (part.slice(0, index).trim() === name) {
      try {
        return decodeURIComponent(part.slice(index + 1).trim());
      } catch {
        return null;
      }
    }
  }
  return null;
}

/**
 * Exposes the visitor's theme choice to every template.
 * @type {import('express').RequestHandler}
 */
function loadTheme(req, res, next) {
  const stored = readCookie(req.headers.cookie, THEME_COOKIE);
  const choice = THEMES.includes(stored) ? stored : DEFAULT_THEME;

  res.locals.themeChoice = choice;
  // Empty string means "let the media query decide".
  res.locals.themeAttribute = choice === DEFAULT_THEME ? '' : choice;

  return next();
}

module.exports = { loadTheme, readCookie, THEME_COOKIE, THEMES, DEFAULT_THEME };
