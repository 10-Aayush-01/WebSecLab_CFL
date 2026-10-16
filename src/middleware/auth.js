'use strict';

/**
 * Authentication / authorization middleware.
 *
 * loadUser       — resolves the session user into res.locals.user (never throws)
 * requireAuth    — every lab route is authenticated in BOTH modes
 * requireAdmin   — dashboard, security events, forensics, mode switching
 */

const { query } = require('../config/db');

/** True when the caller wants JSON rather than an HTML page. */
function wantsJson(req) {
  return req.get('accept') && !req.accepts('html') && Boolean(req.accepts('json'));
}

/**
 * Loads the signed-in user from the session. A database failure must not take
 * the process down, so errors degrade to "signed out".
 */
async function loadUser(req, res, next) {
  res.locals.user = null;

  if (!req.session || !req.session.userId) return next();

  try {
    const { rows } = await query('SELECT id, name, email, role FROM users WHERE id = $1', [
      req.session.userId
    ]);
    if (rows.length === 1) {
      res.locals.user = rows[0];
    } else {
      // The account disappeared underneath the session.
      delete req.session.userId;
    }
  } catch (err) {
    console.error('[auth] could not load user:', err.message);
  }

  return next();
}

/** Blocks anonymous access. Remembers where the user was heading. */
function requireAuth(req, res, next) {
  if (res.locals.user) return next();

  if (wantsJson(req)) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  req.session.returnTo = req.originalUrl;
  return res.redirect('/login');
}

/** Blocks non-admin users (acceptance test §15/3). */
function requireAdmin(req, res, next) {
  if (!res.locals.user) {
    if (wantsJson(req)) return res.status(401).json({ error: 'Authentication required.' });
    req.session.returnTo = req.originalUrl;
    return res.redirect('/login');
  }

  if (res.locals.user.role !== 'ADMIN') {
    if (wantsJson(req)) {
      return res.status(403).json({ error: 'Administrator role required.' });
    }
    return res.status(403).render('errors/error', {
      status: 403,
      title: 'Administrator access required',
      message: 'This area is restricted to administrator accounts. Your account has the USER role.'
    });
  }

  return next();
}

module.exports = { loadUser, requireAuth, requireAdmin, wantsJson };
