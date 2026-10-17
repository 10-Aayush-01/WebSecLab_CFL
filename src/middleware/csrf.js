'use strict';

/**
 * CSRF protection (contract §7): a per-session random token, submitted either as
 * the hidden `_csrf` form field or the `x-csrf-token` header (used by the JSON
 * evidence-verification request).
 *
 * Checked on EVERY unsafe method, including logout and the mode switch.
 * SameSite=Lax on the session cookie is the second layer.
 */

const crypto = require('crypto');

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/** Constant-time string comparison that tolerates unequal lengths. */
function safeEqual(a, b) {
  const bufferA = Buffer.from(String(a));
  const bufferB = Buffer.from(String(b));
  if (bufferA.length !== bufferB.length || bufferA.length === 0) return false;
  return crypto.timingSafeEqual(bufferA, bufferB);
}

/** Ensures a token exists for this session and exposes it to the views. */
function csrfToken(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  return next();
}

/** Rejects unsafe requests without a matching token. */
function verifyCsrf(req, res, next) {
  if (!UNSAFE_METHODS.has(req.method)) return next();

  const presented = (req.body && req.body._csrf) || req.get('x-csrf-token') || '';
  const expected = (req.session && req.session.csrfToken) || '';

  if (!safeEqual(presented, expected)) {
    console.warn(
      `[csrf] rejected ${req.method} ${req.originalUrl} (token ${expected ? 'mismatch' : 'missing'})`
    );
    return res.status(403).render('errors/error', {
      status: 403,
      title: 'Request rejected',
      message:
        'The security token for this form was missing or did not match your session. ' +
        'Reload the page and try again.'
    });
  }

  return next();
}

module.exports = { csrfToken, verifyCsrf, safeEqual };
