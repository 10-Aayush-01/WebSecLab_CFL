'use strict';

/**
 * Rate limiting (contract §7).
 *
 * Auth routes only. /labs/* is deliberately NOT limited: Burp Repeater and
 * Intruder loops would trip the limiter and break the lab demonstrations.
 */

const rateLimit = require('express-rate-limit');

/** Renders the shared error page for a throttled request. */
function tooManyRequestsHandler(message) {
  return (req, res) => {
    res.status(429).render('errors/error', {
      status: 429,
      title: 'Too many attempts',
      message
    });
  };
}

/** Login: only failed attempts count, so normal use is never blocked. */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: tooManyRequestsHandler(
    'Too many failed sign-in attempts. Wait 15 minutes and try again.'
  )
});

/** Registration: creates accounts, so every attempt counts. */
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: tooManyRequestsHandler(
    'Too many accounts created from this address. Wait 15 minutes and try again.'
  )
});

module.exports = { loginLimiter, registerLimiter };
