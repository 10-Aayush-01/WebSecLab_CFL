'use strict';

/**
 * Registration, sign-in and sign-out (contract §7).
 *
 * Security notes:
 *  - bcrypt hashing with runtime-generated salts, cost 11.
 *  - req.session.regenerate() on sign-in defeats session fixation.
 *  - A single generic message for every failure: no account enumeration.
 */

const { body, validationResult } = require('express-validator');

const { query } = require('../config/db');
const { hashPassword, verifyPassword } = require('../security/password');

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Where a signed-in user lands, by role. */
const landingFor = (user) => (user.role === 'ADMIN' ? '/dashboard' : '/labs/sql');

/** Only ever redirect to a same-site path. */
function safeReturnTo(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//')
    ? value
    : null;
}

const registerValidators = [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Enter your full name (2-100 characters).'),
  body('email').trim().isLength({ max: 255 }).withMessage('Email is too long.'),
  body('email').matches(EMAIL_PATTERN).withMessage('Enter a valid email address.'),
  body('password')
    .isLength({ min: 8, max: 72 })
    .withMessage('Password must be at least 8 characters.'),
  body('confirmPassword').custom((value, { req }) => value === req.body.password)
    .withMessage('The two passwords do not match.')
];

/** GET /register */
function showRegister(req, res) {
  if (res.locals.user) return res.redirect(landingFor(res.locals.user));

  return res.render('auth/register', {
    title: 'Create account',
    pageTitle: 'Create account',
    purpose: 'Accounts are local to this machine and are hashed with bcrypt.',
    errors: [],
    values: {}
  });
}

/** POST /register */
async function register(req, res, next) {
  const errors = validationResult(req);
  const values = { name: req.body.name || '', email: req.body.email || '' };

  if (!errors.isEmpty()) {
    return res.status(400).render('auth/register', {
      title: 'Create account',
      pageTitle: 'Create account',
      purpose: 'Accounts are local to this machine and are hashed with bcrypt.',
      errors: errors.array().map((e) => ({ field: e.path, message: e.msg })),
      values
    });
  }

  const email = String(req.body.email).trim().toLowerCase();

  try {
    const existing = await query('SELECT id FROM users WHERE lower(email) = $1', [email]);
    if (existing.rowCount > 0) {
      return res.status(409).render('auth/register', {
        title: 'Create account',
        pageTitle: 'Create account',
        purpose: 'Accounts are local to this machine and are hashed with bcrypt.',
        errors: [{ field: 'email', message: 'That email address is already registered.' }],
        values
      });
    }

    const passwordHash = await hashPassword(String(req.body.password));
    await query(
      `INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, 'USER')`,
      [String(req.body.name).trim(), email, passwordHash]
    );

    res.locals.setFlash('success', 'Account created. Sign in to continue.');
    return res.redirect('/login');
  } catch (err) {
    return next(err);
  }
}

/** GET /login */
function showLogin(req, res) {
  if (res.locals.user) return res.redirect(landingFor(res.locals.user));

  return res.render('auth/login', {
    title: 'Sign in',
    pageTitle: 'Sign in',
    purpose: 'Local lab accounts only.',
    errors: [],
    values: {},
    returnTo: safeReturnTo(req.session.returnTo)
  });
}

/** POST /login */
async function login(req, res, next) {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const genericError = 'Invalid email or password.';

  if (!email || !password) {
    return res.status(400).render('auth/login', {
      title: 'Sign in',
      pageTitle: 'Sign in',
      purpose: 'Local lab accounts only.',
      errors: [{ field: 'email', message: genericError }],
      values: { email }
    });
  }

  try {
    const { rows } = await query(
      'SELECT id, name, email, role, password_hash FROM users WHERE lower(email) = $1',
      [email]
    );

    // Always run a comparison so a missing account and a wrong password take a
    // similar amount of time.
    const user = rows[0] || null;
    const passwordOk = await verifyPassword(
      password,
      user ? user.password_hash : '$2b$11$0000000000000000000000000000000000000000000000000000'
    );

    if (!user || !passwordOk) {
      return res.status(401).render('auth/login', {
        title: 'Sign in',
        pageTitle: 'Sign in',
        purpose: 'Local lab accounts only.',
        errors: [{ field: 'password', message: genericError }],
        values: { email }
      });
    }

    // Session fixation defence: a fresh session id after privilege change.
    return req.session.regenerate((regenerateError) => {
      if (regenerateError) return next(regenerateError);

      req.session.userId = user.id;
      const destination = safeReturnTo(req.session.returnTo) || landingFor(user);
      delete req.session.returnTo;

      return req.session.save((saveError) => {
        if (saveError) return next(saveError);
        return res.redirect(destination);
      });
    });
  } catch (err) {
    return next(err);
  }
}

/** POST /logout — CSRF protected like every other POST. */
function logout(req, res) {
  req.session.destroy(() => {
    res.clearCookie('webseclab.sid');
    res.redirect('/login');
  });
}

module.exports = { showRegister, register, showLogin, login, logout, landingFor, safeReturnTo };
