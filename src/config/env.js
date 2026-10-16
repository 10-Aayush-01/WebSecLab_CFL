'use strict';

/**
 * Single source of truth for configuration. Validates required variables at
 * startup so a misconfigured .env fails loudly instead of at first request.
 */

require('dotenv').config();

const path = require('path');
const crypto = require('crypto');

const nodeEnv = process.env.NODE_ENV || 'development';
const isProduction = nodeEnv === 'production';

/** Raises a readable error for missing required configuration. */
function required(name, value) {
  if (!value || !String(value).trim()) {
    throw new Error(
      `Missing required environment variable ${name}. Copy .env.example to .env and fill it in.`
    );
  }
  return value;
}

const sessionSecret = process.env.SESSION_SECRET;

if (isProduction && (!sessionSecret || sessionSecret.length < 32)) {
  throw new Error('SESSION_SECRET must be set to at least 32 characters in production.');
}

/**
 * Resolves the listening port.
 *
 * A valid explicit port wins. Anything else — including PORT=0, which some
 * shells and launchers export — falls back to 3000: binding a random port would
 * silently break every documented URL and the Burp walkthrough.
 */
function resolvePort(raw) {
  const parsed = Number.parseInt(raw === undefined ? '' : raw, 10);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535 ? parsed : 3000;
}

/**
 * Share of SAFE-mode attempts in which a control deliberately does not engage,
 * so the audit trail has a realistic tail instead of two possible row shapes.
 * Clamped to 0-1; anything unparseable means off. 0 is the default and the
 * setting the scripted demonstration and the acceptance suite assume.
 */
function resolveRate(raw) {
  const parsed = Number.parseFloat(raw === undefined ? '' : raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return 0;
  return Math.min(1, parsed);
}

const env = {
  nodeEnv,
  isProduction,
  port: resolvePort(process.env.PORT),

  /** Residual-risk outcome model — see src/security/outcomeModel.js. 0 = off. */
  residualRiskRate: resolveRate(process.env.RESIDUAL_RISK_RATE),

  databaseUrl: required('DATABASE_URL', process.env.DATABASE_URL),
  labDatabaseUrl: required('LAB_DATABASE_URL', process.env.LAB_DATABASE_URL),

  /** Superuser URL used only by database/reset.js to create the app roles. */
  adminDatabaseUrl: process.env.ADMIN_DATABASE_URL || '',

  /**
   * Development falls back to a random secret so `npm run dev` works before
   * .env exists; sessions then reset on every restart, which is fine locally.
   */
  sessionSecret: sessionSecret || crypto.randomBytes(32).toString('hex'),

  exportsDir: path.resolve(__dirname, '..', '..', 'exports'),

  seedAdminPassword: process.env.SEED_ADMIN_PASSWORD || 'Admin-Lab-Demo-2026',
  seedUserPassword: process.env.SEED_USER_PASSWORD || 'User-Lab-Demo-2026'
};

module.exports = env;
