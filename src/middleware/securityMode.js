'use strict';

/**
 * Global security mode (contract §1).
 *
 * The mode lives in the single-row app_settings table and is read on EVERY
 * request. That is a deliberate choice: caching it per process makes the admin
 * switch look ignored, and one indexed single-row read is negligible.
 *
 * On any failure the mode falls back to SAFE — we fail closed.
 */

const { query } = require('../config/db');
const env = require('../config/env');
const outcomeModel = require('../security/outcomeModel');

const MODES = Object.freeze(['SAFE', 'VULNERABLE']);
const DEFAULT_MODE = 'SAFE';

/** Loads the current mode into res.locals for views and the monitor. */
async function loadSecurityMode(req, res, next) {
  res.locals.securityMode = DEFAULT_MODE;

  try {
    const { rows } = await query('SELECT security_mode FROM app_settings WHERE id = 1');
    if (rows.length === 1 && MODES.includes(rows[0].security_mode)) {
      res.locals.securityMode = rows[0].security_mode;
    }
  } catch (err) {
    console.error('[mode] could not read app_settings, defaulting to SAFE:', err.message);
  }

  res.locals.isVulnerable = res.locals.securityMode === 'VULNERABLE';

  // Views and the events page report whether the residual-risk model is on: an
  // event that succeeded in SAFE mode needs that context to read correctly.
  res.locals.residualRiskRate = env.residualRiskRate;
  res.locals.residualRiskEnabled = outcomeModel.isEnabled(env.residualRiskRate);
  return next();
}

/**
 * Switches the global mode (ADMIN only, POST + CSRF protected by the route).
 *
 * @param {'VULNERABLE'|'SAFE'} nextMode
 * @param {number} userId
 * @returns {Promise<'VULNERABLE'|'SAFE'>} the mode now in effect
 */
async function setSecurityMode(nextMode, userId) {
  if (!MODES.includes(nextMode)) {
    throw new Error(`Unknown security mode: ${nextMode}`);
  }

  const { rows } = await query(
    `UPDATE app_settings
        SET security_mode = $1, updated_by = $2, updated_at = now()
      WHERE id = 1
      RETURNING security_mode`,
    [nextMode, userId]
  );

  return rows[0].security_mode;
}

module.exports = { loadSecurityMode, setSecurityMode, MODES, DEFAULT_MODE };
