'use strict';

/**
 * Content-Security-Policy override for the XSS lab (contract §11 traps).
 *
 * app.js installs a strict CSP globally. Strict CSP blocks inline <script> and
 * inline event handlers, which would silently break the stored-XSS
 * demonstration — a trap that makes the lab look broken.
 *
 * This middleware runs AFTER loadSecurityMode and re-sets the CSP header for
 * /labs/xss* ONLY, and ONLY while the global mode is VULNERABLE. Headers are not
 * flushed until the response body is sent, so replacing the header here works.
 *
 * It is also where the residual-risk draw for this request is taken. The policy
 * has to be settled before the controller renders the comment, and it has to be
 * the SAME draw the controller acts on — so the decision is shared through
 * res.locals rather than taken twice (see src/security/outcomeModel.js).
 */

const helmet = require('helmet');

const outcomeModel = require('../security/outcomeModel');

/** Relaxed policy: inline script and inline attributes allowed (lab only). */
const relaxedXssPolicy = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'script-src': ["'self'", "'unsafe-inline'"],
      'script-src-attr': ["'unsafe-inline'"],
      // Local http demo: never force https upgrades.
      upgradeInsecureRequests: null
    }
  }
});

/**
 * Applied to the /labs/xss mount point. In SAFE mode it is a no-op, so the
 * strict policy from app.js stays in force (acceptance test §15/11).
 */
function xssLabCspOverride(req, res, next) {
  const mode = res.locals.securityMode === 'VULNERABLE' ? 'VULNERABLE' : 'SAFE';
  const decision = mode === 'VULNERABLE' ? null : outcomeModel.forRequest(res, 'XSS');

  // The policy follows the effective protections, not the mode label: in a
  // residual-risk case the escaping is skipped for this attempt, so the policy
  // that would block the fallout has to be relaxed with it or the gap shows a
  // watered-down result that never actually executed.
  const unescaped =
    mode === 'VULNERABLE' || (decision !== null && decision.basis === outcomeModel.BASES.RESIDUAL_RISK);

  if (unescaped) {
    return relaxedXssPolicy(req, res, next);
  }
  return next();
}

module.exports = { xssLabCspOverride };
