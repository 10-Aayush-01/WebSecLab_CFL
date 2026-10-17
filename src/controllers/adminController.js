'use strict';

/**
 * Administrator actions. Today that is only the global security-mode switch.
 * ADMIN only, POST only, CSRF protected — the mode change is itself an audited
 * security decision.
 */

const { MODES, setSecurityMode } = require('../middleware/securityMode');
const { safeReturnTo } = require('./authController');

/** POST /admin/mode */
async function updateMode(req, res, next) {
  const requested = String(req.body.mode || '').trim().toUpperCase();
  const destination = safeReturnTo(req.body.redirectTo) || '/dashboard';

  if (!MODES.includes(requested)) {
    res.locals.setFlash('error', 'Unknown security mode requested.');
    return res.redirect(destination);
  }

  if (requested === res.locals.securityMode) {
    res.locals.setFlash('info', `Global security mode is already set to ${requested}.`);
    return res.redirect(destination);
  }

  try {
    const applied = await setSecurityMode(requested, res.locals.user.id);

    res.locals.setFlash(
      applied === 'VULNERABLE' ? 'error' : 'success',
      applied === 'VULNERABLE'
        ? 'Global security mode is now VULNERABLE. The three lab routes are intentionally insecure until you switch back to SAFE.'
        : 'Global security mode is now SAFE. All three labs are enforcing their protections again.'
    );

    console.log(`[mode] ${res.locals.user.email} switched the global mode to ${applied}`);
    return res.redirect(destination);
  } catch (err) {
    return next(err);
  }
}

module.exports = { updateMode };
