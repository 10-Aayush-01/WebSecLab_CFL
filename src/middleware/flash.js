'use strict';

/**
 * One-shot session messages, so POST → redirect → GET can report an outcome
 * without leaking state into the URL.
 */

/**
 * Reads and clears pending messages, and provides res.locals.setFlash().
 */
function flash(req, res, next) {
  if (!req.session) return next();

  res.locals.flash = Array.isArray(req.session.flash) ? req.session.flash : [];
  delete req.session.flash;

  /**
   * Queues a message for the next rendered page.
   * @param {'success'|'error'|'info'} type
   * @param {string} message
   */
  res.locals.setFlash = (type, message) => {
    if (!Array.isArray(req.session.flash)) req.session.flash = [];
    req.session.flash.push({ type, message });
  };

  return next();
}

module.exports = { flash };
