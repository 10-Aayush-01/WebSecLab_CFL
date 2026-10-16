'use strict';

/**
 * 404 + central error handling (contract §7).
 * Stack traces are never sent to the client when NODE_ENV=production.
 */

const env = require('../config/env');

/** Terminal middleware: nothing matched a route. */
function notFound(req, res) {
  if (req.accepts('html')) {
    return res.status(404).render('errors/error', {
      status: 404,
      title: 'Page not found',
      message: 'That page does not exist in WebSecLab.'
    });
  }
  return res.status(404).json({ error: 'Not found' });
}

/** Central error handler — four arguments so Express recognises it. */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = Number(err.status || err.statusCode) || 500;

  if (status >= 500) {
    console.error('[error]', req.method, req.originalUrl, '-', err.stack || err.message);
  } else {
    console.warn('[error]', req.method, req.originalUrl, '-', err.message);
  }

  if (res.headersSent) {
    return res.destroy ? res.destroy() : undefined;
  }

  const message = env.isProduction
    ? 'Something went wrong while processing that request.'
    : err.message || 'Something went wrong.';

  if (req.accepts('html')) {
    return res.status(status).render('errors/error', {
      status,
      title: status === 500 ? 'Server error' : 'Request failed',
      message,
      detail: env.isProduction ? null : err.stack || null
    });
  }

  return res.status(status).json({ error: message });
}

module.exports = { notFound, errorHandler };
