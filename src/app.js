'use strict';

/**
 * WebSecLab application wiring.
 *
 * Middleware order (contract §2):
 *   helmet -> static (/public, /vendor) -> body parsers -> session -> csrf token
 *   -> locals defaults -> loadUser + loadSecurityMode -> csrf verification
 *   -> XSS-lab CSP override -> securityMonitor (/labs/*) -> routes -> 404 -> errors
 *
 * Headers are not flushed until the response body is written, which is what
 * lets the XSS-lab CSP override replace the strict policy set seconds earlier.
 */

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');

const env = require('./config/env');
const { loadUser } = require('./middleware/auth');
const { loadSecurityMode, DEFAULT_MODE } = require('./middleware/securityMode');
const { csrfToken, verifyCsrf } = require('./middleware/csrf');
const { flash } = require('./middleware/flash');
const { loadTheme } = require('./middleware/theme');
const { securityMonitor } = require('./middleware/securityMonitor');
const { xssLabCspOverride } = require('./middleware/csp');
const { notFound, errorHandler } = require('./middleware/errorHandler');
const { formatTimestamp, formatDate, shortId } = require('./utils/format');
const routes = require('./routes');

const app = express();
const projectRoot = path.join(__dirname, '..');

app.set('view engine', 'ejs');
app.set('views', path.join(projectRoot, 'views'));
app.disable('x-powered-by');
// Loopback only: no proxy in front of this app, so req.ip is the real client.
app.set('trust proxy', false);

// Helpers available in every template.
app.locals.formatTimestamp = formatTimestamp;
app.locals.formatDate = formatDate;
app.locals.shortId = shortId;

// ---------------------------------------------------------------------------
// 1. Security headers. Strict CSP everywhere.
//    upgradeInsecureRequests is disabled because the local demo runs on http.
// ---------------------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: { upgradeInsecureRequests: null }
    }
  })
);

// ---------------------------------------------------------------------------
// 2. Static assets. Vendored from node_modules — no CDN, so the demo works
//    offline and the strict CSP stays simple.
// ---------------------------------------------------------------------------
app.use(express.static(path.join(projectRoot, 'public')));
app.use(
  '/vendor/bootstrap',
  express.static(path.join(projectRoot, 'node_modules', 'bootstrap', 'dist'))
);
app.use(
  '/vendor/chart.js',
  express.static(path.join(projectRoot, 'node_modules', 'chart.js', 'dist'))
);

// ---------------------------------------------------------------------------
// 3. Body parsers. JSON is parsed only on the route that needs it.
// ---------------------------------------------------------------------------
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// ---------------------------------------------------------------------------
// 4. Session
// ---------------------------------------------------------------------------
app.use(
  session({
    name: 'webseclab.sid',
    secret: env.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      // `secure` must stay off on http://localhost or the session never sticks.
      secure: env.isProduction,
      maxAge: 2 * 60 * 60 * 1000
    }
  })
);

// ---------------------------------------------------------------------------
// 5. CSRF token issued for every response.
// ---------------------------------------------------------------------------
app.use(csrfToken);

// ---------------------------------------------------------------------------
// 6. Local defaults. Guarantees the error/403/404 views can always render, even
//    when a request is rejected before loadUser or loadSecurityMode have run.
// ---------------------------------------------------------------------------
app.use((req, res, next) => {
  res.locals.user = null;
  res.locals.securityMode = DEFAULT_MODE;
  res.locals.isVulnerable = false;
  res.locals.flash = [];
  res.locals.setFlash = () => {};
  res.locals.currentPath = req.path;
  res.locals.csrfToken = req.session.csrfToken || '';
  res.locals.themeChoice = 'system';
  res.locals.themeAttribute = '';
  next();
});

// ---------------------------------------------------------------------------
// 7. Theme preference (cookie, read server-side so the first paint is correct),
//    flash messages and the current path (sidebar highlight).
// ---------------------------------------------------------------------------
app.use(loadTheme);
app.use(flash);
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  next();
});

// ---------------------------------------------------------------------------
// 8. Identity and the global security mode (read per request, never cached).
// ---------------------------------------------------------------------------
app.use(loadUser);
app.use(loadSecurityMode);

// ---------------------------------------------------------------------------
// 9. CSRF verification for EVERY unsafe method — logout and the mode switch
//    included. Placed after identity loading so a rejection can render a
//    complete page.
// ---------------------------------------------------------------------------
app.use(verifyCsrf);

// ---------------------------------------------------------------------------
// 10. Relaxed CSP for /labs/xss, only while the mode is VULNERABLE.
// ---------------------------------------------------------------------------
app.use('/labs/xss', xssLabCspOverride);

// ---------------------------------------------------------------------------
// 11. Security monitor for /labs/* only (detection runs on response finish).
// ---------------------------------------------------------------------------
app.use('/labs', securityMonitor);

// ---------------------------------------------------------------------------
// 12. Application routes, then 404 and the central error handler.
// ---------------------------------------------------------------------------
app.use(routes);
app.use(notFound);
app.use(errorHandler);

module.exports = app;
