'use strict';

/**
 * Top-level router. Mounted after all cross-cutting middleware (see app.js).
 */

const express = require('express');

const authRoutes = require('./authRoutes');
const labRoutes = require('./labRoutes');
const adminRoutes = require('./adminRoutes');
const dashboardRoutes = require('./dashboardRoutes');
const securityRoutes = require('./securityRoutes');
const forensicsRoutes = require('./forensicsRoutes');
const { landingFor } = require('../controllers/authController');

const router = express.Router();

/** Root: send each visitor to the most useful page for their role. */
router.get('/', (req, res) => {
  if (!res.locals.user) return res.redirect('/login');
  return res.redirect(landingFor(res.locals.user));
});

/**
 * Liveness probe used by the start-up script and by the acceptance tests to
 * confirm the server is answering HTTP (not merely holding a port open).
 */
router.get('/health', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  return res.json({
    status: 'ok',
    securityMode: res.locals.securityMode,
    authenticated: Boolean(res.locals.user)
  });
});

router.use('/', authRoutes);
router.use('/labs', labRoutes);
router.use('/admin', adminRoutes);
router.use('/dashboard', dashboardRoutes);
router.use('/security', securityRoutes);
router.use('/forensics', forensicsRoutes);

module.exports = router;
