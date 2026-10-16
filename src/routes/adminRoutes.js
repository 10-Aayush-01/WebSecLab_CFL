'use strict';

/** Administrator-only actions. */

const express = require('express');

const { requireAdmin } = require('../middleware/auth');
const adminController = require('../controllers/adminController');

const router = express.Router();

// POST /admin/mode — the global SAFE/VULNERABLE switch (CSRF checked globally).
router.post('/mode', requireAdmin, adminController.updateMode);

module.exports = router;
