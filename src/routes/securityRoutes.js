'use strict';

/** ADMIN-only security console. */

const express = require('express');

const { requireAdmin } = require('../middleware/auth');
const securityController = require('../controllers/securityController');

const router = express.Router();

router.use(requireAdmin);

router.get('/events', securityController.showEvents);

module.exports = router;
