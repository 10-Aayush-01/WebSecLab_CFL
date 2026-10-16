'use strict';

/** ADMIN dashboard and its chart-data endpoint. */

const express = require('express');

const { requireAdmin } = require('../middleware/auth');
const dashboardController = require('../controllers/dashboardController');

const router = express.Router();

router.use(requireAdmin);

router.get('/', dashboardController.showDashboard);
router.get('/data', dashboardController.dashboardData);

module.exports = router;
