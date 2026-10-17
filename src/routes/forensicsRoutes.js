'use strict';

/**
 * ADMIN-only forensic console (contract §6).
 *
 * Route order matters: /verify is declared before /:uuid so the literal path is
 * never captured by the parameterised one.
 */

const express = require('express');

const { requireAdmin } = require('../middleware/auth');
const forensicsController = require('../controllers/forensicsController');

const router = express.Router();

router.use(requireAdmin);

// Evidence verification page and the re-hash endpoint.
router.get('/verify', forensicsController.showVerify);
router.post(
  '/verify',
  // The submitted file is read as text and posted as JSON, so this route needs
  // a larger JSON limit than the rest of the app (contract §6).
  express.json({ limit: '1mb' }),
  forensicsController.verifyEvidence
);

// Incident investigation.
router.get('/:uuid', forensicsController.showInvestigation);
router.post('/:uuid/export', forensicsController.exportEvidence);
router.get('/:uuid/evidence/:filename', forensicsController.downloadEvidence);

module.exports = router;
