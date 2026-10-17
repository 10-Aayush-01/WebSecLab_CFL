'use strict';

/**
 * The three labs. Every route requires authentication in BOTH modes
 * (contract §3) — the intentional weaknesses are confined to the three lab
 * controllers and their views.
 *
 * No rate limiting here on purpose: Burp Repeater/Intruder loops would trip it
 * and break the demonstrations.
 */

const express = require('express');

const { requireAuth } = require('../middleware/auth');
const sqlController = require('../controllers/sqlController');
const xssController = require('../controllers/xssController');
const idorController = require('../controllers/idorController');

const router = express.Router();

router.use(requireAuth);

// Lab 1 — SQL Injection (GET on purpose, trivial to replay in Burp)
router.get('/sql', sqlController.searchValidators, sqlController.showSearch);

// Lab 2 — Stored XSS.
// The comment validators run in BOTH modes: length and type checking is one of
// the controls this lab marks as always on, and the mode only decides whether
// the stored text is escaped when the page renders it.
router.get('/xss', xssController.showLab);
router.post('/xss/comments', xssController.commentValidators, xssController.createComment);

// Lab 3 — IDOR
router.get('/idor', idorController.showIndex);
// Convenience redirect for the id form on the lab page (no JavaScript needed).
router.get('/idor/open', idorController.openById);
router.get('/idor/documents/:id', idorController.idValidators, idorController.showDocument);

module.exports = router;
