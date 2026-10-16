'use strict';

/** Sign-in, registration and sign-out. Rate limited (auth routes only). */

const express = require('express');

const authController = require('../controllers/authController');
const { loginLimiter, registerLimiter } = require('../middleware/rateLimit');

const router = express.Router();

router.get('/login', authController.showLogin);
router.post('/login', loginLimiter, authController.login);

router.get('/register', authController.showRegister);
router.post('/register', registerLimiter, authController.register);

// POST only: a GET logout can be triggered by any third-party <img> tag.
router.post('/logout', authController.logout);

module.exports = router;
