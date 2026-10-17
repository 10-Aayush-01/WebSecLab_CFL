'use strict';

/**
 * Lab 2 — Stored XSS, GET /labs/xss and POST /labs/xss/comments.
 *
 * Store once, render per mode: the comment is written to the database exactly as
 * submitted in BOTH modes. The mode only decides whether xss-lab.ejs prints it
 * with `<%- %>` (unescaped) or `<%= %>` (escaped). That is what makes the
 * "same comment, switch to SAFE, refresh" re-test meaningful.
 */

const { body, validationResult } = require('express-validator');

const { query } = require('../config/db');
const { labContent } = require('../labs/labContent');
const { markLabContext } = require('../middleware/securityMonitor');
const outcomeModel = require('../security/outcomeModel');

const CONTENT = labContent('XSS');
const MAX_COMMENT_LENGTH = 1000;

const commentValidators = [
  body('comment')
    .isString()
    .withMessage('A comment must be text.')
    .isLength({ min: 1, max: MAX_COMMENT_LENGTH })
    .withMessage(`A comment must be between 1 and ${MAX_COMMENT_LENGTH} characters.`)
];

/** All comments, newest first, with the author shown as an email. */
async function listComments() {
  const { rows } = await query(
    `SELECT c.id, c.comment, c.created_at, u.email AS author_email
       FROM comments c
       JOIN users u ON u.id = c.user_id
      ORDER BY c.created_at DESC, c.id DESC`
  );
  return rows;
}

/** GET /labs/xss */
async function showLab(req, res, next) {
  const mode = res.locals.securityMode;

  // The same draw the CSP override already took for this request, so the policy
  // and the render branch can never disagree about whether escaping was skipped.
  const decision = outcomeModel.forRequest(res, 'XSS');

  try {
    return res.render('labs/xss-lab', {
      title: CONTENT.title,
      pageTitle: CONTENT.title,
      purpose: CONTENT.purpose,
      lab: CONTENT,
      mode,
      globalMode: mode,
      residualRisk: decision.basis === outcomeModel.BASES.RESIDUAL_RISK,
      rendersUnescaped: mode === 'VULNERABLE' || decision.basis === outcomeModel.BASES.RESIDUAL_RISK,
      comments: await listComments(),
      maxCommentLength: MAX_COMMENT_LENGTH,
      errors: [],
      values: {}
    });
  } catch (err) {
    return next(err);
  }
}

/** POST /labs/xss/comments */
async function createComment(req, res, next) {
  const mode = res.locals.securityMode;
  const rawComment = req.body.comment === undefined ? '' : String(req.body.comment);
  const errors = validationResult(req);
  const decision = outcomeModel.forRequest(res, 'XSS');

  if (!errors.isEmpty()) {
    markLabContext(res, { lab: 'XSS', payload: rawComment, outcome: 'BLOCKED' });
    try {
      return res.status(400).render('labs/xss-lab', {
        title: CONTENT.title,
        pageTitle: CONTENT.title,
        purpose: CONTENT.purpose,
        lab: CONTENT,
        mode,
        comments: await listComments(),
        maxCommentLength: MAX_COMMENT_LENGTH,
        globalMode: mode,
        residualRisk: false,
        rendersUnescaped: mode === 'VULNERABLE',
        errors: errors.array().map((e) => ({ field: e.path, message: e.msg })),
        values: { comment: rawComment }
      });
    } catch (err) {
      return next(err);
    }
  }

  try {
    await query('INSERT INTO comments (user_id, comment) VALUES ($1, $2)', [
      res.locals.user.id,
      rawComment
    ]);

    // A SAFE-mode attempt whose controls were skipped by the residual-risk model
    // really does store and render an executable comment, so it is reported as
    // EXECUTED_UNSAFE — the same as VULNERABLE mode.
    markLabContext(res, {
      lab: 'XSS',
      payload: rawComment,
      outcome: decision.protectionApplied ? 'NEUTRALIZED' : 'EXECUTED_UNSAFE',
      basis: decision.basis
    });

    const skipped = decision.basis === outcomeModel.BASES.RESIDUAL_RISK;
    res.locals.setFlash(
      'info',
      decision.protectionApplied
        ? 'Comment stored. In SAFE mode it is rendered as escaped text.'
        : skipped
          ? 'Comment stored raw and rendered unescaped: the residual-risk model skipped the SAFE controls for this attempt.'
          : 'Comment stored raw and rendered unescaped — see the result panel.'
    );

    return res.redirect('/labs/xss');
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  showLab,
  createComment,
  listComments,
  commentValidators,
  COMMENT_MAX: MAX_COMMENT_LENGTH
};
