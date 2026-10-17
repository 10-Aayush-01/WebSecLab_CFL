'use strict';

/**
 * Lab 3 — IDOR, GET /labs/idor and GET /labs/idor/documents/:id.
 *
 * Authentication is required in BOTH modes. The document query is parameterized
 * in BOTH modes on purpose: this lab must demonstrate broken access control, not
 * SQL injection. There is no administrator exemption inside the lab, so the demo
 * stays unambiguous.
 *
 * A missing document is a 404 and never records an event.
 */

const { param, validationResult } = require('express-validator');

const { query } = require('../config/db');
const { labContent } = require('../labs/labContent');
const { markLabContext } = require('../middleware/securityMonitor');
const outcomeModel = require('../security/outcomeModel');

const CONTENT = labContent('IDOR');

const idValidators = [
  param('id').isInt({ min: 1 }).withMessage('A document id must be a positive integer.')
];

/** The signed-in user's own documents — the legitimate starting point. */
async function listOwnDocuments(userId) {
  const { rows } = await query(
    'SELECT id, title, created_at FROM user_documents WHERE owner_id = $1 ORDER BY id',
    [userId]
  );
  return rows;
}

/** Total documents, so the page can hint at the id range without listing them. */
async function documentRange() {
  const { rows } = await query(
    'SELECT COALESCE(min(id), 0)::int AS lowest, COALESCE(max(id), 0)::int AS highest, count(*)::int AS total FROM user_documents'
  );
  return rows[0];
}

/**
 * GET /labs/idor/open?id=N — convenience redirect used by the page's id form.
 * It exists so the lab page works without JavaScript; the documented IDOR route
 * /labs/idor/documents/:id stays exactly as the contract requires.
 */
async function openById(req, res) {
  const raw = String(req.query.id === undefined ? '' : req.query.id).trim();

  if (!/^\d+$/.test(raw) || Number(raw) < 1) {
    return res.status(404).render('errors/error', {
      status: 404,
      title: 'Document not found',
      message: 'That document id is not valid.'
    });
  }

  return res.redirect(`/labs/idor/documents/${Number(raw)}`);
}

/** GET /labs/idor */
async function showIndex(req, res, next) {
  try {
    return res.render('labs/idor-lab', {
      title: CONTENT.title,
      pageTitle: CONTENT.title,
      purpose: CONTENT.purpose,
      lab: CONTENT,
      mode: res.locals.securityMode,
      documents: await listOwnDocuments(res.locals.user.id),
      range: await documentRange(),
      errors: [],
      values: {}
    });
  } catch (err) {
    return next(err);
  }
}

/** GET /labs/idor/documents/:id */
async function showDocument(req, res, next) {
  const mode = res.locals.securityMode;
  const user = res.locals.user;

  // Invalid or missing id: 404, and deliberately no security event.
  if (!validationResult(req).isEmpty()) {
    return res.status(404).render('errors/error', {
      status: 404,
      title: 'Document not found',
      message: 'That document id is not valid.'
    });
  }

  const documentId = Number(req.params.id);

  try {
    const { rows } = await query(
      `SELECT d.id, d.title, d.content, d.owner_id, u.email AS owner_email
         FROM user_documents d
         JOIN users u ON u.id = d.owner_id
        WHERE d.id = $1`,
      [documentId]
    );

    const document = rows[0];

    // Unknown id: 404, no event (contract §3).
    if (!document) {
      return res.status(404).render('errors/error', {
        status: 404,
        title: 'Document not found',
        message: `No document exists with id ${documentId}.`
      });
    }

    const isOwner = document.owner_id === user.id;

    const view = {
      title: CONTENT.title,
      pageTitle: CONTENT.title,
      purpose: CONTENT.purpose,
      lab: CONTENT,
      mode,
      currentUser: user,
      requestedId: documentId,
      document,
      isOwner,
      denied: false,
      // Set when the residual-risk model skipped the ownership check for this
      // attempt, so the page describes the request that actually happened.
      residualRisk: false,
      globalMode: mode
    };

    if (mode === 'VULNERABLE') {
      // No ownership comparison at all.
      markLabContext(res, {
        lab: 'IDOR',
        payload: null,
        resourceId: documentId,
        ownerId: document.owner_id,
        outcome: isOwner ? 'NORMAL' : 'EXECUTED_UNSAFE'
      });
      return res.render('labs/idor-document', view);
    }

    // SAFE mode — unless the residual-risk model skipped the check for this
    // attempt, in which case the foreign document is genuinely returned.
    const decision = outcomeModel.forRequest(res, 'IDOR');

    if (!isOwner && decision.protectionApplied) {
      markLabContext(res, {
        lab: 'IDOR',
        payload: null,
        resourceId: documentId,
        ownerId: document.owner_id,
        outcome: 'BLOCKED',
        basis: decision.basis
      });
      return res.status(403).render('labs/idor-document', {
        ...view,
        denied: true,
        // Never send the protected content on a refused request.
        document: { id: document.id, owner_id: document.owner_id, owner_email: document.owner_email }
      });
    }

    markLabContext(res, {
      lab: 'IDOR',
      payload: null,
      resourceId: documentId,
      ownerId: document.owner_id,
      outcome: !isOwner ? 'EXECUTED_UNSAFE' : 'NORMAL',
      basis: decision.basis
    });
    return res.render('labs/idor-document', {
      ...view,
      // Only worth announcing when a foreign document was actually served.
      residualRisk: !isOwner && decision.basis === outcomeModel.BASES.RESIDUAL_RISK
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = { showIndex, showDocument, openById, listOwnDocuments, idValidators };
