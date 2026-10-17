'use strict';

/**
 * Lab 1 — SQL Injection, GET /labs/sql?q=...
 *
 * GET on purpose: the payload is trivial to edit and replay in Burp Repeater.
 *
 * VULNERABLE mode runs the term through searchProductsUnsafe() on the
 * least-privilege lab pool (lab_reader), so even a successful injection cannot
 * read users / password_hash or write anything. SAFE mode runs the same term as
 * a bound parameter on the normal pool, after validation.
 */

const { query: queryValidator, validationResult } = require('express-validator');

const { query, labQuery } = require('../config/db');
const { labContent } = require('../labs/labContent');
const { markLabContext } = require('../middleware/securityMonitor');
const outcomeModel = require('../security/outcomeModel');

const CONTENT = labContent('SQLI');
const MAX_SEARCH_LENGTH = 50;
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/;

/** Applied in SAFE mode only — VULNERABLE mode deliberately has no validation. */
const searchValidators = [
  queryValidator('q')
    .isLength({ max: MAX_SEARCH_LENGTH })
    .withMessage(`Search terms are limited to ${MAX_SEARCH_LENGTH} characters.`),
  queryValidator('q')
    .custom((value) => !CONTROL_CHARACTERS.test(String(value)))
    .withMessage('Control characters are not allowed in the search term.')
];

/**
 * ---------------------------------------------------------------------------
 * INTENTIONALLY VULNERABLE — EDUCATIONAL LAB ONLY
 * ---------------------------------------------------------------------------
 * The search term is concatenated straight into the SQL string. This function
 * exists for teaching and is imported by nothing except this controller
 * (acceptance test §15/7). It runs on the lab_reader pool, which holds SELECT
 * on `products` and no other privilege, so the blast radius of a successful
 * injection is capped by the database itself.
 *
 * @param {string} searchTerm raw, unvalidated user input
 * @returns {Promise<{sql: string, rows: object[]}>}
 */
async function searchProductsUnsafe(searchTerm) {
  const sql = `SELECT id, name, description, price, category FROM products WHERE is_released = TRUE AND name ILIKE '%${searchTerm}%'`;
  const result = await labQuery(sql);
  return { sql, rows: result.rows };
}

/**
 * Safe counterpart: the term is bound as a parameter and can only ever be a
 * literal string. Normal searches behave identically in both modes.
 */
async function searchProductsSafe(searchTerm) {
  const sql =
    'SELECT id, name, description, price, category FROM products WHERE is_released = TRUE AND name ILIKE $1';
  const result = await query(sql, [`%${searchTerm}%`]);
  return { sql, rows: result.rows };
}

/** Marks rows that a normal search never shows ("hidden data" demo). */
async function annotateHidden(rows) {
  const released = await query('SELECT id FROM products WHERE is_released = TRUE');
  const releasedIds = new Set(released.rows.map((row) => row.id));
  return rows.map((row) => ({ ...row, hidden: !releasedIds.has(row.id) }));
}

/** GET /labs/sql */
async function showSearch(req, res, next) {
  const mode = res.locals.securityMode;
  const rawTerm = req.query.q === undefined ? '' : String(req.query.q);
  const trimmedTerm = rawTerm.trim();

  const view = {
    title: CONTENT.title,
    pageTitle: CONTENT.title,
    purpose: CONTENT.purpose,
    lab: CONTENT,
    mode,
    term: rawTerm,
    maxSearchLength: MAX_SEARCH_LENGTH,
    rows: null,
    executedSql: null,
    hiddenCount: 0,
    searched: false,
    errors: [],
    // Set when the residual-risk model skipped the protections for this attempt,
    // so the view can describe what actually happened instead of what should have.
    residualRisk: false,
    globalMode: mode,
    // The exact request to replay in Burp Repeater, offered with a copy button on
    // the result card. Built here, not in the view, so the encoding is the same
    // one the search form produced.
    requestPath: trimmedTerm ? `/labs/sql?q=${encodeURIComponent(trimmedTerm)}` : null
  };

  // An empty search runs nothing and records nothing.
  if (!trimmedTerm) return res.render('labs/sql-lab', view);

  if (mode === 'SAFE') {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      markLabContext(res, { lab: 'SQLI', payload: rawTerm, outcome: 'BLOCKED' });
      return res.status(400).render('labs/sql-lab', {
        ...view,
        errors: errors.array().map((e) => ({ field: e.path, message: e.msg }))
      });
    }

    // Validation always runs above; the parameterized path itself is what the
    // residual-risk model can skip. A skipped attempt runs the real vulnerable
    // query, so the leak and the event are both genuine.
    const decision = outcomeModel.forRequest(res, 'SQL_INJECTION');

    if (!decision.protectionApplied) {
      try {
        const { sql, rows } = await searchProductsUnsafe(rawTerm);
        const annotated = await annotateHidden(rows);
        markLabContext(res, {
          lab: 'SQLI',
          payload: rawTerm,
          outcome: 'EXECUTED_UNSAFE',
          basis: decision.basis
        });
        return res.render('labs/sql-lab', {
          ...view,
          executedSql: sql,
          rows: annotated,
          hiddenCount: annotated.filter((row) => row.hidden).length,
          searched: true,
          residualRisk: true
        });
      } catch (err) {
        console.warn('[sql] residual-risk query rejected by the database:', err.message);
        markLabContext(res, {
          lab: 'SQLI',
          payload: rawTerm,
          outcome: 'BLOCKED',
          basis: decision.basis
        });
        return res.status(500).render('labs/sql-lab', {
          ...view,
          searched: true,
          residualRisk: true,
          errors: [
            {
              field: 'q',
              message:
                'The database refused the statement this payload produced (least-privilege role ' +
                'lab_reader). The SAFE controls were skipped for this attempt, but the blast-radius ' +
                'control still applied.'
            }
          ]
        });
      }
    }

    try {
      const { sql, rows } = await searchProductsSafe(trimmedTerm);
      markLabContext(res, {
        lab: 'SQLI',
        payload: rawTerm,
        outcome: 'NEUTRALIZED',
        basis: decision.basis
      });
      return res.render('labs/sql-lab', {
        ...view,
        executedSql: sql,
        rows: await annotateHidden(rows),
        searched: true
      });
    } catch (err) {
      return next(err);
    }
  }

  // VULNERABLE
  try {
    const { sql, rows } = await searchProductsUnsafe(rawTerm);
    const annotated = await annotateHidden(rows);
    markLabContext(res, { lab: 'SQLI', payload: rawTerm, outcome: 'EXECUTED_UNSAFE' });
    return res.render('labs/sql-lab', {
      ...view,
      executedSql: sql,
      rows: annotated,
      hiddenCount: annotated.filter((row) => row.hidden).length,
      searched: true
    });
  } catch (err) {
    // The least-privilege role refused the injected statement. The weakness is
    // still present; the database simply would not let it reach other tables.
    console.warn('[sql] lab query rejected by the database:', err.message);
    markLabContext(res, { lab: 'SQLI', payload: rawTerm, outcome: 'BLOCKED' });
    return res.status(500).render('labs/sql-lab', {
      ...view,
      searched: true,
      errors: [
        {
          field: 'q',
          message:
            'The database refused the statement this payload produced (least-privilege role ' +
            'lab_reader). Nothing was returned — see the report section on blast-radius control.'
        }
      ]
    });
  }
}

module.exports = { showSearch, searchProductsUnsafe, searchProductsSafe, searchValidators };
