'use strict';

/**
 * Read-side queries for the events table, the dashboard and the forensics
 * console. Writes live in src/security/securityLogger.js.
 */

const { query } = require('../config/db');

const ATTACK_TYPES = ['SQL_INJECTION', 'XSS', 'IDOR'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const RESULTS = ['SUCCESSFUL', 'BLOCKED', 'NEUTRALIZED', 'DETECTED'];

const PER_PAGE = 25;

/**
 * Filters come straight from the query string, so every value is validated
 * against a whitelist before it reaches SQL, and the search term is always
 * passed as a bound parameter.
 *
 * @param {object} filters
 * @param {string} [filters.attackType]
 * @param {string} [filters.severity]
 * @param {string} [filters.result]
 * @param {string} [filters.search]
 * @param {number} [filters.page]
 * @returns {Promise<{rows: object[], total: number, page: number, pages: number}>}
 */
async function listEvents(filters = {}) {
  const conditions = [];
  const params = [];

  if (ATTACK_TYPES.includes(filters.attackType)) {
    params.push(filters.attackType);
    conditions.push(`e.attack_type = $${params.length}`);
  }
  if (SEVERITIES.includes(filters.severity)) {
    params.push(filters.severity);
    conditions.push(`e.severity = $${params.length}`);
  }
  if (RESULTS.includes(filters.result)) {
    params.push(filters.result);
    conditions.push(`e.result = $${params.length}`);
  }
  if (filters.search && String(filters.search).trim()) {
    params.push(`%${String(filters.search).trim()}%`);
    conditions.push(
      `(e.endpoint ILIKE $${params.length}
        OR e.matched_rule ILIKE $${params.length}
        OR e.attack_type ILIKE $${params.length}
        OR COALESCE(e.request_data->>'payload', '') ILIKE $${params.length})`
    );
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const totalResult = await query(`SELECT count(*)::int AS total FROM security_events e ${where}`, params);
  const total = totalResult.rows[0].total;
  const pages = Math.max(1, Math.ceil(total / PER_PAGE));

  const page = Math.min(Math.max(1, Number(filters.page) || 1), pages);
  params.push(PER_PAGE, (page - 1) * PER_PAGE);

  const { rows } = await query(
    `SELECT e.id, e.event_uuid, e.occurred_at, e.http_method, e.endpoint, e.attack_type,
            e.severity, e.risk_score, e.matched_rule, e.security_mode, e.result, e.status_code,
            e.source_ip, u.email AS user_email,
            COALESCE(e.request_data->>'payload', '') AS payload,
            COALESCE(e.request_data->>'outcomeBasis', 'MODE') AS outcome_basis
       FROM security_events e
       LEFT JOIN users u ON u.id = e.user_id
       ${where}
      ORDER BY e.occurred_at DESC, e.id DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params
  );

  return { rows, total, page, pages };
}

/** @returns {Promise<object|null>} one event including its raw request_data */
async function getEventByUuid(eventUuid) {
  const { rows } = await query(
    `SELECT e.*, u.email AS user_email, u.name AS user_name
       FROM security_events e
       LEFT JOIN users u ON u.id = e.user_id
      WHERE e.event_uuid = $1`,
    [eventUuid]
  );
  return rows[0] || null;
}

/**
 * Forensic timeline entries for one event (contract §6).
 * @param {number} eventId
 */
async function listIncidentActions(eventId) {
  const { rows } = await query(
    `SELECT a.id, a.action, a.description, a.evidence_filename, a.evidence_sha256,
            a.occurred_at, u.email AS performed_by_email
       FROM incident_actions a
       LEFT JOIN users u ON u.id = a.performed_by
      WHERE a.event_id = $1
      ORDER BY a.occurred_at ASC, a.id ASC`,
    [eventId]
  );
  return rows;
}

/** Latest export recorded for an event, used to show filename + hash. */
async function getLatestExport(eventId) {
  const { rows } = await query(
    `SELECT evidence_filename, evidence_sha256, occurred_at, description
       FROM incident_actions
      WHERE event_id = $1 AND action = 'EVIDENCE_EXPORTED'
      ORDER BY occurred_at DESC, id DESC
      LIMIT 1`,
    [eventId]
  );
  return rows[0] || null;
}

/** Looks up the stored hash for a filename (evidence verification). */
async function findExportByFilename(filename) {
  const { rows } = await query(
    `SELECT a.event_id, a.evidence_filename, a.evidence_sha256, a.occurred_at,
            e.event_uuid
       FROM incident_actions a
       JOIN security_events e ON e.id = a.event_id
      WHERE a.action = 'EVIDENCE_EXPORTED' AND a.evidence_filename = $1
      ORDER BY a.occurred_at DESC
      LIMIT 1`,
    [filename]
  );
  return rows[0] || null;
}

/** All exports, newest first — the evidence registry on the verify page. */
async function listExports(limit = 20) {
  const { rows } = await query(
    `SELECT a.evidence_filename, a.evidence_sha256, a.occurred_at,
            e.event_uuid, e.attack_type, a.event_id
       FROM incident_actions a
       JOIN security_events e ON e.id = a.event_id
      WHERE a.action = 'EVIDENCE_EXPORTED'
      ORDER BY a.occurred_at DESC
      LIMIT $1`,
    [limit]
  );
  return rows;
}

/**
 * Dashboard aggregate. Each number is a plain count so it can be checked
 * against a raw SELECT in the acceptance test (§15/14).
 */
async function getDashboardSummary() {
  const { rows } = await query(
    `SELECT
       (SELECT count(*)::int FROM monitored_requests)                        AS monitored_requests,
       (SELECT count(*)::int FROM security_events)                           AS total_events,
       (SELECT count(*)::int FROM security_events WHERE result = 'SUCCESSFUL')  AS successful_attacks,
       (SELECT count(*)::int FROM security_events
         WHERE result IN ('BLOCKED','NEUTRALIZED'))                          AS blocked_attacks,
       (SELECT count(*)::int FROM monitored_requests WHERE flagged)          AS flagged_requests,
       (SELECT count(*)::int FROM security_events
         WHERE occurred_at >= now() - interval '24 hours')                    AS events_last_24h,
       (SELECT count(*)::int FROM security_events
         WHERE occurred_at >= now() - interval '48 hours'
           AND occurred_at < now() - interval '24 hours')                     AS events_prev_24h,
       (SELECT count(*)::int FROM monitored_requests
         WHERE occurred_at >= now() - interval '24 hours')                    AS monitored_last_24h,
       (SELECT count(*)::int FROM monitored_requests
         WHERE occurred_at >= now() - interval '48 hours'
           AND occurred_at < now() - interval '24 hours')                     AS monitored_prev_24h,
       (SELECT count(*)::int FROM products)                                  AS products,
       (SELECT count(*)::int FROM products WHERE is_released = FALSE)         AS hidden_products,
       (SELECT count(*)::int FROM user_documents)                            AS documents,
       (SELECT count(*)::int FROM comments)                                  AS comments`
  );
  return rows[0];
}

/** Events grouped by attack type (doughnut chart). */
async function getAttackDistribution() {
  const { rows } = await query(
    `SELECT attack_type, count(*)::int AS total
       FROM security_events
      GROUP BY attack_type
      ORDER BY attack_type`
  );
  return rows;
}

/** Events per day for the last 14 days (line chart), zero-filled. */
async function getEventsOverTime(days = 14) {
  const { rows } = await query(
    `SELECT to_char(d.day, 'YYYY-MM-DD') AS day,
            COALESCE(count(e.id), 0)::int AS total
       FROM generate_series(
              (CURRENT_DATE - ($1::int - 1) * INTERVAL '1 day')::date,
              CURRENT_DATE,
              INTERVAL '1 day'
            ) AS d(day)
       LEFT JOIN security_events e ON e.occurred_at::date = d.day
      GROUP BY d.day
      ORDER BY d.day`,
    [days]
  );
  return rows;
}

/** Mode split, shown as context beside the charts. */
async function getModeSplit() {
  const { rows } = await query(
    `SELECT security_mode, count(*)::int AS total
       FROM security_events
      GROUP BY security_mode
      ORDER BY security_mode`
  );
  return rows;
}

/** Most recent events for the dashboard table. */
async function getRecentEvents(limit = 6) {
  const { rows } = await query(
    `SELECT event_uuid, occurred_at, attack_type, severity, risk_score, result, endpoint, security_mode,
            COALESCE(request_data->>'outcomeBasis', 'MODE') AS outcome_basis
       FROM security_events
      ORDER BY occurred_at DESC, id DESC
      LIMIT $1`,
    [limit]
  );
  return rows;
}

module.exports = {
  ATTACK_TYPES,
  SEVERITIES,
  RESULTS,
  PER_PAGE,
  listEvents,
  getEventByUuid,
  listIncidentActions,
  getLatestExport,
  findExportByFilename,
  listExports,
  getDashboardSummary,
  getAttackDistribution,
  getEventsOverTime,
  getModeSplit,
  getRecentEvents
};
