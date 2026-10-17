'use strict';

/**
 * Security logger — the only module that writes audit records.
 *
 * Everything the forensics module later reads is written here, so a rule change
 * in one place cannot produce half-populated events.
 */

const { query } = require('../config/db');
const { redact } = require('./sanitizer');

/**
 * Inserts a detected security event.
 *
 * @param {object} input
 * @param {number|null} input.userId
 * @param {string|null} input.sourceIp
 * @param {string} input.httpMethod
 * @param {string} input.endpoint
 * @param {'SQL_INJECTION'|'XSS'|'IDOR'} input.attackType
 * @param {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} input.severity
 * @param {number} input.riskScore
 * @param {string} input.matchedRule
 * @param {object} input.requestData
 * @param {'VULNERABLE'|'SAFE'} input.securityMode
 * @param {'DETECTED'|'SUCCESSFUL'|'BLOCKED'|'NEUTRALIZED'} input.result
 * @param {number} input.statusCode
 * @returns {Promise<{id: number, event_uuid: string, occurred_at: Date}>}
 */
async function createSecurityEvent(input) {
  const {
    userId = null,
    sourceIp = null,
    httpMethod,
    endpoint,
    attackType,
    severity,
    riskScore,
    matchedRule,
    requestData = {},
    securityMode,
    result,
    statusCode
  } = input;

  // Defence in depth: redact again at the write boundary.
  const safeRequestData = redact(requestData) ?? {};

  const { rows } = await query(
    `INSERT INTO security_events
       (user_id, source_ip, http_method, endpoint, attack_type, severity,
        risk_score, matched_rule, request_data, security_mode, result, status_code)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     RETURNING id, event_uuid, occurred_at`,
    [
      userId,
      sourceIp,
      httpMethod,
      endpoint,
      attackType,
      severity,
      riskScore,
      matchedRule,
      JSON.stringify(safeRequestData),
      securityMode,
      result,
      statusCode
    ]
  );

  return rows[0];
}

/**
 * Records one row of the forensic timeline / chain of custody.
 *
 * @param {object} input
 * @param {number} input.eventId
 * @param {'INVESTIGATION_OPENED'|'EVIDENCE_EXPORTED'|'EVIDENCE_VERIFIED'} input.action
 * @param {string|null} [input.description]
 * @param {string|null} [input.evidenceFilename]
 * @param {string|null} [input.evidenceSha256]
 * @param {number|null} [input.performedBy]
 * @returns {Promise<{id: number, occurred_at: Date}>}
 */
async function recordIncidentAction(input) {
  const {
    eventId,
    action,
    description = null,
    evidenceFilename = null,
    evidenceSha256 = null,
    performedBy = null
  } = input;

  const { rows } = await query(
    `INSERT INTO incident_actions
       (event_id, action, description, evidence_filename, evidence_sha256, performed_by)
     VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING id, occurred_at`,
    [eventId, action, description, evidenceFilename, evidenceSha256, performedBy]
  );

  return rows[0];
}

/**
 * Records a monitored lab request. Returns the new row id so the monitor can
 * flag it once detection has run.
 *
 * @param {object} input
 * @param {number|null} input.userId
 * @param {string} input.httpMethod
 * @param {string} input.endpoint
 * @param {'VULNERABLE'|'SAFE'} input.securityMode
 * @param {number} input.statusCode
 * @returns {Promise<number>} the monitored_requests id
 */
async function recordMonitoredRequest(input) {
  const { userId = null, httpMethod, endpoint, securityMode, statusCode } = input;

  const { rows } = await query(
    `INSERT INTO monitored_requests
       (user_id, http_method, endpoint, security_mode, status_code, flagged)
     VALUES ($1,$2,$3,$4,$5,FALSE)
     RETURNING id`,
    [userId, httpMethod, endpoint, securityMode, statusCode]
  );

  return rows[0].id;
}

/** Marks a monitored request as having produced a security event. */
async function flagMonitoredRequest(id) {
  await query('UPDATE monitored_requests SET flagged = TRUE WHERE id = $1', [id]);
}

module.exports = {
  createSecurityEvent,
  recordIncidentAction,
  recordMonitoredRequest,
  flagMonitoredRequest
};
