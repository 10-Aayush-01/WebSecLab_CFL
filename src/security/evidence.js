'use strict';

/**
 * Evidence package builder and SHA-256 integrity helper (contract §6).
 *
 * Honest scope note carried on every page that shows a hash:
 * "SHA-256 here demonstrates whether the exported file has changed. Hashing by
 *  itself does not establish authenticity or a complete chain of custody."
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const env = require('../config/env');
const { redact } = require('./sanitizer');
const { RESULT_LABEL } = require('./riskCalculator');
const { ATTACK_TYPES } = require('./detectors/rules');

const EVIDENCE_VERSION = '1.0';

/** Mandatory disclaimer text (contract §6). */
const INTEGRITY_DISCLAIMER =
  'SHA-256 here demonstrates whether the exported file has changed. Hashing by itself does not ' +
  'establish authenticity or a complete chain of custody.';

/** Recommended mitigations per attack type (contract §6). */
const MITIGATIONS = Object.freeze({
  SQL_INJECTION:
    'Use parameterized queries (prepared statements) for every database call; validate input ' +
    'server-side; run the query on a least-privilege database account so a successful injection ' +
    'cannot reach unrelated tables.',
  XSS:
    'Apply context-aware output encoding at render time; sanitize rich input on the server; ' +
    'enforce a strict Content-Security-Policy; keep the session cookie httpOnly.',
  IDOR:
    'Check object ownership on the server for every access to a user-owned resource; return 403 ' +
    'when the check fails; never trust an id supplied by the client.'
});

/**
 * @param {string} attackType
 * @returns {string}
 */
function mitigationFor(attackType) {
  return (
    MITIGATIONS[attackType] ||
    'Apply defence in depth: validate input server-side, authorize every object access and log the attempt.'
  );
}

/**
 * Builds the evidence object in the frozen key order of contract §6.
 *
 * @param {object} input
 * @param {object} input.event           a security_events row
 * @param {{id: number, role: string}|null} input.user
 * @param {{parameter: string|null, payload: string|null, resourceId: number|null, userAgent: string|null}} input.requestData
 * @param {string} [input.exportedAt]    ISO timestamp
 * @returns {object} evidence package
 */
function buildEvidence({ event, user, requestData, exportedAt = new Date() }) {
  const exportedAtIso = exportedAt instanceof Date ? exportedAt.toISOString() : String(exportedAt);
  const occurredAtIso = new Date(event.occurred_at).toISOString();
  const sanitized = redact(requestData) ?? {};

  // Fixed key order — do not reorder: the report walks through these keys.
  return {
    evidenceVersion: EVIDENCE_VERSION,
    incidentId: event.event_uuid,
    exportedAt: exportedAtIso,
    event: {
      occurredAt: occurredAtIso,
      attackType: event.attack_type,
      severity: event.severity,
      riskScore: event.risk_score,
      riskScoreLabel: RESULT_LABEL,
      matchedRule: event.matched_rule,
      securityMode: event.security_mode,
      result: event.result,
      statusCode: event.status_code,
      httpMethod: event.http_method,
      endpoint: event.endpoint,
      sourceIp: event.source_ip,
      user: user ? { id: user.id, role: user.role } : null,
      requestEvidence: {
        parameter: sanitized.parameter ?? null,
        payload: sanitized.payload ?? null,
        resourceId: sanitized.resourceId ?? null,
        userAgent: sanitized.userAgent ?? null
      }
    },
    recommendedMitigation: mitigationFor(event.attack_type)
  };
}

/** Serializes with a fixed 2-space indentation — these exact bytes get hashed. */
const serializeEvidence = (evidence) => JSON.stringify(evidence, null, 2);

/** @returns {string} lowercase hex SHA-256 of the exact bytes given. */
const hashContent = (content) => crypto.createHash('sha256').update(content, 'utf8').digest('hex');

/**
 * Builds the evidence filename: evidence-<uuid>-<yyyymmddThhmmss>.json
 * @param {string} eventUuid
 * @param {Date} [date]
 * @returns {string}
 */
function evidenceFilename(eventUuid, date = new Date()) {
  const stamp = date.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, '');
  return `evidence-${eventUuid}-${stamp}.json`;
}

/** Guards against path traversal when reading back an exported file. */
const isValidEvidenceFilename = (name) =>
  typeof name === 'string' &&
  /^evidence-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-\d{8}T\d{6}\.json$/.test(name);

/** Absolute path of an already-validated evidence file. */
const evidencePath = (filename) => path.join(env.exportsDir, filename);

/** Ensures exports/ exists (it is gitignored apart from .gitkeep). */
function ensureExportsDir() {
  fs.mkdirSync(env.exportsDir, { recursive: true });
}

/**
 * Writes the exact bytes to exports/ and returns their SHA-256.
 * The hash is deliberately kept OUTSIDE the file (contract §6).
 *
 * @param {string} filename
 * @param {string} content
 * @returns {{filePath: string, sha256: string, bytes: number}}
 */
function writeEvidenceFile(filename, content) {
  if (!isValidEvidenceFilename(filename)) {
    throw new Error(`Refusing to write evidence with an unexpected filename: ${filename}`);
  }
  ensureExportsDir();
  const filePath = evidencePath(filename);
  fs.writeFileSync(filePath, content, 'utf8');
  return { filePath, sha256: hashContent(content), bytes: Buffer.byteLength(content, 'utf8') };
}

/** Reads an exported file back for download. Filename must already be validated. */
const readEvidenceFile = (filename) => fs.readFileSync(evidencePath(filename), 'utf8');

module.exports = {
  EVIDENCE_VERSION,
  INTEGRITY_DISCLAIMER,
  MITIGATIONS,
  ATTACK_TYPES,
  mitigationFor,
  buildEvidence,
  serializeEvidence,
  hashContent,
  evidenceFilename,
  isValidEvidenceFilename,
  evidencePath,
  writeEvidenceFile,
  readEvidenceFile,
  ensureExportsDir
};
