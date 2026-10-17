'use strict';

/**
 * Request-data sanitizer (contract §5).
 *
 * `request_data` and the evidence package are built from an ALLOWLIST — we never
 * copy req.headers or req.body wholesale. Two layers of protection:
 *   1. buildRequestData() only ever emits the four known fields.
 *   2. redact() removes anything whose key looks like a credential, recursively.
 *
 * The same function runs again while building evidence (defence in depth).
 */

const MAX_STRING_LENGTH = 500;
const MAX_DEPTH = 6;
const MAX_ARRAY_ITEMS = 50;
const REDACTED = '[REDACTED]';
const TRUNCATED = '[TRUNCATED]';

/** Any key matching this is replaced with [REDACTED] before it is ever stored. */
const SENSITIVE_KEY_PATTERN = /pass|pwd|secret|token|cookie|session|authorization|csrf/i;

/** Truncates a string to the contract limit of 500 characters. */
function truncate(value) {
  if (typeof value !== 'string') return value;
  return value.length > MAX_STRING_LENGTH ? value.slice(0, MAX_STRING_LENGTH) : value;
}

/**
 * Recursively redacts sensitive keys and truncates long strings.
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {unknown} a JSON-safe, credential-free copy
 */
function redact(value, depth = 0) {
  if (value === null || value === undefined) return null;

  const type = typeof value;
  if (type === 'string') return truncate(value);
  if (type === 'number') return Number.isFinite(value) ? value : null;
  if (type === 'boolean') return value;
  if (type === 'bigint') return value.toString();
  if (value instanceof Date) return value.toISOString();
  if (depth >= MAX_DEPTH) return TRUNCATED;

  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => redact(item, depth + 1));
  }

  if (type === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) {
      result[key] = SENSITIVE_KEY_PATTERN.test(key) ? REDACTED : redact(item, depth + 1);
    }
    return result;
  }

  return String(value);
}

/**
 * Builds the stored request evidence from an allowlist of five fields.
 *
 * Four describe the request; `outcomeBasis` describes how the outcome was
 * decided (the global mode, or the residual-risk model skipping the controls),
 * which is what makes a successful attack in SAFE mode legible instead of
 * looking like a broken protection.
 *
 * @param {object} input
 * @param {string|null} [input.parameter]     the parameter that was tested (q, comment, id)
 * @param {string|null} [input.payload]       the raw tested input
 * @param {number|null} [input.resourceId]    the object id targeted (IDOR)
 * @param {string|null} [input.userAgent]     the client user agent
 * @param {'MODE'|'RESIDUAL_RISK'} [input.outcomeBasis] which model decided the result
 * @returns {{parameter: string|null, payload: string|null, resourceId: number|null, userAgent: string|null, outcomeBasis: string}}
 */
function buildRequestData({
  parameter = null,
  payload = null,
  resourceId = null,
  userAgent = null,
  outcomeBasis = 'MODE'
} = {}) {
  const resourceIdNumber = resourceId === null || resourceId === undefined ? null : Number(resourceId);

  const allowlisted = {
    parameter: parameter === null || parameter === undefined ? null : String(parameter),
    payload: payload === null || payload === undefined ? null : String(payload),
    resourceId: Number.isFinite(resourceIdNumber) ? resourceIdNumber : null,
    userAgent: userAgent === null || userAgent === undefined ? null : String(userAgent),
    outcomeBasis: outcomeBasis === 'RESIDUAL_RISK' ? 'RESIDUAL_RISK' : 'MODE'
  };

  return redact(allowlisted);
}

/**
 * Lists any sensitive keys still present in an object. Used by the acceptance
 * test (§15/5) to prove that no credential reached request_data or the evidence.
 *
 * @param {unknown} value
 * @param {string} [path]
 * @returns {string[]} dotted paths of offending keys
 */
function findSensitiveKeys(value, path = '$') {
  if (value === null || typeof value !== 'object') return [];

  const found = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => found.push(...findSensitiveKeys(item, `${path}[${index}]`)));
    return found;
  }

  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_KEY_PATTERN.test(key)) found.push(`${path}.${key}`);
    found.push(...findSensitiveKeys(item, `${path}.${key}`));
  }
  return found;
}

module.exports = {
  redact,
  truncate,
  buildRequestData,
  findSensitiveKeys,
  MAX_STRING_LENGTH,
  REDACTED,
  SENSITIVE_KEY_PATTERN
};
