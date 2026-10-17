'use strict';

/**
 * Result mapping (contract §3 table).
 *
 * The controller records what actually happened (`outcome`); the monitor turns
 * that plus the active security mode into the stored `result` value.
 *
 * DETECTED is reserved for a rule match whose outcome cannot be determined.
 */

/** @type {Record<string, Record<string, string>>} */
const OUTCOME_TO_RESULT = Object.freeze({
  EXECUTED_UNSAFE: 'SUCCESSFUL',
  NEUTRALIZED: 'NEUTRALIZED',
  BLOCKED: 'BLOCKED',
  NORMAL: 'DETECTED'
});

/**
 * @param {string|null|undefined} outcome  res.locals.labContext.outcome
 * @returns {'SUCCESSFUL'|'BLOCKED'|'NEUTRALIZED'|'DETECTED'}
 */
function mapResult(outcome) {
  return OUTCOME_TO_RESULT[outcome] || 'DETECTED';
}

/** Human-readable result text for the UI. */
const RESULT_LABELS = Object.freeze({
  SUCCESSFUL: 'Successful (attack worked)',
  BLOCKED: 'Blocked',
  NEUTRALIZED: 'Neutralized',
  DETECTED: 'Detected'
});

module.exports = { mapResult, OUTCOME_TO_RESULT, RESULT_LABELS };
