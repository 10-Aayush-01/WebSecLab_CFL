'use strict';

/**
 * SQL Injection detector (contract §3, §4).
 * Pure function — no I/O, no DB access. Unit-tested by scripts/test-detectors.js
 */

const { SQLI_RULES, BASE_SCORES, ATTACK_TYPES } = require('./rules');

/**
 * @typedef {object} Detection
 * @property {boolean} detected
 * @property {'SQL_INJECTION'|'XSS'|'IDOR'} attackType
 * @property {string|null} matchedRule
 * @property {number} baseScore
 */

/**
 * @param {{ payload?: string|null }} input
 * @returns {Detection}
 */
function detect({ payload } = {}) {
  const value = typeof payload === 'string' ? payload : '';

  const notDetected = {
    detected: false,
    attackType: ATTACK_TYPES.SQL_INJECTION,
    matchedRule: null,
    baseScore: BASE_SCORES.SQL_INJECTION
  };

  if (!value) return notDetected;

  for (const rule of SQLI_RULES) {
    if (rule.pattern.test(value)) {
      return {
        detected: true,
        attackType: ATTACK_TYPES.SQL_INJECTION,
        matchedRule: rule.id,
        baseScore: BASE_SCORES.SQL_INJECTION
      };
    }
  }

  return notDetected;
}

module.exports = { detect };
