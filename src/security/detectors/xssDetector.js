'use strict';

/**
 * XSS detector (contract §3, §4).
 * Pure function — no I/O, no DB access. Unit-tested by scripts/test-detectors.js
 */

const { XSS_RULES, BASE_SCORES, ATTACK_TYPES } = require('./rules');

/**
 * @typedef {import('./sqlDetector').Detection} Detection
 */

/**
 * @param {{ payload?: string|null }} input
 * @returns {Detection}
 */
function detect({ payload } = {}) {
  const value = typeof payload === 'string' ? payload : '';

  const notDetected = {
    detected: false,
    attackType: ATTACK_TYPES.XSS,
    matchedRule: null,
    baseScore: BASE_SCORES.XSS
  };

  if (!value) return notDetected;

  for (const rule of XSS_RULES) {
    if (rule.pattern.test(value)) {
      return {
        detected: true,
        attackType: ATTACK_TYPES.XSS,
        matchedRule: rule.id,
        baseScore: BASE_SCORES.XSS
      };
    }
  }

  return notDetected;
}

module.exports = { detect };
