'use strict';

/**
 * IDOR detector (contract §3, §4).
 * A logic condition rather than a payload pattern: the authenticated user asked
 * for a document that belongs to somebody else.
 *
 * Pure function — no I/O, no DB access. Unit-tested by scripts/test-detectors.js
 */

const { IDOR_RULES, BASE_SCORES, ATTACK_TYPES } = require('./rules');

/**
 * @typedef {import('./sqlDetector').Detection} Detection
 */

/**
 * @param {object} input
 * @param {number|null} input.userId      the authenticated session user
 * @param {number|null} input.ownerId     owner_id of the requested document
 * @param {number|null} input.resourceId  the document id that was requested
 * @returns {Detection}
 */
function detect({ userId = null, ownerId = null } = {}) {
  const notDetected = {
    detected: false,
    attackType: ATTACK_TYPES.IDOR,
    matchedRule: null,
    baseScore: BASE_SCORES.IDOR
  };

  // A missing document (404) is not an attack and must never raise an event.
  if (userId === null || userId === undefined || ownerId === null || ownerId === undefined) {
    return notDetected;
  }

  if (Number(userId) !== Number(ownerId)) {
    return {
      detected: true,
      attackType: ATTACK_TYPES.IDOR,
      matchedRule: IDOR_RULES[0].id,
      baseScore: BASE_SCORES.IDOR
    };
  }

  return notDetected;
}

module.exports = { detect };
