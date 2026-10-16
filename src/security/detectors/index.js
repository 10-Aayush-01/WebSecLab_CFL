'use strict';

/**
 * Detector registry (contract §3).
 * The security monitor calls detectors[lab].detect(...) with the fields it has.
 */

const sqlDetector = require('./sqlDetector');
const xssDetector = require('./xssDetector');
const idorDetector = require('./idorDetector');
const rules = require('./rules');

/** Maps a labContext.lab value to its detector. */
const detectors = {
  SQLI: sqlDetector,
  XSS: xssDetector,
  IDOR: idorDetector
};

/**
 * Runs the detector for a lab.
 *
 * @param {'SQLI'|'XSS'|'IDOR'} lab
 * @param {{ payload?: string|null, userId?: number|null, ownerId?: number|null, resourceId?: number|null }} context
 * @returns {import('./sqlDetector').Detection}
 */
function detectForLab(lab, context) {
  const detector = detectors[lab];
  if (!detector) {
    return { detected: false, attackType: null, matchedRule: null, baseScore: 0 };
  }
  return detector.detect(context);
}

module.exports = { detectors, detectForLab, ...rules };
