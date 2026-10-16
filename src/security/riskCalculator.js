'use strict';

/**
 * Risk scoring (contract §3).
 *
 * This is the "WebSecLab Educational Risk Score" — a transparent teaching
 * score. It is NOT CVSS and must never be labelled as CVSS anywhere in the UI,
 * the report or the evidence package.
 *
 *   base (SQL_INJECTION 90 | XSS 80 | IDOR 85)
 *   +5  result = SUCCESSFUL
 *   +5  authenticated actor (every lab route is authenticated)
 *   -10 result = BLOCKED or NEUTRALIZED
 *   clamp to 0-100
 */

const { BASE_SCORES } = require('./detectors/rules');

const RISK_LABEL = 'WebSecLab Educational Risk Score';
const RESULT_LABEL = 'WebSecLab Educational Risk Score (not CVSS)';

/** @type {ReadonlyArray<{severity: string, min: number, max: number}>} */
const SEVERITY_BANDS = Object.freeze([
  { severity: 'CRITICAL', min: 90, max: 100 },
  { severity: 'HIGH', min: 75, max: 89 },
  { severity: 'MEDIUM', min: 50, max: 74 },
  { severity: 'LOW', min: 0, max: 49 }
]);

/**
 * @param {number} score
 * @returns {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'}
 */
function severityFor(score) {
  const band = SEVERITY_BANDS.find((b) => score >= b.min && score <= b.max);
  return band ? band.severity : 'LOW';
}

/**
 * @param {object} input
 * @param {'SQL_INJECTION'|'XSS'|'IDOR'} input.attackType
 * @param {'DETECTED'|'SUCCESSFUL'|'BLOCKED'|'NEUTRALIZED'} input.result
 * @param {boolean} [input.authenticated] the actor was authenticated
 * @returns {{score: number, severity: string, label: string, breakdown: Array<{component: string, delta: number, running: number}>}}
 */
function calculate({ attackType, result, authenticated = false }) {
  const base = BASE_SCORES[attackType];
  if (!Number.isFinite(base)) {
    throw new Error(`riskCalculator: unknown attack type "${attackType}"`);
  }

  const breakdown = [{ component: `Base score for ${attackType}`, delta: base, running: base }];
  let score = base;

  if (result === 'SUCCESSFUL') {
    score += 5;
    breakdown.push({ component: 'Attack succeeded', delta: 5, running: score });
  }

  if (authenticated) {
    score += 5;
    breakdown.push({ component: 'Authenticated actor', delta: 5, running: score });
  }

  if (result === 'BLOCKED' || result === 'NEUTRALIZED') {
    score -= 10;
    breakdown.push({ component: `Attack ${result.toLowerCase()}`, delta: -10, running: score });
  }

  const clamped = Math.min(100, Math.max(0, score));
  if (clamped !== score) {
    breakdown.push({ component: 'Clamped to 0-100', delta: clamped - score, running: clamped });
  }

  return { score: clamped, severity: severityFor(clamped), label: RISK_LABEL, breakdown };
}

/**
 * The six expectations from contract §3, used by scripts/test-risk.js and by
 * the acceptance test so the score model cannot drift silently.
 */
const EXPECTED_SCORES = Object.freeze([
  { attackType: 'SQL_INJECTION', mode: 'VULNERABLE', result: 'SUCCESSFUL', score: 100, severity: 'CRITICAL' },
  { attackType: 'SQL_INJECTION', mode: 'SAFE', result: 'NEUTRALIZED', score: 85, severity: 'HIGH' },
  { attackType: 'XSS', mode: 'VULNERABLE', result: 'SUCCESSFUL', score: 90, severity: 'CRITICAL' },
  { attackType: 'XSS', mode: 'SAFE', result: 'NEUTRALIZED', score: 75, severity: 'HIGH' },
  { attackType: 'IDOR', mode: 'VULNERABLE', result: 'SUCCESSFUL', score: 95, severity: 'CRITICAL' },
  { attackType: 'IDOR', mode: 'SAFE', result: 'BLOCKED', score: 80, severity: 'HIGH' }
]);

module.exports = { calculate, severityFor, RISK_LABEL, RESULT_LABEL, SEVERITY_BANDS, EXPECTED_SCORES };
