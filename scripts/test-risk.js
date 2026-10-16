'use strict';

/**
 * Risk model tests: `npm run test:risk`
 *
 * Reproduces the six expected score rows from the contract exactly, so the
 * scoring model cannot drift without a test failing, and checks the severity
 * bands and clamping behaviour.
 */

const riskCalculator = require('../src/security/riskCalculator');

const { EXPECTED_SCORES, calculate, severityFor } = riskCalculator;

let passed = 0;
let failed = 0;

function check(label, ok, detail = '') {
  if (ok) {
    passed += 1;
    console.log(`  PASS  ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

console.log('\nContract score table (authenticated actor, as in every lab route)');
for (const row of EXPECTED_SCORES) {
  const result = calculate({
    attackType: row.attackType,
    result: row.result,
    authenticated: true
  });

  check(
    `${row.attackType} in ${row.mode} mode, result ${row.result} -> ${row.score} ${row.severity}`,
    result.score === row.score && result.severity === row.severity,
    `got ${result.score} ${result.severity}`
  );
}

console.log('\nSeverity bands');
check('100 is CRITICAL', severityFor(100) === 'CRITICAL');
check('90 is CRITICAL', severityFor(90) === 'CRITICAL');
check('89 is HIGH', severityFor(89) === 'HIGH');
check('75 is HIGH', severityFor(75) === 'HIGH');
check('74 is MEDIUM', severityFor(74) === 'MEDIUM');
check('50 is MEDIUM', severityFor(50) === 'MEDIUM');
check('49 is LOW', severityFor(49) === 'LOW');
check('0 is LOW', severityFor(0) === 'LOW');

console.log('\nAdjustments and clamping');
const unauthBlocked = calculate({ attackType: 'XSS', result: 'BLOCKED', authenticated: false });
check('unauthenticated blocked XSS is 70 (80-10)', unauthBlocked.score === 70, `got ${unauthBlocked.score}`);

const detected = calculate({ attackType: 'IDOR', result: 'DETECTED', authenticated: true });
check('undetermined outcome adds nothing (85+5)', detected.score === 90, `got ${detected.score}`);

const clamped = calculate({ attackType: 'SQL_INJECTION', result: 'SUCCESSFUL', authenticated: true });
check('score never exceeds 100', clamped.score === 100, `got ${clamped.score}`);
check(
  'breakdown explains every adjustment',
  Array.isArray(clamped.breakdown) && clamped.breakdown.length >= 3,
  `entries: ${clamped.breakdown.length}`
);

const label = calculate({ attackType: 'XSS', result: 'SUCCESSFUL', authenticated: true }).label;
check('label is the WebSecLab Educational Risk Score', label === 'WebSecLab Educational Risk Score', label);

let threw = false;
try {
  calculate({ attackType: 'NOT_A_TYPE', result: 'SUCCESSFUL' });
} catch {
  threw = true;
}
check('unknown attack type throws', threw);

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exitCode = failed === 0 ? 0 : 1;
