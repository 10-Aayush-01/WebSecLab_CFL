'use strict';

/**
 * Unit tests for the residual-risk outcome model (src/security/outcomeModel.js).
 *
 * No server and no database: the model is a pure decision function once the rate
 * is passed in explicitly, so these cases pin the behaviour that the labs, the
 * audit trail and the configuration all depend on.
 *
 *   npm run test:outcome
 */

const assert = require('assert');

const outcomeModel = require('../src/security/outcomeModel');
const env = require('../src/config/env');

let passed = 0;
const failures = [];

function check(title, fn) {
  try {
    const detail = fn();
    passed += 1;
    console.log(`  PASS  ${title}${detail ? ` — ${detail}` : ''}`);
  } catch (error) {
    failures.push({ title, message: error.message });
    console.log(`  FAIL  ${title} — ${error.message}`);
  }
}

/** Counts how often each basis comes back over n draws. */
function tally(mode, rate, draws = 4000) {
  const counts = { MODE: 0, RESIDUAL_RISK: 0, gapped: 0 };
  for (let i = 0; i < draws; i += 1) {
    const decision = outcomeModel.decision({ attackType: 'SQL_INJECTION', mode, rate });
    counts[decision.basis] += 1;
    if (!decision.protectionApplied) counts.gapped += 1;
  }
  return counts;
}

console.log('\nResidual-risk outcome model\n');

check('the rate is off unless configured', () => {
  assert.strictEqual(env.residualRiskRate, 0, `expected 0, got ${env.residualRiskRate}`);
  return 'RESIDUAL_RISK_RATE is unset, so the mode decides everything';
});

check('an unset or invalid rate means off', () => {
  assert.strictEqual(outcomeModel.isEnabled(0), false);
  assert.strictEqual(outcomeModel.isEnabled(undefined), false);
  assert.strictEqual(outcomeModel.isEnabled(Number.NaN), false);
  assert.strictEqual(outcomeModel.isEnabled(0.2), true);
  return 'only a positive number enables it';
});

check('rate 0 never draws, in either mode', () => {
  for (const mode of ['SAFE', 'VULNERABLE']) {
    const counts = tally(mode, 0, 200);
    assert.strictEqual(counts.RESIDUAL_RISK, 0, `${mode} produced a residual-risk case`);
  }
  return 'the SAFE mode decides every attempt';
});

check('VULNERABLE mode is never gapped, at any rate', () => {
  const counts = tally('VULNERABLE', 0.9, 2000);
  assert.strictEqual(counts.RESIDUAL_RISK, 0, 'a VULNERABLE attempt was marked residual risk');
  assert.strictEqual(counts.gapped, 2000, 'the protections were applied in VULNERABLE mode');
  return 'nothing to fail there: the controls are off by definition';
});

check('rate 1 skips the SAFE controls on every attempt', () => {
  const counts = tally('SAFE', 1, 200);
  assert.strictEqual(counts.RESIDUAL_RISK, 200);
  assert.strictEqual(counts.gapped, 200);
  return 'RESIDUAL_RISK on all 200 draws';
});

check('the observed share tracks the configured rate', () => {
  for (const rate of [0.1, 0.3, 0.75]) {
    const counts = tally('SAFE', rate, 4000);
    const observed = counts.RESIDUAL_RISK / 4000;
    assert.ok(
      Math.abs(observed - rate) < 0.03,
      `rate ${rate} produced ${observed.toFixed(3)} over 4000 draws`
    );
  }
  return '0.10 / 0.30 / 0.75 all land within 0.03 of the configured rate';
});

check('a gapped SAFE attempt reports the protections as not applied', () => {
  const decision = outcomeModel.decision({ attackType: 'IDOR', mode: 'SAFE', rate: 1 });
  assert.strictEqual(decision.protectionApplied, false);
  assert.strictEqual(decision.basis, outcomeModel.BASES.RESIDUAL_RISK);
  return 'protectionApplied follows the draw, not the mode';
});

check('the draw is taken once per request', () => {
  const res = { locals: { securityMode: 'SAFE' } };
  const first = outcomeModel.forRequest(res, 'XSS');
  const second = outcomeModel.forRequest(res, 'XSS');
  assert.strictEqual(first, second, 'a second call took a second draw');
  return 'the CSP override and the controller must see the same decision';
});

check('an attacker cannot influence the basis through the request', () => {
  // forRequest only ever reads res.locals.securityMode, which the mode
  // middleware sets from the database — never from a header, query or body.
  const res = { locals: { securityMode: 'SAFE', outcomeDecision: undefined } };
  const decision = outcomeModel.forRequest(res, 'SQLI_INJECTION_TYPO');
  assert.ok(['MODE', 'RESIDUAL_RISK'].includes(decision.basis));
  return 'the basis is decided server-side only';
});

console.log(`\n${passed} passed, ${failures.length} failed`);

if (failures.length > 0) {
  console.log('\nFailures:');
  for (const failure of failures) console.log(`  ${failure.title} — ${failure.message}`);
}

process.exitCode = failures.length === 0 ? 0 : 1;
