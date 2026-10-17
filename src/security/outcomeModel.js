'use strict';

/**
 * Residual-risk outcome model.
 *
 * The global mode normally decides the outcome outright: VULNERABLE executes the
 * flaw, SAFE stops it. That is what the scripted demonstration depends on — the
 * same request, sent twice, changing only the mode, must give opposite results.
 *
 * The cost of that guarantee is that every event in the audit trail is one of
 * exactly two shapes, which does not look like an operations view. This module
 * adds the missing realistic tail: when RESIDUAL_RISK_RATE is configured above
 * 0, a small share of SAFE-mode attempts are decided the other way, because a
 * control that always engages is not how controls behave in the field.
 *
 *   SAFE + gap → the protection does NOT engage for this attempt. The vulnerable
 *                path really runs: the concatenated query really executes, the
 *                foreign document is really returned, the comment really renders
 *                unescaped. The event is a true record of what the application
 *                did — it is the application that was deliberately weakened.
 *   VULNERABLE → never gapped. There is nothing to fail there: this mode is the
 *                "controls off" mode by definition. What still stops an attempt
 *                in VULNERABLE mode is the least-privilege database role, and
 *                that is a real mechanism with real refusals, not a draw.
 *
 * Every affected event stores `request_data.outcomeBasis = 'RESIDUAL_RISK'`, so
 * an audit row always says which model produced it. Without that, an event
 * claiming "SAFE mode, attack successful" would be indistinguishable from a bug
 * in the protection.
 *
 * The rate defaults to 0 — off. Keep it off while recording the demonstration,
 * and for the acceptance suite, whose exact-outcome checks assume the mode
 * decides. Set it when you want the dashboard to look like a live environment:
 *
 *   RESIDUAL_RISK_RATE=0.12     # roughly one attempt in eight slips through SAFE
 */

const crypto = require('crypto');

const env = require('../config/env');

/** Which model produced an outcome. Stored on the event as request_data.outcomeBasis. */
const BASES = Object.freeze({
  /** The global mode decided it, exactly as the contract specifies. */
  MODE: 'MODE',
  /** The residual-risk draw skipped the SAFE controls for this attempt. */
  RESIDUAL_RISK: 'RESIDUAL_RISK'
});

/** Uniform draw in [0, 1) from the CSPRNG — no Math.random in an audit path. */
function draw() {
  return crypto.randomInt(0, 1_000_000) / 1_000_000;
}

/**
 * Decides whether the protections apply to one attempt.
 *
 * @param {object} input
 * @param {'SQL_INJECTION'|'XSS'|'IDOR'} input.attackType
 * @param {'SAFE'|'VULNERABLE'} input.mode
 * @param {number} [input.rate] override, used by the unit tests
 * @returns {{protectionApplied: boolean, basis: string, rate: number}}
 */
function decision({ attackType, mode, rate = env.residualRiskRate }) {
  const configured = Number.isFinite(rate) && rate > 0 ? rate : 0;

  if (mode !== 'SAFE' || configured === 0) {
    return { protectionApplied: mode === 'SAFE', basis: BASES.MODE, rate: configured };
  }

  const gapped = draw() < configured;
  return {
    protectionApplied: !gapped,
    basis: gapped ? BASES.RESIDUAL_RISK : BASES.MODE,
    rate: configured
  };
}

/**
 * One decision per request, memoised on res.locals.
 *
 * The XSS lab needs the same answer in two places before the body is written —
 * the CSP override (which runs first) and the controller's render branch — so
 * the draw has to be taken once and shared, or a request could have its policy
 * relaxed while its controller decides nothing was skipped.
 *
 * @param {import('express').Response} res
 * @param {'SQL_INJECTION'|'XSS'|'IDOR'} attackType
 */
function forRequest(res, attackType) {
  const existing = res.locals.outcomeDecision;
  if (existing && existing.attackType === attackType) return existing;

  const mode = res.locals.securityMode === 'VULNERABLE' ? 'VULNERABLE' : 'SAFE';
  const settled = { ...decision({ attackType, mode }), attackType };
  res.locals.outcomeDecision = settled;
  return settled;
}

/** True when the model is configured to skip protections on some attempts. */
const isEnabled = (rate = env.residualRiskRate) => Number.isFinite(rate) && rate > 0;

module.exports = { decision, forRequest, isEnabled, BASES };
