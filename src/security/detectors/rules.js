'use strict';

/**
 * Detection rules (contract §4). First match wins.
 *
 * Deliberate trade-off, stated in the report: there is NO rule on a bare
 * apostrophe, because that would false-positive on legitimate input such as
 * "O'Brien" or "men's". Detection is regex-based and therefore evadable by
 * encoding or case tricks — this is an educational detector, not a WAF.
 */

const ATTACK_TYPES = Object.freeze({
  SQL_INJECTION: 'SQL_INJECTION',
  XSS: 'XSS',
  IDOR: 'IDOR'
});

/** Base score per attack type (contract §3). */
const BASE_SCORES = Object.freeze({
  SQL_INJECTION: 90,
  XSS: 80,
  IDOR: 85
});

/**
 * @typedef {object} Rule
 * @property {string} id          matched_rule value stored on the event
 * @property {string} attackType  SQL_INJECTION | XSS | IDOR
 * @property {RegExp|null} pattern evaluated against the payload (null for IDOR)
 * @property {string} description human-readable, reused in the report
 */

/** @type {Rule[]} evaluated in this exact order. */
const SQLI_RULES = [
  {
    id: 'SQLI_UNION_SELECT',
    attackType: ATTACK_TYPES.SQL_INJECTION,
    pattern: /union\s+(all\s+)?select/i,
    description: 'UNION SELECT — appends an attacker-controlled result set'
  },
  {
    id: 'SQLI_STACKED_QUERY',
    attackType: ATTACK_TYPES.SQL_INJECTION,
    pattern: /;\s*(drop|insert|update|delete|select)\b/i,
    description: 'Stacked query — terminates the statement and starts another'
  },
  {
    id: 'SQLI_TAUTOLOGY',
    attackType: ATTACK_TYPES.SQL_INJECTION,
    pattern: /['"]\s*(or|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+/i,
    description: 'Tautology — makes the WHERE clause true for every row (hidden data)'
  },
  {
    id: 'SQLI_COMMENT_TERMINATOR',
    attackType: ATTACK_TYPES.SQL_INJECTION,
    pattern: /['"].*(--|#|\/\*)/,
    description: 'Comment terminator — discards the remainder of the developer query'
  }
];

/** @type {Rule[]} evaluated in this exact order. */
const XSS_RULES = [
  {
    id: 'XSS_SCRIPT_TAG',
    attackType: ATTACK_TYPES.XSS,
    pattern: /<\s*script\b/i,
    description: 'Inline script tag'
  },
  {
    id: 'XSS_EVENT_HANDLER',
    attackType: ATTACK_TYPES.XSS,
    pattern: /<[^>]+\bon\w+\s*=/i,
    description: 'HTML tag with an inline event handler (onerror, onload, …)'
  },
  {
    id: 'XSS_JS_URI',
    attackType: ATTACK_TYPES.XSS,
    pattern: /javascript\s*:/i,
    description: 'javascript: URI in an href/src attribute'
  },
  {
    id: 'XSS_HTML_INJECTION',
    attackType: ATTACK_TYPES.XSS,
    pattern: /<\s*(img|svg|iframe|object|embed|body|link)\b/i,
    description: 'Injected HTML element able to load or execute content'
  }
];

/** IDOR is a logic condition, not a pattern; kept in the table for the report. */
const IDOR_RULES = [
  {
    id: 'IDOR_OWNER_MISMATCH',
    attackType: ATTACK_TYPES.IDOR,
    pattern: null,
    description: 'Authenticated user requested a resource whose owner_id differs'
  }
];

/** All rules, in evaluation order per attack type. */
const RULES_BY_TYPE = Object.freeze({
  SQL_INJECTION: SQLI_RULES,
  XSS: XSS_RULES,
  IDOR: IDOR_RULES
});

/** Flat list for documentation, the report and the rules table in the UI. */
const ALL_RULES = [...SQLI_RULES, ...XSS_RULES, ...IDOR_RULES];

module.exports = {
  ATTACK_TYPES,
  BASE_SCORES,
  SQLI_RULES,
  XSS_RULES,
  IDOR_RULES,
  RULES_BY_TYPE,
  ALL_RULES
};
