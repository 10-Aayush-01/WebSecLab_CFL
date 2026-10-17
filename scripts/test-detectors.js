'use strict';

/**
 * Detector unit tests: `npm run test:detectors`
 *
 * Detectors are pure functions, so they can be exercised without a server,
 * a database or a browser — which is also why they double as a viva demo.
 */

const sqlDetector = require('../src/security/detectors/sqlDetector');
const xssDetector = require('../src/security/detectors/xssDetector');
const idorDetector = require('../src/security/detectors/idorDetector');
const { ALL_RULES } = require('../src/security/detectors');

let passed = 0;
let failed = 0;

/**
 * @param {string} label
 * @param {boolean} ok
 * @param {string} [detail]
 */
function check(label, ok, detail = '') {
  if (ok) {
    passed += 1;
    console.log(`  PASS  ${label}`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

/** Asserts a payload produces the expected rule (or no detection at all). */
function expectRule(name, detector, input, expectedRule) {
  const result = detector.detect(input);
  check(
    `${name} -> ${expectedRule || 'no detection'}`,
    result.matchedRule === expectedRule,
    `got ${result.matchedRule || 'null'}`
  );
}

console.log('\nSQL Injection rules');
expectRule('plain word', sqlDetector, { payload: 'laptop' }, null);
expectRule('mixed case word', sqlDetector, { payload: 'Laptop Pro' }, null);
expectRule('name with apostrophe (O\'Brien)', sqlDetector, { payload: "O'Brien" }, null);
expectRule('possessive (men\'s)', sqlDetector, { payload: "men's shoes" }, null);
expectRule('arithmetic comparison', sqlDetector, { payload: '5 < 6' }, null);
expectRule('empty payload', sqlDetector, { payload: '' }, null);
expectRule('missing payload', sqlDetector, {}, null);
expectRule('tautology', sqlDetector, { payload: "' OR 1=1--" }, 'SQLI_TAUTOLOGY');
expectRule('tautology quoted', sqlDetector, { payload: "' OR '1'='1" }, 'SQLI_TAUTOLOGY');
expectRule('tautology hash comment', sqlDetector, { payload: "1' or 1=1#" }, 'SQLI_TAUTOLOGY');
expectRule('union select', sqlDetector, { payload: "' UNION SELECT email FROM users--" }, 'SQLI_UNION_SELECT');
expectRule('union all select', sqlDetector, { payload: "' union all select 1,2" }, 'SQLI_UNION_SELECT');
expectRule('stacked query', sqlDetector, { payload: "x'; DROP TABLE users;--" }, 'SQLI_STACKED_QUERY');
expectRule('comment terminator only', sqlDetector, { payload: "'--" }, 'SQLI_COMMENT_TERMINATOR');
expectRule('first match wins (tautology before comment)', sqlDetector, { payload: "' OR 1=1--" }, 'SQLI_TAUTOLOGY');

console.log('\nXSS rules');
expectRule('plain sentence', xssDetector, { payload: 'The search works well.' }, null);
expectRule('less-than comparison', xssDetector, { payload: '5 < 6 and 7 > 6' }, null);
expectRule('apostrophe', xssDetector, { payload: "It's fine" }, null);
expectRule('script tag', xssDetector, { payload: '<script>alert(document.domain)</script>' }, 'XSS_SCRIPT_TAG');
expectRule('script tag spaced', xssDetector, { payload: '<  script >alert(1)< / script >' }, 'XSS_SCRIPT_TAG');
expectRule('event handler', xssDetector, { payload: '<img src=x onerror=alert(1)>' }, 'XSS_EVENT_HANDLER');
expectRule('svg onload', xssDetector, { payload: '<svg/onload=alert(1)>' }, 'XSS_EVENT_HANDLER');
expectRule('javascript uri', xssDetector, { payload: '<a href="javascript:alert(1)">x</a>' }, 'XSS_JS_URI');
expectRule('html injection', xssDetector, { payload: '<img src=x>' }, 'XSS_HTML_INJECTION');
expectRule('iframe injection', xssDetector, { payload: '<iframe src="/"></iframe>' }, 'XSS_HTML_INJECTION');
expectRule('empty payload', xssDetector, { payload: '' }, null);

console.log('\nIDOR rule');
expectRule('own document', idorDetector, { userId: 2, ownerId: 2, resourceId: 3 }, null);
expectRule('another user\'s document', idorDetector, { userId: 2, ownerId: 3, resourceId: 5 }, 'IDOR_OWNER_MISMATCH');
expectRule('string ids that match', idorDetector, { userId: 2, ownerId: '2', resourceId: 5 }, null);
expectRule('string ids that differ', idorDetector, { userId: '2', ownerId: '3', resourceId: 5 }, 'IDOR_OWNER_MISMATCH');
expectRule('missing document (no owner)', idorDetector, { userId: 2, ownerId: null, resourceId: 999 }, null);
expectRule('anonymous request', idorDetector, { userId: null, ownerId: 3, resourceId: 5 }, null);

console.log('\nBase scores');
check(
  'SQL_INJECTION base score is 90',
  sqlDetector.detect({ payload: "' OR 1=1" }).baseScore === 90
);
check('XSS base score is 80', xssDetector.detect({ payload: '<script>' }).baseScore === 80);
check('IDOR base score is 85', idorDetector.detect({ userId: 1, ownerId: 2 }).baseScore === 85);

console.log('\nRule table');
check('9 detection rules are registered', ALL_RULES.length === 9, `found ${ALL_RULES.length}`);
check(
  'every rule id is unique',
  new Set(ALL_RULES.map((rule) => rule.id)).size === ALL_RULES.length
);

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exitCode = failed === 0 ? 0 : 1;
