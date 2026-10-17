'use strict';

/**
 * Static page content for the three labs (contract §8 / UI spec §12.4).
 *
 * Keeping the copy here means the three lab pages share exactly one template
 * shape — header, mode strip, explanation, interaction, result, comparison,
 * note — and the wording stays consistent between the app and the report.
 *
 * `protectionStatus(mode)` is honest: `always: true` marks a control that stays
 * on in BOTH modes, which is the whole point of the blast-radius design.
 */

const NOTE = 'Test only against this local WebSecLab instance.';

const SQLI = {
  key: 'SQLI',
  title: 'SQL Injection — Product Search',
  shortTitle: 'SQL Injection',
  path: '/labs/sql',
  purpose: 'Compare a string-built product search query with a parameterized one.',

  explanation: [
    'The search box feeds a SQL query against the products table. In VULNERABLE mode the',
    'term is concatenated straight into the SQL string, so characters such as an apostrophe',
    'change the meaning of the query. In SAFE mode the same term is sent as a bound parameter',
    'and is only ever treated as text. Watch what happens to the three unreleased products:',
    'a tautology makes the WHERE clause true for every row, including hidden data.'
  ].join(' '),

  /** @param {'SAFE'|'VULNERABLE'} mode */
  protectionStatus: (mode) => [
    { name: 'Parameterized query', on: mode === 'SAFE' },
    { name: 'Server-side validation (length, control characters)', on: mode === 'SAFE' },
    {
      name: 'Least-privilege database role (SELECT on products only)',
      on: true,
      always: true
    }
  ],

  comparison: {
    vulnerable: {
      handling: 'Search term concatenated into the SQL string',
      outcome: 'Injected SQL changes the query and returns extra rows',
      detection: 'Regex rule matches the payload',
      result: 'SUCCESSFUL — risk 100 (CRITICAL)'
    },
    safe: {
      handling: 'Bound parameter ($1); the payload is a literal string',
      outcome: 'No matching rows, or HTTP 400 when validation fails',
      detection: 'Same rule still matches the payload',
      result: 'NEUTRALIZED (85, HIGH) or BLOCKED (400)'
    }
  },

  examples: {
    normal: 'laptop',
    attack: "' OR 1=1--",
    equivalent: "' UNION SELECT 1,email,password_hash,'1','x' FROM users--"
  },

  note: NOTE
};

const XSS = {
  key: 'XSS',
  title: 'Cross-Site Scripting — Comments',
  shortTitle: 'XSS',
  path: '/labs/xss',
  purpose: 'Store a comment once, then see it execute or render as inert text as the mode changes.',

  explanation: [
    'A comment is stored exactly as submitted in both modes — the mode only decides how it is',
    'rendered. In VULNERABLE mode the view prints the stored text unescaped and the route',
    'relaxes its Content-Security-Policy, so markup and inline script execute. In SAFE mode the',
    'comment is HTML-escaped and the strict policy stays in place, so the same stored text is',
    'displayed as harmless characters. Comments written in VULNERABLE mode therefore become',
    'inert after switching to SAFE — the cleanest re-test demonstration in this project.'
  ].join(' '),

  /** @param {'SAFE'|'VULNERABLE'} mode */
  protectionStatus: (mode) => [
    { name: 'Context-aware output escaping', on: mode === 'SAFE' },
    { name: 'Strict Content-Security-Policy on this route', on: mode === 'SAFE' },
    { name: 'Session cookie is httpOnly', on: true, always: true },
    { name: 'Comment length and type validation', on: true, always: true }
  ],

  comparison: {
    vulnerable: {
      handling: 'Stored raw, rendered unescaped, inline script allowed',
      outcome: 'Payload executes in the browser of every visitor',
      detection: 'Regex rule matches the submitted comment',
      result: 'SUCCESSFUL — risk 90 (CRITICAL)'
    },
    safe: {
      handling: 'Stored raw, rendered escaped, strict CSP enforced',
      outcome: 'The same text is displayed, nothing executes',
      detection: 'Same rule still matches the submitted comment',
      result: 'NEUTRALIZED — risk 75 (HIGH)'
    }
  },

  examples: {
    normal: 'The search works well now, thanks.',
    attack: '<script>alert(document.domain)</script>',
    equivalent: '<img src=x onerror=alert(document.domain)>'
  },

  note: NOTE
};

const IDOR = {
  key: 'IDOR',
  title: 'Insecure Direct Object Reference — Documents',
  shortTitle: 'IDOR',
  path: '/labs/idor',
  purpose: 'Request a document id that belongs to another user and watch the authorization check.',

  explanation: [
    'Document ids are sequential, so the id in the URL is easy to guess. In VULNERABLE mode the',
    'controller fetches the document and returns it without ever comparing the owner to the',
    'signed-in user. In SAFE mode the same parameterized fetch is followed by a server-side',
    'ownership check, and a mismatch returns HTTP 403. The database query is parameterized in',
    'both modes on purpose: this lab must demonstrate broken access control alone, not SQL',
    'injection.'
  ].join(' '),

  /** @param {'SAFE'|'VULNERABLE'} mode */
  protectionStatus: (mode) => [
    { name: 'Authentication required', on: true, always: true },
    { name: 'Server-side ownership check', on: mode === 'SAFE' },
    { name: 'Parameterized document query', on: true, always: true },
    { name: 'No administrator bypass inside this lab', on: true, always: true }
  ],

  comparison: {
    vulnerable: {
      handling: 'Fetch by id, no ownership comparison',
      outcome: 'Another user\u2019s document is returned with HTTP 200',
      detection: 'userId !== ownerId on the requested document',
      result: 'SUCCESSFUL — risk 95 (CRITICAL)'
    },
    safe: {
      handling: 'Fetch by id, then compare owner_id with the session user',
      outcome: 'HTTP 403 — "You do not own this document"',
      detection: 'Same condition still evaluated',
      result: 'BLOCKED — risk 80 (HIGH)'
    }
  },

  examples: {
    normal: 'Open your own document from the list (no event is recorded).',
    attack: 'Change the id in the URL to a document owned by the other user.',
    equivalent: 'Ids are sequential. Any id that is not in your own list belongs to the other account.'
  },

  note: NOTE
};

const LABS = Object.freeze({ SQLI, XSS, IDOR });
const ALL_LABS = Object.freeze([SQLI, XSS, IDOR]);

/** @param {'SQLI'|'XSS'|'IDOR'} key */
const labContent = (key) => LABS[key];

module.exports = { LABS, ALL_LABS, labContent, SQLI, XSS, IDOR };
