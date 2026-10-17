'use strict';

/**
 * Acceptance tests (spec §15). Run against a server that is already listening:
 *
 *   npm run dev          # in one terminal
 *   npm run test:acceptance
 *
 * Override the target with WEB_SECLAB_URL. The suite drives the real HTTP
 * interface with its own cookie jar — it never calls controllers directly — and
 * checks the database, the views on disk and the exported evidence files.
 *
 * Side effects that are cleaned up: the global mode is restored to SAFE, and
 * the live `<script>` comment check 11 stores is deleted. Side effects that are
 * meant to remain: the security events and evidence packages the run itself
 * generates (they are the audit trail of the test).
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { Pool } = require('pg');

const env = require('../src/config/env');
const { pool, query } = require('../src/config/db');
const riskCalculator = require('../src/security/riskCalculator');
const { findSensitiveKeys } = require('../src/security/sanitizer');

const ROOT = path.join(__dirname, '..');
const BASE = process.env.WEB_SECLAB_URL || `http://127.0.0.1:${env.port}`;

/**
 * The one live script payload this suite stores, and the prefix that finds it
 * again. Check 11 and the cleanup share these two constants on purpose: if the
 * payload ever changes shape, the cleanup follows it without being edited.
 */
const XSS_TEST_PAYLOAD_PREFIX = "<script>alert('acceptance-";
const xssTestPayload = (marker) => `${XSS_TEST_PAYLOAD_PREFIX}${marker}')</script>`;

const ADMIN = { email: 'admin@webseclab.local', password: 'Admin-Lab-Demo-2026' };
const ALICE = { email: 'alice@webseclab.local', password: 'User-Lab-Demo-2026' };
const BOB = { email: 'bob@webseclab.local', password: 'User-Lab-Demo-2026' };

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// --------------------------------------------------------------------------
// tiny HTTP client with a cookie jar
// --------------------------------------------------------------------------
class Session {
  constructor(label) {
    this.label = label;
    this.cookies = new Map();
  }

  cookieHeader() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }

  storeCookies(response) {
    const raw =
      typeof response.headers.getSetCookie === 'function'
        ? response.headers.getSetCookie()
        : [response.headers.get('set-cookie')].filter(Boolean);

    for (const cookie of raw) {
      const pair = String(cookie).split(';')[0];
      const index = pair.indexOf('=');
      if (index === -1) continue;
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1).trim();
      if (value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  async fetch(pathname, options = {}) {
    const headers = { ...(options.headers || {}) };
    const cookie = this.cookieHeader();
    if (cookie) headers.Cookie = cookie;

    const response = await fetch(`${BASE}${pathname}`, { redirect: 'manual', ...options, headers });
    this.storeCookies(response);
    return response;
  }

  async get(pathname) {
    return this.fetch(pathname, { headers: { Accept: 'text/html' } });
  }

  async text(pathname) {
    const response = await this.get(pathname);
    return { status: response.status, location: response.headers.get('location'), body: await response.text() };
  }

  tokenFrom(html) {
    const match = /name="_csrf" value="([a-f0-9]+)"/.exec(html);
    return match ? match[1] : null;
  }

  /** Reads a fresh CSRF token from a page this session is allowed to view. */
  async csrf(page = '/labs/sql') {
    const { status, body } = await this.text(page);
    const token = this.tokenFrom(body);
    if (!token) throw new Error(`no CSRF token on ${page} (HTTP ${status})`);
    return token;
  }

  async post(pathname, fields, extraHeaders = {}, tokenPage = '/labs/sql') {
    const token = await this.csrf(tokenPage);
    return this.fetch(pathname, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...extraHeaders },
      body: new URLSearchParams({ _csrf: token, ...fields })
    });
  }
}

/** Signs in and returns a session bound to that account. */
async function signIn(account, label) {
  const session = new Session(label);
  const page = await session.text('/login');
  const token = session.tokenFrom(page.body);
  if (!token) throw new Error('the sign-in page did not carry a CSRF token');

  const response = await session.fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: token, email: account.email, password: account.password })
  });

  if (response.status !== 302) {
    throw new Error(`sign-in failed for ${account.email}: HTTP ${response.status}`);
  }
  return session;
}

// --------------------------------------------------------------------------
// assertions and reporting
// --------------------------------------------------------------------------
const results = [];

/** Optional filter: `node scripts/acceptance.js 6 12` runs only those checks. */
const only = process.argv.slice(2).map((value) => Number(value)).filter((value) => Number.isInteger(value));

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function check(id, title, fn) {
  if (only.length > 0 && !only.includes(id)) return;

  try {
    const detail = await fn();
    results.push({ id, title, pass: true, detail: detail || 'ok' });
    console.log(`  PASS  [${String(id).padStart(2)}] ${title}${detail ? ` — ${detail}` : ''}`);
  } catch (error) {
    results.push({ id, title, pass: false, detail: error.message });
    console.log(`  FAIL  [${String(id).padStart(2)}] ${title} — ${error.message}`);
  }
}

// --------------------------------------------------------------------------
// database helpers
// --------------------------------------------------------------------------
const latestEventId = async () =>
  Number((await query('SELECT COALESCE(max(id), 0) AS id FROM security_events')).rows[0].id);

/**
 * The monitor writes on response finish, so the event appears a moment after the
 * HTTP response is delivered. Wait for it instead of sleeping blindly.
 */
async function waitForEvent(where, params, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { rows } = await query(
      `SELECT * FROM security_events WHERE ${where} ORDER BY id DESC LIMIT 1`,
      params
    );
    if (rows.length === 1) return rows[0];
    await sleep(150);
  }
  throw new Error(`no security event matched: ${where}`);
}

async function currentMode() {
  return (await query('SELECT security_mode FROM app_settings WHERE id = 1')).rows[0].security_mode;
}

/**
 * Deletes the live script payloads this suite deliberately stores.
 *
 * Check 11 posts a real `<script>` comment to prove unescaped rendering. The row
 * must not outlive the run: the XSS lab renders every stored comment raw in
 * VULNERABLE mode, so a leftover payload fires `alert()` on every page view —
 * for the next demo, the next test run and the marker's browser alike.
 *
 * Only comments starting with the payload prefix are removed, so seeded and
 * hand-written comments are untouched. The prefix is bound as a parameter:
 * quoting a pattern by hand is exactly how this cleanup silently matched
 * nothing the first time it was written.
 *
 * @returns {Promise<number>} number of rows removed
 */
async function cleanupStoredXssPayloads() {
  const { rowCount } = await query('DELETE FROM comments WHERE comment LIKE $1', [
    `${XSS_TEST_PAYLOAD_PREFIX}%`
  ]);
  return rowCount;
}

async function setMode(session, mode) {
  if ((await currentMode()) === mode) return mode;

  const response = await session.post('/admin/mode', { mode, redirectTo: '/dashboard' }, {}, '/dashboard');
  assert(response.status === 302 || response.status === 200, `mode switch returned HTTP ${response.status}`);

  const after = await currentMode();
  assert(after === mode, `mode is ${after} after switching to ${mode}`);
  return after;
}

/** Recursively lists files under a directory. */
function walk(dir) {
  const found = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) found.push(...walk(full));
    else found.push(full);
  }
  return found;
}

/**
 * Inner text of the element with that id, as a browser would read it.
 *
 * Used to prove a copy button's `data-copy` selector actually resolves: the
 * button would look correct and copy nothing if the id were renamed.
 */
function elementText(html, id) {
  const pattern = new RegExp(`<([a-z0-9]+)[^>]*\\bid="${id}"[^>]*>([\\s\\S]*?)<\\/\\1>`, 'i');
  const match = pattern.exec(html);
  return match ? match[2].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim() : null;
}

/** Extracts one directive from a Content-Security-Policy header. */
const cspDirective = (header, name) =>
  String(header || '')
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(name)) || '';

// --------------------------------------------------------------------------
// the suite
// --------------------------------------------------------------------------
async function run() {
  console.log(`\nWebSecLab acceptance tests against ${BASE}\n`);
  console.log('Setup');

  const admin = await signIn(ADMIN, 'admin');
  const alice = await signIn(ALICE, 'alice');
  const bob = await signIn(BOB, 'bob');

  await setMode(admin, 'SAFE');
  console.log('  signed in as admin, alice and bob; global mode is SAFE\n');

  console.log('Contract checks');

  // 1 -----------------------------------------------------------------------
  await check(1, 'Passwords are bcrypt hashes, never plaintext', async () => {
    const { rows } = await query('SELECT email, password_hash FROM users ORDER BY id');
    assert(rows.length >= 3, `expected at least 3 accounts, found ${rows.length}`);

    for (const row of rows) {
      assert(row.password_hash.startsWith('$2'), `${row.email} is not a bcrypt hash`);
      const cost = Number(row.password_hash.split('$')[2]);
      assert(cost >= 10 && cost <= 12, `${row.email} uses bcrypt cost ${cost}, outside 10-12`);
    }

    const plaintext = rows.filter((row) =>
      [ADMIN.password, ALICE.password, BOB.password].includes(row.password_hash)
    );
    assert(plaintext.length === 0, 'a demo password is stored in plaintext');

    return `${rows.length} accounts, bcrypt cost ${rows[0].password_hash.split('$')[2]}`;
  });

  // 2 -----------------------------------------------------------------------
  await check(2, 'Fresh database defaults to SAFE mode', async () => {
    const column = await query(
      `SELECT column_default FROM information_schema.columns
        WHERE table_name = 'app_settings' AND column_name = 'security_mode'`
    );
    assert(column.rows.length === 1, 'app_settings.security_mode not found');
    assert(/SAFE/.test(column.rows[0].column_default), `schema default is ${column.rows[0].column_default}`);
    assert((await currentMode()) === 'SAFE', `current mode is ${await currentMode()}`);
    return "column default is 'SAFE'::character varying";
  });

  // 3 -----------------------------------------------------------------------
  await check(3, 'USER role is refused on every admin route', async () => {
    const routes = ['/dashboard', '/security/events', '/forensics/verify'];
    for (const route of routes) {
      const response = await alice.get(route);
      assert(response.status === 403, `${route} returned HTTP ${response.status} for a USER`);
    }

    const modeAttempt = await alice.post('/admin/mode', { mode: 'VULNERABLE', redirectTo: '/labs/sql' });
    assert(modeAttempt.status === 403, `mode switch returned HTTP ${modeAttempt.status} for a USER`);
    assert((await currentMode()) === 'SAFE', 'a USER changed the global mode');
    return `${routes.length} pages + the mode switch all returned 403`;
  });

  // 4 -----------------------------------------------------------------------
  await check(4, 'Risk score table reproduces the contract exactly', async () => {
    for (const row of riskCalculator.EXPECTED_SCORES) {
      const scored = riskCalculator.calculate({
        attackType: row.attackType,
        result: row.result,
        authenticated: true
      });
      assert(
        scored.score === row.score && scored.severity === row.severity,
        `${row.attackType}/${row.mode}/${row.result} scored ${scored.score} ${scored.severity}, expected ${row.score} ${row.severity}`
      );
    }
    return 'all six rows match';
  });

  // 5 -----------------------------------------------------------------------
  await check(5, 'No credential material in request_data or evidence', async () => {
    const { rows } = await query('SELECT id, request_data FROM security_events');
    for (const row of rows) {
      const offenders = findSensitiveKeys(row.request_data);
      assert(offenders.length === 0, `event ${row.id} stores sensitive keys: ${offenders.join(', ')}`);
    }

    const files = fs.existsSync(env.exportsDir)
      ? fs.readdirSync(env.exportsDir).filter((name) => name.endsWith('.json'))
      : [];

    for (const name of files) {
      const content = fs.readFileSync(path.join(env.exportsDir, name), 'utf8');
      const offenders = findSensitiveKeys(JSON.parse(content));
      assert(offenders.length === 0, `${name} stores sensitive keys: ${offenders.join(', ')}`);
      assert(!content.includes('$2b$'), `${name} contains a bcrypt hash`);
      assert(!/webseclab\.sid/.test(content), `${name} contains a session cookie`);
    }

    return `${rows.length} events and ${files.length} evidence files checked`;
  });

  // 6 -----------------------------------------------------------------------
  await check(6, 'Unescaped output is confined to the XSS lab and layout includes', async () => {
    // `<%- include(...) %>` is the layout mechanism and is allowed everywhere.
    // Any OTHER `<%- ... %>` renders data unescaped and is the real risk.
    const offenders = [];
    let unescapedDataRenders = 0;

    for (const file of walk(path.join(ROOT, 'views'))) {
      const source = fs.readFileSync(file, 'utf8');
      const relative = path.relative(ROOT, file);

      for (const match of source.matchAll(/<%-([\s\S]*?)%>/g)) {
        const expression = match[1].trim();
        if (expression.startsWith('include(')) continue;

        unescapedDataRenders += 1;
        const isLabRender = relative.endsWith('xss-lab.ejs') && expression.includes('comment.comment');
        if (!isLabRender) offenders.push(`${relative}: <%- ${expression} %>`);
      }
    }

    assert(offenders.length === 0, `unescaped data renders found: ${offenders.join(' | ')}`);
    assert(
      unescapedDataRenders === 1,
      `expected exactly one unescaped data render in the whole app, found ${unescapedDataRenders}`
    );

    const xssLab = fs.readFileSync(path.join(ROOT, 'views', 'labs', 'xss-lab.ejs'), 'utf8');
    const escaped = (xssLab.match(/<%= comment\.comment %>/g) || []).length;
    assert(escaped === 1, `expected exactly one escaped render beside it, found ${escaped}`);

    return 'one unescaped data render, in the VULNERABLE branch of the XSS lab only';
  });

  // 7 -----------------------------------------------------------------------
  await check(7, 'The unsafe SQL function exists in one file only', async () => {
    const name = 'searchProducts' + 'Unsafe';
    const hits = [...walk(path.join(ROOT, 'src')), ...walk(path.join(ROOT, 'scripts'))]
      .filter((file) => fs.readFileSync(file, 'utf8').includes(name))
      .map((file) => path.relative(ROOT, file));

    assert(hits.length === 1, `referenced in ${hits.length} files: ${hits.join(', ')}`);
    assert(hits[0].endsWith('sqlController.js'), `found in ${hits[0]}`);
    return hits[0];
  });

  // 8 -----------------------------------------------------------------------
  await check(8, 'The lab database role cannot reach users or write anything', async () => {
    const lab = new Pool({ connectionString: env.labDatabaseUrl, max: 1 });
    try {
      const products = await lab.query('SELECT count(*)::int AS total FROM products');
      assert(products.rows[0].total > 0, 'the lab role cannot read products at all');

      const forbidden = ['users', 'security_events', 'incident_actions', 'monitored_requests'];
      for (const table of forbidden) {
        let allowed = false;
        try {
          await lab.query(`SELECT 1 FROM ${table} LIMIT 1`);
          allowed = true;
        } catch (error) {
          assert(/permission denied/i.test(error.message), `unexpected error on ${table}: ${error.message}`);
        }
        assert(!allowed, `the lab role can read ${table}`);
      }

      let wrote = false;
      try {
        await lab.query(
          `INSERT INTO products (name, description, price, category) VALUES ('x', 'x', 1, 'x')`
        );
        wrote = true;
      } catch (error) {
        assert(/permission denied/i.test(error.message), `unexpected error writing: ${error.message}`);
      }
      assert(!wrote, 'the lab role can write to products');

      return 'SELECT on products only; refused everywhere else';
    } finally {
      await lab.end();
    }
  });

  console.log('\nLab lifecycle (attack -> detect -> log -> re-test)');

  const marker = Date.now();

  // 9 -----------------------------------------------------------------------
  await check(9, 'SQL injection: hidden data in VULNERABLE, neutralized in SAFE', async () => {
    const payload = "' OR 1=1--";

    await setMode(admin, 'VULNERABLE');
    const before = await latestEventId();

    const vulnerable = await alice.get(`/labs/sql?q=${encodeURIComponent(payload)}`);
    const vulnerableBody = await vulnerable.text();
    assert(vulnerable.status === 200, `VULNERABLE search returned HTTP ${vulnerable.status}`);
    assert(
      vulnerableBody.includes('ws-hidden-row'),
      'VULNERABLE search returned no rows marked as hidden data'
    );
    assert(
      vulnerableBody.includes('Falcon Pre-Release Laptop'),
      'the unreleased product did not appear in the VULNERABLE result'
    );

    const successEvent = await waitForEvent(
      `id > $1 AND attack_type = 'SQL_INJECTION' AND result = 'SUCCESSFUL'`,
      [before]
    );
    assert(
      successEvent.risk_score === 100 && successEvent.severity === 'CRITICAL',
      `VULNERABLE score ${successEvent.risk_score} ${successEvent.severity}`
    );
    assert(
      successEvent.matched_rule === 'SQLI_TAUTOLOGY',
      `matched rule was ${successEvent.matched_rule}`
    );
    assert(successEvent.security_mode === 'VULNERABLE', 'event recorded the wrong mode');

    await setMode(admin, 'SAFE');
    const safeBefore = await latestEventId();

    const safe = await alice.get(`/labs/sql?q=${encodeURIComponent(payload)}`);
    const safeBody = await safe.text();
    assert(safe.status === 200, `SAFE search returned HTTP ${safe.status}`);
    assert(!safeBody.includes('ws-hidden-row'), 'SAFE mode still marked rows as hidden data');
    assert(
      !safeBody.includes('Falcon Pre-Release Laptop'),
      'SAFE mode returned an unreleased product'
    );

    const neutralizedEvent = await waitForEvent(
      `id > $1 AND attack_type = 'SQL_INJECTION'`,
      [safeBefore]
    );
    assert(
      neutralizedEvent.result === 'NEUTRALIZED' &&
        neutralizedEvent.risk_score === 85 &&
        neutralizedEvent.severity === 'HIGH',
      `SAFE result ${neutralizedEvent.result} ${neutralizedEvent.risk_score} ${neutralizedEvent.severity}`
    );

    return 'hidden rows only in VULNERABLE; 100/CRITICAL then 85/HIGH';
  });

  // 10 ----------------------------------------------------------------------
  await check(10, 'SQL injection: over-length payload is blocked with HTTP 400 in SAFE', async () => {
    const payload = `' OR 1=1-- ${'A'.repeat(60)}`;
    const before = await latestEventId();

    const response = await alice.get(`/labs/sql?q=${encodeURIComponent(payload)}`);
    assert(response.status === 400, `expected HTTP 400, got ${response.status}`);

    const event = await waitForEvent(`id > $1 AND attack_type = 'SQL_INJECTION'`, [before]);
    assert(event.result === 'BLOCKED', `result was ${event.result}`);
    assert(event.status_code === 400, `event status code was ${event.status_code}`);
    return 'HTTP 400 and a BLOCKED event';
  });

  // 11 ----------------------------------------------------------------------
  await check(11, 'XSS: stored raw, executes in VULNERABLE, inert after switching to SAFE', async () => {
    const payload = xssTestPayload(marker);

    await setMode(admin, 'VULNERABLE');
    const before = await latestEventId();

    const posted = await alice.post('/labs/xss/comments', { comment: payload });
    assert(posted.status === 302, `comment post returned HTTP ${posted.status}`);

    const stored = await query('SELECT comment FROM comments WHERE comment = $1', [payload]);
    assert(stored.rowCount === 1, 'the comment was not stored exactly as submitted');

    const successEvent = await waitForEvent(
      `id > $1 AND attack_type = 'XSS' AND result = 'SUCCESSFUL'`,
      [before]
    );
    assert(
      successEvent.risk_score === 90 && successEvent.severity === 'CRITICAL',
      `XSS VULNERABLE score ${successEvent.risk_score} ${successEvent.severity}`
    );
    assert(successEvent.matched_rule === 'XSS_SCRIPT_TAG', `rule was ${successEvent.matched_rule}`);

    const vulnerableView = await alice.text('/labs/xss');
    assert(vulnerableView.body.includes(payload), 'VULNERABLE mode did not render the raw payload');

    await setMode(admin, 'SAFE');
    const safeBefore = await latestEventId();
    const safeView = await alice.text('/labs/xss');

    // The stored row is unchanged; only the rendered output must differ.
    const occurrences = safeView.body.split(payload).length - 1;
    const markerText = `acceptance-${marker}`;
    assert(occurrences === 0, `SAFE mode rendered the raw payload ${occurrences} time(s)`);
    assert(safeView.body.includes('&lt;script&gt;'), 'SAFE mode did not escape the script tag');
    assert(safeView.body.includes(markerText), 'the escaped comment is not visible on the page');

    return 'stored once, unescaped render only in VULNERABLE';
  });

  // 12 ----------------------------------------------------------------------
  await check(12, 'IDOR: HTTP 200 in VULNERABLE, HTTP 403 in SAFE', async () => {
    const foreign = (
      await query(
        `SELECT d.id FROM user_documents d
           JOIN users u ON u.id = d.owner_id
          WHERE u.email = $1 ORDER BY d.id LIMIT 1`,
        [BOB.email]
      )
    ).rows[0];
    assert(foreign, 'no seeded document for bob');

    const own = (
      await query(
        `SELECT d.id FROM user_documents d
           JOIN users u ON u.id = d.owner_id
          WHERE u.email = $1 ORDER BY d.id LIMIT 1`,
        [ALICE.email]
      )
    ).rows[0];
    assert(own, 'no seeded document for alice');

    await setMode(admin, 'VULNERABLE');
    const before = await latestEventId();

    const vulnerable = await alice.get(`/labs/idor/documents/${foreign.id}`);
    assert(vulnerable.status === 200, `VULNERABLE IDOR returned HTTP ${vulnerable.status}`);
    const vulnerableBody = await vulnerable.text();
    assert(vulnerableBody.includes(BOB.email), 'the foreign document was not returned');

    const successEvent = await waitForEvent(
      `id > $1 AND attack_type = 'IDOR' AND result = 'SUCCESSFUL'`,
      [before]
    );
    assert(
      successEvent.risk_score === 95 && successEvent.severity === 'CRITICAL',
      `IDOR VULNERABLE score ${successEvent.risk_score} ${successEvent.severity}`
    );
    assert(successEvent.matched_rule === 'IDOR_OWNER_MISMATCH', `rule was ${successEvent.matched_rule}`);

    await setMode(admin, 'SAFE');
    const safeBefore = await latestEventId();

    const safe = await alice.get(`/labs/idor/documents/${foreign.id}`);
    const safeBody = await safe.text();
    assert(safe.status === 403, `SAFE IDOR returned HTTP ${safe.status}`);
    assert(safeBody.includes('You do not own this document'), 'the 403 page did not explain the refusal');

    const blockedEvent = await waitForEvent(`id > $1 AND attack_type = 'IDOR'`, [safeBefore]);
    assert(
      blockedEvent.result === 'BLOCKED' &&
        blockedEvent.risk_score === 80 &&
        blockedEvent.severity === 'HIGH',
      `IDOR SAFE result ${blockedEvent.result} ${blockedEvent.risk_score} ${blockedEvent.severity}`
    );

    // Own document: served in SAFE mode and deliberately not an event.
    const ownBefore = await latestEventId();
    const ownDocument = await alice.get(`/labs/idor/documents/${own.id}`);
    assert(ownDocument.status === 200, `own document returned HTTP ${ownDocument.status}`);
    await sleep(600);
    const ownAfter = await latestEventId();
    assert(ownAfter === ownBefore, 'reading your own document raised a security event');

    return '200/SUCCESSFUL/95 then 403/BLOCKED/80; own document is silent';
  });

  // 13 ----------------------------------------------------------------------
  await check(13, 'XSS lab CSP is relaxed only in VULNERABLE mode', async () => {
    await setMode(admin, 'VULNERABLE');
    const vulnerable = await alice.get('/labs/xss');
    const vulnerableCsp = vulnerable.headers.get('content-security-policy');
    assert(
      /'unsafe-inline'/.test(cspDirective(vulnerableCsp, 'script-src')),
      'script-src does not allow inline script in VULNERABLE mode'
    );

    // The relaxation must not leak onto the other lab routes.
    const sqlLab = await alice.get('/labs/sql');
    const sqlCsp = sqlLab.headers.get('content-security-policy');
    assert(
      !/'unsafe-inline'/.test(cspDirective(sqlCsp, 'script-src')),
      'the relaxed policy leaked onto /labs/sql'
    );

    await setMode(admin, 'SAFE');
    const safe = await alice.get('/labs/xss');
    const safeCsp = safe.headers.get('content-security-policy');
    assert(
      !/'unsafe-inline'/.test(cspDirective(safeCsp, 'script-src')),
      'SAFE mode still allows inline script on the XSS lab'
    );
    assert(/'self'/.test(cspDirective(safeCsp, 'script-src')), 'script-src lost self in SAFE mode');

    return 'relaxed on /labs/xss in VULNERABLE only';
  });

  // 14 ----------------------------------------------------------------------
  await check(14, 'CSRF: an unsafe request without a token is refused', async () => {
    const response = await alice.fetch('/labs/xss/comments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'comment=no-token'
    });
    assert(response.status === 403, `expected HTTP 403, got ${response.status}`);

    const forged = await alice.fetch('/admin/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'mode=VULNERABLE'
    });
    assert(forged.status === 403, `forged mode switch returned HTTP ${forged.status}`);
    assert((await currentMode()) === 'SAFE', 'a token-less request changed the mode');

    return 'comment and mode switch both refused with 403';
  });

  console.log('\nForensics');

  // 15 ----------------------------------------------------------------------
  await check(15, 'Evidence export hashes the exact bytes it hands out', async () => {
    const incident = (
      await query('SELECT event_uuid FROM security_events ORDER BY occurred_at DESC, id DESC LIMIT 1')
    ).rows[0];
    assert(incident, 'no incident available to export');

    const token = await admin.csrf(`/forensics/${incident.event_uuid}`);
    const response = await admin.fetch(`/forensics/${incident.event_uuid}/export`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        'x-csrf-token': token
      },
      body: ''
    });
    assert(response.status === 200, `export returned HTTP ${response.status}`);

    const payload = await response.json();
    assert(payload.filename && payload.sha256, 'the export response is missing filename or hash');
    assert(/^[a-f0-9]{64}$/.test(payload.sha256), `sha256 looks wrong: ${payload.sha256}`);

    const download = await admin.fetch(payload.downloadUrl, { headers: { Accept: 'application/json' } });
    assert(download.status === 200, `download returned HTTP ${download.status}`);
    const bytes = await download.text();

    const crypto = require('crypto');
    const downloadedHash = crypto.createHash('sha256').update(bytes, 'utf8').digest('hex');
    assert(downloadedHash === payload.sha256, 'the downloaded bytes do not hash to the recorded value');
    assert(download.headers.get('x-evidence-sha256') === payload.sha256, 'download header hash mismatch');

    const evidence = JSON.parse(bytes);
    assert(evidence.incidentId === incident.event_uuid, 'the evidence names the wrong incident');
    assert(
      evidence.event.riskScoreLabel === 'WebSecLab Educational Risk Score (not CVSS)',
      `unexpected label: ${evidence.event.riskScoreLabel}`
    );
    assert(
      typeof evidence.recommendedMitigation === 'string' && evidence.recommendedMitigation.length > 20,
      'the evidence has no recommended mitigation'
    );
    assert(evidence.event.requestEvidence, 'the evidence has no requestEvidence block');

    // Recorded in the incident trail with its hash.
    const trail = await query(
      `SELECT evidence_sha256 FROM incident_actions
        WHERE action = 'EVIDENCE_EXPORTED' AND evidence_filename = $1`,
      [payload.filename]
    );
    assert(trail.rowCount === 1, 'the export was not recorded in incident_actions');
    assert(String(trail.rows[0].evidence_sha256).trim() === payload.sha256, 'the recorded hash differs');

    // Stash for the next two checks.
    run.exported = { incident, filename: payload.filename, bytes, sha256: payload.sha256 };
    return `${payload.filename} (${downloadedHash.slice(0, 16)}…)`;
  });

  // 16 ----------------------------------------------------------------------
  await check(16, 'Evidence verification passes for unchanged bytes', async () => {
    const exported = run.exported;
    assert(exported, 'the export check did not run');

    const token = await admin.csrf('/forensics/verify');
    const response = await admin.fetch('/forensics/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'x-csrf-token': token
      },
      body: JSON.stringify({ filename: exported.filename, content: exported.bytes })
    });
    assert(response.status === 200, `verify returned HTTP ${response.status}`);

    const result = await response.json();
    assert(result.verified === true, `expected verified true, got ${JSON.stringify(result)}`);
    assert(result.message === 'Evidence integrity verified.', `message was "${result.message}"`);

    const trail = await query(
      `SELECT action, description FROM incident_actions
        WHERE action = 'EVIDENCE_VERIFIED' AND evidence_filename = $1
        ORDER BY id DESC LIMIT 1`,
      [exported.filename]
    );
    assert(trail.rowCount === 1, 'the verification was not recorded');
    return result.message;
  });

  // 17 ----------------------------------------------------------------------
  await check(17, 'Evidence verification fails after a one-character edit', async () => {
    const exported = run.exported;
    assert(exported, 'the export check did not run');

    const edited = exported.bytes.replace('"1.0"', '"1.1"');
    assert(edited !== exported.bytes, 'the edit did not change the file');

    const token = await admin.csrf('/forensics/verify');
    const response = await admin.fetch('/forensics/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'x-csrf-token': token
      },
      body: JSON.stringify({ filename: exported.filename, content: edited })
    });
    assert(response.status === 200, `verify returned HTTP ${response.status}`);

    const result = await response.json();
    assert(result.verified === false, 'an edited file was reported as verified');
    assert(
      result.message === 'Evidence integrity check failed.',
      `message was "${result.message}"`
    );
    assert(result.expected === exported.sha256 && result.actual !== exported.sha256, 'the hashes do not differ');
    return `detected the change (${result.actual.slice(0, 12)}… vs ${result.expected.slice(0, 12)}…)`;
  });

  console.log('\nResilience and reporting');

  // 18 ----------------------------------------------------------------------
  await check(18, 'The application survives an unreachable database', async () => {
    const port = 3999;
    const child = spawn(process.execPath, [path.join(ROOT, 'src', 'server.js')], {
      cwd: ROOT,
      env: {
        ...process.env,
        PORT: String(port),
        DATABASE_URL: 'postgres://nobody:nobody@127.0.0.1:1/nothing',
        LAB_DATABASE_URL: 'postgres://nobody:nobody@127.0.0.1:1/nothing'
      },
      stdio: 'ignore'
    });

    try {
      const deadline = Date.now() + 15000;
      let health = null;

      while (Date.now() < deadline) {
        try {
          const response = await fetch(`http://127.0.0.1:${port}/health`);
          if (response.ok) {
            health = await response.json();
            break;
          }
        } catch {
          // still starting
        }
        await sleep(250);
      }

      assert(health, 'the server did not answer /health with a broken database');
      assert(health.securityMode === 'SAFE', `mode fell back to ${health.securityMode}, expected SAFE`);

      const login = await fetch(`http://127.0.0.1:${port}/login`);
      assert(login.status === 200, `/login returned HTTP ${login.status} with a broken database`);

      const protectedPage = await fetch(`http://127.0.0.1:${port}/security/events`, { redirect: 'manual' });
      assert(
        [302, 401, 403].includes(protectedPage.status),
        `/security/events returned HTTP ${protectedPage.status} with a broken database`
      );

      return 'started, answered HTTP and failed closed to SAFE';
    } finally {
      child.kill();
      await sleep(300);
    }
  });

  // 19 ----------------------------------------------------------------------
  await check(19, 'Dashboard numbers match raw SELECT counts', async () => {
    const response = await admin.get('/dashboard/data');
    assert(response.status === 200, `dashboard data returned HTTP ${response.status}`);
    const data = await response.json();

    const raw = (
      await query(`SELECT
        (SELECT count(*)::int FROM monitored_requests) AS monitored_requests,
        (SELECT count(*)::int FROM security_events) AS total_events,
        (SELECT count(*)::int FROM security_events WHERE result = 'SUCCESSFUL') AS successful,
        (SELECT count(*)::int FROM security_events WHERE result IN ('BLOCKED','NEUTRALIZED')) AS blocked`)
    ).rows[0];

    assert(
      data.summary.monitored_requests === raw.monitored_requests,
      `monitored requests ${data.summary.monitored_requests} != ${raw.monitored_requests}`
    );
    assert(data.summary.total_events === raw.total_events, 'event total mismatch');
    assert(data.summary.successful_attacks === raw.successful, 'successful attack count mismatch');
    assert(data.summary.blocked_attacks === raw.blocked, 'blocked count mismatch');

    const chartTotal = data.attackDistribution.values.reduce((sum, value) => sum + value, 0);
    assert(chartTotal === raw.total_events, `chart series sums to ${chartTotal}, expected ${raw.total_events}`);
    assert(data.eventsOverTime.labels.length === 14, 'the time series is not 14 days long');

    return `${data.summary.total_events} events, ${data.summary.monitored_requests} monitored requests`;
  });

  // 20 ----------------------------------------------------------------------
  await check(20, 'Monitored requests are flagged only when an event is written', async () => {
    const totals = (
      await query(`SELECT
        (SELECT count(*)::int FROM monitored_requests) AS monitored,
        (SELECT count(*)::int FROM monitored_requests WHERE flagged) AS flagged,
        (SELECT count(*)::int FROM security_events) AS events`)
    ).rows[0];

    assert(totals.monitored > totals.events, 'fewer monitored requests than events — monitoring is incomplete');
    assert(totals.flagged > 0, 'no monitored request was ever flagged');
    assert(totals.flagged <= totals.events, 'more flagged requests than events');
    return `${totals.monitored} monitored, ${totals.flagged} flagged, ${totals.events} events`;
  });

  // 21 ----------------------------------------------------------------------
  // The theme is an interface preference, not a security control, but it must be
  // resolved before the first paint or the page flashes the wrong colours.
  await check(21, 'Theme preference is resolved server-side for the first paint', async () => {
    for (const choice of ['light', 'dark', 'system']) {
      const session = new Session(`theme:${choice}`);
      session.cookies.set('ws_theme', choice);

      const { status, body } = await session.text('/login');
      assert(status === 200, `HTTP ${status} for ws_theme=${choice}`);

      const tag = /<html[^>]*>/.exec(body);
      assert(tag, 'the response carried no <html> tag');

      if (choice === 'system') {
        assert(!/data-theme=/.test(tag[0]), `system must leave the choice to CSS, got ${tag[0]}`);
      } else {
        assert(tag[0].includes(`data-theme="${choice}"`), `${choice} rendered ${tag[0]}`);
      }
    }
    return 'light and dark pinned in the HTML, system left to prefers-color-scheme';
  });

  // 22 ----------------------------------------------------------------------
  await check(22, 'The theme toggle is served, wired and accessible', async () => {
    const tokensResponse = await fetch(`${BASE}/css/tokens.css`);
    assert(tokensResponse.status === 200, `tokens.css returned HTTP ${tokensResponse.status}`);
    const tokens = await tokensResponse.text();
    for (const [label, needle] of [
      ['dark theme block', ':root[data-theme="dark"]'],
      ['system media query', 'prefers-color-scheme: dark'],
      ['reduced-motion guard', 'prefers-reduced-motion']
    ]) {
      assert(tokens.includes(needle), `tokens.css has no ${label}`);
    }

    const scriptResponse = await fetch(`${BASE}/js/theme.js`);
    assert(scriptResponse.status === 200, `theme.js returned HTTP ${scriptResponse.status}`);
    const script = await scriptResponse.text();
    assert(script.includes('themechange'), 'theme.js never announces a theme change, so charts would keep stale colours');
    assert(/samesite/i.test(script), 'theme.js does not persist the choice in a cookie');

    const { status, body } = await admin.text('/dashboard');
    assert(status === 200, `dashboard returned HTTP ${status}`);

    const buttons = body.match(/data-theme-choice="(light|dark|system)"/g) || [];
    assert(buttons.length === 3, `expected 3 theme buttons, found ${buttons.length}`);
    assert(
      (body.match(/aria-pressed="true"/g) || []).length === 1,
      'exactly one theme button must be pressed, or a screen reader cannot tell which theme is active'
    );
    assert(body.includes('aria-controls="ws-sidebar"'), 'the mobile navigation toggle is missing from the top bar');
    assert(body.includes('data-nav-close'), 'the drawer has no way to be dismissed');

    return '3 theme controls (1 pressed), drawer toggle and dismiss controls present';
  });

  // 23 ----------------------------------------------------------------------
  // A same-specificity media query only wins when it appears after the rule it
  // overrides. The responsive grid collapse was silently dead before this check.
  await check(23, 'Responsive rules override the components they replace', async () => {
    const css = fs.readFileSync(path.join(ROOT, 'public', 'css', 'app.css'), 'utf8');

    const baseGrid = css.indexOf('.ws-grid-2 { display: grid;');
    assert(baseGrid !== -1, 'the .ws-grid-2 base rule is missing');
    const collapse = css.indexOf('.ws-grid-2 { grid-template-columns: minmax(0, 1fr); }');
    assert(collapse !== -1, 'the <=900px single-column grid rule is missing');
    assert(
      collapse > baseGrid,
      'the grid collapse is declared before its base rule, so the cascade discards it'
    );

    assert(
      css.includes('.ws-grid-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));'),
      '.ws-grid-2 must use minmax(0, 1fr): a bare 1fr track cannot shrink below a canvas'
    );

    const rigid = [...css.matchAll(/grid-template-columns:\s*([^;]+);/g)]
      .map((match) => match[1].trim())
      // A single track has nothing to shrink against; only multi-track rows are
      // at risk of forcing the page into horizontal scroll.
      .filter((value) => /(^|\s)1fr(\s|$)/.test(value) && /[\s,]/.test(value));
    assert(rigid.length === 0, `grid rows using a bare 1fr: ${rigid.join(' | ')}`);

    const drawer = css.lastIndexOf('body.ws-nav-open .ws-sidebar');
    assert(drawer > css.indexOf('.ws-sidebar {'), 'the drawer rules must follow the sidebar base rule');

    return `collapse at ${collapse} > base at ${baseGrid}; no unsrinkable grid rows`;
  });

  // 24 ----------------------------------------------------------------------
  // A sticky box is sized by its own content, so a rail that is itself sticky
  // stops at its last nav item and leaves its background and right border
  // hanging in mid-column. The rail must stretch and the stickiness must live
  // on an inner box that is reset again inside the mobile drawer.
  await check(24, 'The sidebar rail spans the full column height', async () => {
    const css = fs.readFileSync(path.join(ROOT, 'public', 'css', 'app.css'), 'utf8');
    const sidebar = fs.readFileSync(
      path.join(ROOT, 'views', 'partials', 'sidebar.ejs'),
      'utf8'
    );

    const railStart = css.indexOf('.ws-sidebar {');
    const innerStart = css.indexOf('.ws-sidebar__inner {');
    assert(railStart !== -1, 'the .ws-sidebar base rule is missing');
    assert(innerStart > railStart, 'the .ws-sidebar__inner rule must follow the rail rule');

    const rail = css.slice(railStart, innerStart);
    assert(
      /align-self:\s*stretch/.test(rail),
      'the rail must stretch to the shell height, or its border stops mid-page'
    );
    assert(
      !/position:\s*sticky/.test(rail),
      'the rail itself must not be sticky: a sticky box sizes to its own content'
    );

    const inner = css.slice(innerStart, css.indexOf('}', innerStart) + 1);
    assert(/position:\s*sticky/.test(inner), 'the inner box is what must stick');
    assert(
      /max-height:\s*calc\(100vh/.test(inner),
      'the inner box must be capped so a long nav scrolls instead of overflowing'
    );

    // The drawer scrolls as a whole, so the inner box must stop sticking there.
    const drawerStart = css.lastIndexOf('.ws-sidebar__inner {');
    const drawerInner = css.slice(drawerStart, css.indexOf('}', drawerStart) + 1);
    assert(
      /position:\s*static/.test(drawerInner),
      'the inner box must be reset to static inside the <=900px drawer'
    );

    const wrapper = sidebar.indexOf('<div class="ws-sidebar__inner">');
    assert(
      wrapper !== -1 && wrapper < sidebar.indexOf('<nav'),
      'sidebar.ejs must wrap the navigation in .ws-sidebar__inner'
    );

    return 'rail stretches to the shell height; the inner box sticks and is reset in the drawer';
  });

  // 25 ----------------------------------------------------------------------
  // Checks 9, 10, 12 and 13 assert that the MODE decides the outcome. The
  // residual-risk model is the one feature that overrides that on purpose, so a
  // run with it enabled cannot verify those checks. Say so here, once, instead
  // of letting them fail as a mysterious flake later.
  await check(25, 'The residual-risk outcome model is off, so the outcome checks mean something', async () => {
    assert(
      env.residualRiskRate === 0,
      `RESIDUAL_RISK_RATE=${env.residualRiskRate} is set in .env: the exact-outcome checks above assume the mode ` +
        'decides every result. Unset it to run the full suite.'
    );

    // The suite reads .env; the SERVER may have been started with something
    // else. The events page reports the server's setting, so check that too.
    const { status, body } = await admin.text('/security/events');
    assert(status === 200, `security events returned HTTP ${status}`);
    assert(
      !/residual-risk model is\s*<strong>on<\/strong>/.test(body),
      'the running server has the residual-risk model enabled'
    );

    return 'off in .env and on the running server; the mode decides every result';
  });

  // 26 ----------------------------------------------------------------------
  // The example payloads, the request paths and the hashes are the values the
  // demonstration copies into Burp or into a form. A renamed id would leave a
  // button that looks right and copies nothing, so bind them here.
  await check(26, 'Every attack payload and request path has a copy button that resolves', async () => {
    const own = (
      await query(
        `SELECT d.id FROM user_documents d
           JOIN users u ON u.id = d.owner_id
          WHERE u.email = $1 ORDER BY d.id LIMIT 1`,
        [ALICE.email]
      )
    ).rows[0];
    assert(own, 'no seeded document for alice');

    const pages = [
      {
        path: '/labs/sql?q=laptop',
        minimum: 5,
        required: ['sql-example-normal', 'sql-example-tautology', 'sql-example-union', 'request-path', 'executed-sql']
      },
      {
        path: '/labs/xss',
        minimum: 3,
        required: ['xss-example-normal', 'xss-example-script', 'xss-example-handler']
      },
      { path: '/labs/idor', minimum: 1, required: [] },
      { path: `/labs/idor/documents/${own.id}`, minimum: 2, required: ['doc-request-path', 'doc-next-path'] }
    ];

    let buttons = 0;

    for (const page of pages) {
      const { status, body } = await alice.text(page.path);
      assert(status === 200, `${page.path} returned HTTP ${status}`);

      const targets = [...body.matchAll(/data-copy="#([^"]+)"/g)].map((match) => match[1]);
      assert(
        targets.length >= page.minimum,
        `${page.path} serves ${targets.length} copy button(s), expected at least ${page.minimum}`
      );
      assert(
        new Set(targets).size === targets.length,
        `${page.path} reuses a copy target, so one of the buttons copies the wrong value`
      );

      for (const id of page.required) {
        assert(targets.includes(id), `${page.path} no longer offers a copy button for #${id}`);
      }

      for (const id of targets) {
        const text = elementText(body, id);
        assert(text !== null, `${page.path} has a copy button pointing at #${id}, which the page does not render`);
        assert(text.length > 0, `${page.path}: #${id} is empty, so its button copies nothing`);
        buttons += 1;
      }
    }

    return `${buttons} copy targets resolve across four lab pages`;
  });

  // Restore the documented default state.
  await setMode(admin, 'SAFE');
}

// --------------------------------------------------------------------------
(async () => {
  try {
    await run();
  } catch (error) {
    console.error(`\nFATAL: ${error.stack || error.message}`);
    results.push({ id: 0, title: 'suite completed', pass: false, detail: error.message });
  } finally {
    const failed = results.filter((result) => !result.pass);
    console.log(`\n${results.length - failed.length} passed, ${failed.length} failed`);

    if (failed.length > 0) {
      console.log('\nFailures:');
      for (const result of failed) console.log(`  [${result.id}] ${result.title} — ${result.detail}`);
    }

    try {
      await query('UPDATE app_settings SET security_mode = $1 WHERE id = 1', ['SAFE']);
    } catch {
      // nothing more we can do here
    }

    try {
      const removed = await cleanupStoredXssPayloads();
      if (removed > 0) {
        console.log(`\nRemoved ${removed} stored XSS test payload(s) from the comments table.`);
      }
    } catch (error) {
      console.log(`\nWARNING: could not remove the stored XSS test payloads: ${error.message}`);
    }

    await pool.end();
    process.exitCode = failed.length === 0 ? 0 : 1;
  }
})();
