'use strict';

/**
 * Demo traffic generator.
 *
 *   npm run demo:traffic          # 21 recorded attacks + 6 benign requests
 *   npm run demo:traffic -- --dry # print the plan, send nothing
 *
 * WHY THIS EXISTS
 * A database that has only ever seen hand-made requests looks like exactly
 * that: a dozen rows with one payload, one browser and one account. This script
 * drives the three labs through the real HTTP interface with a varied set of
 * payloads, accounts, user agents and modes, so the events table, the dashboard
 * charts and the forensic console have realistic activity to show.
 *
 * Every row it produces is a GENUINE record: the request really is sent, the
 * detector really runs, the risk score really is calculated and the monitor
 * really writes the row. Nothing here is inserted into the database directly —
 * the alternative (writing invented rows with invented timestamps and source
 * IPs) would put fabricated evidence in an audit log, and this project's whole
 * claim is that the audit trail can be trusted.
 *
 * CONSEQUENCES, STATED PLAINLY
 *   - source_ip will be the loopback address, because that is the truth for a
 *     local lab. The user agents vary because those really are different
 *     clients; the source address does not, and pretending otherwise would be
 *     the one thing a forensics demo must not do.
 *   - the timestamps are the real time you run the script, so the 14-day chart
 *     fills in around "now", not spread across the past.
 *   - events are additive: re-running it adds more traffic, which is what real
 *     traffic does.
 *
 * The live `<script>` comments the XSS scenarios post are deleted again on the
 * way out (see cleanupDemoComments). They would otherwise fire alert() on every
 * VULNERABLE-mode page view — including yours, mid-demo.
 *
 * Exit status is 0 only when every scenario produced the event it predicted,
 * so this doubles as a smoke test of the running application.
 */

const env = require('../src/config/env');
const { pool, query } = require('../src/config/db');
const riskCalculator = require('../src/security/riskCalculator');

const BASE = process.env.WEB_SECLAB_URL || `http://127.0.0.1:${env.port}`;
const DRY = process.argv.includes('--dry');

/**
 * Whether the mode decides every result. With the residual-risk model on, the
 * scenario table describes the outcome you EXPECT to be typical, not the one
 * every attempt must produce, so the exact-result assertions stand down.
 */
const RESIDUAL_RISK_RATE = env.residualRiskRate;
let residualCases = 0;

/** Marks every comment this script writes, so it can remove exactly those. */
const DEMO_MARKER = 'demo-traffic';

const ACCOUNTS = {
  admin: { email: 'admin@webseclab.local', password: 'Admin-Lab-Demo-2026' },
  alice: { email: 'alice@webseclab.local', password: 'User-Lab-Demo-2026' },
  bob: { email: 'bob@webseclab.local', password: 'User-Lab-Demo-2026' }
};

/**
 * Clients the scenarios claim to come from. Only the user-agent header varies:
 * a real request from Burp or sqlmap carries its own string, and that string is
 * what the monitor stores in request_data, so the variation is recorded rather
 * than asserted.
 */
const CLIENTS = {
  chrome: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
  firefox: 'Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
  safari: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
  edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
  curl: 'curl/8.10.1',
  sqlmap: 'sqlmap/1.8.9#stable (https://sqlmap.org)',
  burp: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 BurpSuite/2024.10'
};

// --------------------------------------------------------------------------
// HTTP client — deliberately independent of scripts/acceptance.js so that
// demo traffic can never change what the contract tests assert.
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
    if (options.userAgent) headers['User-Agent'] = options.userAgent;

    const response = await fetch(`${BASE}${pathname}`, {
      redirect: 'manual',
      ...options,
      headers
    });
    this.storeCookies(response);
    return response;
  }

  async get(pathname, userAgent) {
    return this.fetch(pathname, { headers: { Accept: 'text/html' }, userAgent });
  }

  async text(pathname, userAgent) {
    const response = await this.get(pathname, userAgent);
    return { status: response.status, body: await response.text() };
  }

  tokenFrom(html) {
    const match = /name="_csrf" value="([a-f0-9]+)"/.exec(html);
    return match ? match[1] : null;
  }

  async csrf(page = '/labs/sql', userAgent) {
    const { status, body } = await this.text(page, userAgent);
    const token = this.tokenFrom(body);
    if (!token) throw new Error(`no CSRF token on ${page} (HTTP ${status})`);
    return token;
  }

  async post(pathname, fields, userAgent, tokenPage = '/labs/sql') {
    const token = await this.csrf(tokenPage, userAgent);
    return this.fetch(pathname, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: token, ...fields }),
      userAgent
    });
  }
}

async function signIn(key) {
  const account = ACCOUNTS[key];
  const session = new Session(key);
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
// scenarios
// --------------------------------------------------------------------------

/**
 * Payloads are grouped so each one genuinely triggers the rule it claims: the
 * script asserts the stored matched_rule afterwards, so a payload that stopped
 * matching its rule fails the run instead of quietly producing a wrong row.
 *
 * The `target` field is resolved at run time to a document id owned by another
 * account — the IDOR lab has no administrator bypass, so "another account" is
 * a real boundary in every scenario.
 */
const SCENARIOS = [
  // --- SQL injection ------------------------------------------------------
  {
    label: 'tautology returns hidden rows',
    lab: 'SQL_INJECTION',
    mode: 'VULNERABLE',
    actor: 'alice',
    client: 'chrome',
    payload: "' OR 1=1--",
    rule: 'SQLI_TAUTOLOGY',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'quoted tautology variant',
    lab: 'SQL_INJECTION',
    mode: 'VULNERABLE',
    actor: 'bob',
    client: 'sqlmap',
    payload: "laptop' OR '1'='1",
    rule: 'SQLI_TAUTOLOGY',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'UNION SELECT on the product columns',
    lab: 'SQL_INJECTION',
    mode: 'VULNERABLE',
    actor: 'alice',
    client: 'burp',
    payload: "' UNION SELECT 1,'injected row','x',1,'Accessories'--",
    rule: 'SQLI_UNION_SELECT',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'stacked DROP refused by the lab role',
    lab: 'SQL_INJECTION',
    mode: 'VULNERABLE',
    actor: 'alice',
    client: 'sqlmap',
    payload: "'; DROP TABLE products--",
    rule: 'SQLI_STACKED_QUERY',
    result: 'BLOCKED',
    status: 500
  },
  {
    label: 'comment terminator',
    lab: 'SQL_INJECTION',
    mode: 'VULNERABLE',
    actor: 'bob',
    client: 'curl',
    payload: "admin'--",
    rule: 'SQLI_COMMENT_TERMINATOR',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'same tautology, bound parameter',
    lab: 'SQL_INJECTION',
    mode: 'SAFE',
    actor: 'alice',
    client: 'chrome',
    payload: "' OR 1=1--",
    rule: 'SQLI_TAUTOLOGY',
    result: 'NEUTRALIZED',
    status: 200
  },
  {
    label: 'long tautology rejected by validation',
    lab: 'SQL_INJECTION',
    mode: 'SAFE',
    actor: 'bob',
    client: 'sqlmap',
    // 59 characters: past the 50-character limit the search validator applies.
    payload: "' OR 1=1 OR 2=2 OR 3=3 OR 4=4 OR 5=5 OR 6=6 OR 7=7 OR 8=8--",
    rule: 'SQLI_TAUTOLOGY',
    result: 'BLOCKED',
    status: 400
  },
  {
    label: 'stacked DROP, parameterized this time',
    lab: 'SQL_INJECTION',
    mode: 'SAFE',
    actor: 'alice',
    client: 'sqlmap',
    payload: "'; DROP TABLE products--",
    rule: 'SQLI_STACKED_QUERY',
    result: 'NEUTRALIZED',
    status: 200
  },
  {
    label: 'UNION payload longer than the 50-character limit',
    lab: 'SQL_INJECTION',
    mode: 'SAFE',
    actor: 'bob',
    client: 'burp',
    payload: "' UNION SELECT 1,email,password_hash,'1','x' FROM users--",
    rule: 'SQLI_UNION_SELECT',
    result: 'BLOCKED',
    status: 400
  },

  // --- Stored XSS ---------------------------------------------------------
  {
    label: 'inline script in a comment',
    lab: 'XSS',
    mode: 'VULNERABLE',
    actor: 'alice',
    client: 'chrome',
    payload: `<script>alert('${DEMO_MARKER}-1')</script>`,
    rule: 'XSS_SCRIPT_TAG',
    result: 'SUCCESSFUL',
    status: 302
  },
  {
    label: 'image with an onerror handler',
    lab: 'XSS',
    mode: 'VULNERABLE',
    actor: 'bob',
    client: 'firefox',
    payload: `<img src=x onerror=alert('${DEMO_MARKER}-2')>`,
    rule: 'XSS_EVENT_HANDLER',
    result: 'SUCCESSFUL',
    status: 302
  },
  {
    label: 'javascript: URI',
    lab: 'XSS',
    mode: 'VULNERABLE',
    actor: 'alice',
    client: 'safari',
    payload: `<a href="javascript:alert('${DEMO_MARKER}-3')">open</a>`,
    rule: 'XSS_JS_URI',
    result: 'SUCCESSFUL',
    status: 302
  },
  {
    label: 'injected iframe',
    lab: 'XSS',
    mode: 'VULNERABLE',
    actor: 'bob',
    client: 'burp',
    payload: `<iframe src="https://example.invalid/${DEMO_MARKER}-4"></iframe>`,
    rule: 'XSS_HTML_INJECTION',
    result: 'SUCCESSFUL',
    status: 302
  },
  {
    label: 'script tag stored and rendered escaped',
    lab: 'XSS',
    mode: 'SAFE',
    actor: 'alice',
    client: 'chrome',
    payload: `<script>alert('${DEMO_MARKER}-5')</script>`,
    rule: 'XSS_SCRIPT_TAG',
    result: 'NEUTRALIZED',
    status: 302
  },
  {
    label: 'comment over the 1000-character limit',
    lab: 'XSS',
    mode: 'SAFE',
    actor: 'bob',
    client: 'curl',
    payload: `<script>alert('${DEMO_MARKER}-6')</script>${'A'.repeat(1100)}`,
    rule: 'XSS_SCRIPT_TAG',
    result: 'BLOCKED',
    status: 400
  },

  // --- IDOR ---------------------------------------------------------------
  {
    label: 'reads a document belonging to another account',
    lab: 'IDOR',
    mode: 'VULNERABLE',
    actor: 'alice',
    client: 'chrome',
    target: { owner: 'bob', index: 0 },
    rule: 'IDOR_OWNER_MISMATCH',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'second foreign document, no enumeration cost',
    lab: 'IDOR',
    mode: 'VULNERABLE',
    actor: 'alice',
    client: 'firefox',
    target: { owner: 'bob', index: 1 },
    rule: 'IDOR_OWNER_MISMATCH',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'same weakness, other direction',
    lab: 'IDOR',
    mode: 'VULNERABLE',
    actor: 'bob',
    client: 'edge',
    target: { owner: 'alice', index: 0 },
    rule: 'IDOR_OWNER_MISMATCH',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'administrator is not exempt inside the lab',
    lab: 'IDOR',
    mode: 'VULNERABLE',
    actor: 'admin',
    client: 'chrome',
    target: { owner: 'alice', index: 1 },
    rule: 'IDOR_OWNER_MISMATCH',
    result: 'SUCCESSFUL',
    status: 200
  },
  {
    label: 'ownership check refuses the request',
    lab: 'IDOR',
    mode: 'SAFE',
    actor: 'alice',
    client: 'chrome',
    target: { owner: 'bob', index: 0 },
    rule: 'IDOR_OWNER_MISMATCH',
    result: 'BLOCKED',
    status: 403
  },
  {
    label: 'ownership check, other direction',
    lab: 'IDOR',
    mode: 'SAFE',
    actor: 'bob',
    client: 'firefox',
    target: { owner: 'alice', index: 0 },
    rule: 'IDOR_OWNER_MISMATCH',
    result: 'BLOCKED',
    status: 403
  }
];

/** Legitimate traffic: monitored, and deliberately not a security event. */
const BENIGN_SCENARIOS = [
  { label: 'normal product search', actor: 'alice', client: 'chrome', path: '/labs/sql?q=laptop' },
  { label: 'normal product search', actor: 'bob', client: 'firefox', path: '/labs/sql?q=monitor' },
  { label: 'opens the SQL injection lab', actor: 'alice', client: 'chrome', path: '/labs/sql' },
  { label: 'opens the XSS lab', actor: 'bob', client: 'edge', path: '/labs/xss' },
  { label: 'opens the IDOR lab', actor: 'alice', client: 'safari', path: '/labs/idor' },
  { label: 'opens an own document', actor: 'alice', client: 'chrome', path: 'own-document' }
];

// --------------------------------------------------------------------------
// database helpers
// --------------------------------------------------------------------------
const latestEventId = async () =>
  Number((await query('SELECT COALESCE(max(id), 0) AS id FROM security_events')).rows[0].id);

async function currentMode() {
  return (await query('SELECT security_mode FROM app_settings WHERE id = 1')).rows[0].security_mode;
}

/** The monitor writes on response finish, so the row lands just after the reply. */
async function waitForEvent(afterId, attackType, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { rows } = await query(
      `SELECT * FROM security_events
        WHERE id > $1 AND attack_type = $2
        ORDER BY id DESC LIMIT 1`,
      [afterId, attackType]
    );
    if (rows.length === 1) return rows[0];
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return null;
}

/** Document ids grouped by owner email — resolved at run time, never hard-coded. */
async function documentsByOwner() {
  const { rows } = await query(
    `SELECT d.id, u.email
       FROM user_documents d
       JOIN users u ON u.id = d.owner_id
      ORDER BY u.email, d.id`
  );
  const byEmail = {};
  for (const row of rows) {
    (byEmail[row.email] ||= []).push(row.id);
  }
  return byEmail;
}

/** Removes the script-bearing comments this run stored. */
async function cleanupDemoComments() {
  const { rowCount } = await query('DELETE FROM comments WHERE comment LIKE $1', [
    `%${DEMO_MARKER}%`
  ]);
  return rowCount;
}

// --------------------------------------------------------------------------
// runner
// --------------------------------------------------------------------------
const failures = [];

function record(label, ok, detail) {
  if (!ok) failures.push(`${label}: ${detail}`);
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label.padEnd(48)} ${detail}`);
}

async function setMode(admin, mode) {
  if ((await currentMode()) === mode) return;
  const response = await admin.post('/admin/mode', { mode, redirectTo: '/dashboard' }, CLIENTS.chrome, '/dashboard');
  if (response.status !== 302 && response.status !== 200) {
    throw new Error(`mode switch to ${mode} returned HTTP ${response.status}`);
  }
}

async function main() {
  console.log(`\nWebSecLab demo traffic against ${BASE}${DRY ? '  (dry run)' : ''}\n`);

  if (RESIDUAL_RISK_RATE > 0 && !DRY) {
    console.log(
      `Note: RESIDUAL_RISK_RATE=${RESIDUAL_RISK_RATE} is set, so a minority of attempts are expected to come back the\n` +
        'other way. Exact results are not asserted; the rule and the score are.\n'
    );
  }

  const byOwner = await documentsByOwner();
  const sessions = {};
  for (const key of ['admin', 'alice', 'bob']) {
    sessions[key] = await signIn(key);
  }

  console.log('Scenarios');

  // Grouped by mode so the global switch is flipped as few times as possible.
  const ordered = [...SCENARIOS].sort((a, b) => a.mode.localeCompare(b.mode));

  for (const scenario of ordered) {
    const userAgent = CLIENTS[scenario.client];
    const actor = sessionFor(sessions, scenario.actor);
    const expected = riskCalculator.calculate({
      attackType: scenario.lab,
      result: scenario.result,
      authenticated: true
    });

    if (DRY) {
      const target = scenario.target ? ` (document index ${scenario.target.index} of ${scenario.target.owner})` : '';
      console.log(
        `  plan  ${scenario.mode.padEnd(10)} ${scenario.lab.padEnd(14)} ` +
          `${scenario.result.padEnd(12)} score ${expected.score} — ${scenario.label}${target}`
      );
      continue;
    }

    await setMode(sessions.admin, scenario.mode);
    const before = await latestEventId();
    const response = await send(actor, scenario, byOwner, userAgent);
    const event = await waitForEvent(before, scenario.lab);

    if (!event) {
      record(scenario.label, false, `no ${scenario.lab} event was recorded`);
      continue;
    }

    // The rule and the score-for-the-result are always assertions. The exact
    // result and status are only assertions when the mode is what decides them:
    // with the residual-risk model on, a minority of attempts are supposed to
    // come back the other way, so demanding the predicted result would be
    // testing that the model is broken.
    const problems = [];
    if (event.matched_rule !== scenario.rule) problems.push(`rule ${event.matched_rule}`);

    const actualScore = riskCalculator.calculate({
      attackType: scenario.lab,
      result: event.result,
      authenticated: true
    }).score;
    if (event.risk_score !== actualScore) {
      problems.push(`score ${event.risk_score} does not follow from ${event.result} (expected ${actualScore})`);
    }

    if (RESIDUAL_RISK_RATE === 0) {
      if (event.result !== scenario.result) problems.push(`result ${event.result}`);
      if (event.status_code !== scenario.status) problems.push(`HTTP ${event.status_code}`);
      if (response.status !== scenario.status) problems.push(`reply HTTP ${response.status}`);
    }

    if (!event.request_data || event.request_data.userAgent !== userAgent) {
      problems.push('user agent not stored');
    }

    const basis = event.request_data ? event.request_data.outcomeBasis : 'MODE';

    // Counted once per scenario: a gapped attempt both changes the result and
    // records the basis, and counting both would report twice the real rate.
    if (event.result !== scenario.result || basis === 'RESIDUAL_RISK') residualCases += 1;
    record(
      scenario.label,
      problems.length === 0,
      problems.length === 0
        ? `${scenario.mode} ${event.result} ${event.matched_rule} score=${event.risk_score} ` +
            `HTTP ${event.status_code} basis=${basis}`
        : problems.join(', ')
    );
  }

  console.log('\nLegitimate traffic (must stay silent)');
  for (const scenario of BENIGN_SCENARIOS) {
    const userAgent = CLIENTS[scenario.client];
    const actor = sessionFor(sessions, scenario.actor);
    const path =
      scenario.path === 'own-document'
        ? `/labs/idor/documents/${byOwner[ACCOUNTS[scenario.actor].email][0]}`
        : scenario.path;

    if (DRY) {
      console.log(`  plan  ${scenario.actor.padEnd(6)} GET ${path} — no event expected`);
      continue;
    }

    const before = await latestEventId();
    const response = await actor.get(path, userAgent);
    await new Promise((resolve) => setTimeout(resolve, 400));
    const after = await latestEventId();

    record(
      scenario.label,
      response.status === 200 && after === before,
      // A silent request proves the benign path is monitored but not alarmed.
      `HTTP ${response.status}, events ${after === before ? 'unchanged' : 'RAISED'}`
    );
  }

  if (!DRY) {
    const removed = await cleanupDemoComments();
    await setMode(sessions.admin, 'SAFE');

    const [monitored, events] = await Promise.all([
      query('SELECT count(*)::int AS n FROM monitored_requests'),
      query('SELECT count(*)::int AS n FROM security_events')
    ]);

    console.log(
      `\nRemoved ${removed} demo comment(s); global mode left on SAFE.\n` +
        `Database now holds ${monitored.rows[0].n} monitored requests and ${events.rows[0].n} security events.`
    );

    if (RESIDUAL_RISK_RATE > 0) {
      console.log(
        `${residualCases} of ${SCENARIOS.length} attempts came back the other way or were recorded as residual risk.`
      );
    }

    const { rows: mix } = await query(
      `SELECT attack_type, result, count(*)::int AS total
         FROM security_events
        GROUP BY attack_type, result
        ORDER BY attack_type, result`
    );
    console.log('\nRecorded mix:');
    for (const row of mix) {
      console.log(`  ${row.attack_type.padEnd(14)} ${row.result.padEnd(12)} ${row.total}`);
    }
  }

  if (failures.length > 0) {
    console.log(`\n${failures.length} scenario(s) did not match the expectation:`);
    for (const failure of failures) console.log(`  ${failure}`);
  } else if (!DRY) {
    console.log('\nEvery scenario produced the event it predicted.');
  }
}

/** Small indirection so the scenario table reads as data, not dispatch code. */
function sessionFor(sessions, actor) {
  return sessions[actor];
}

async function send(actor, scenario, byOwner, userAgent) {
  if (scenario.lab === 'SQL_INJECTION') {
    return actor.get(`/labs/sql?q=${encodeURIComponent(scenario.payload)}`, userAgent);
  }
  if (scenario.lab === 'XSS') {
    return actor.post('/labs/xss/comments', { comment: scenario.payload }, userAgent, '/labs/sql');
  }
  const ownerEmail = ACCOUNTS[scenario.target.owner].email;
  const documentId = byOwner[ownerEmail][scenario.target.index];
  if (!documentId) {
    throw new Error(`no document ${scenario.target.index} for ${ownerEmail}`);
  }
  return actor.get(`/labs/idor/documents/${documentId}`, userAgent);
}

main()
  .catch((error) => {
    console.error(`\nFATAL: ${error.stack || error.message}`);
    failures.push(error.message);
  })
  .finally(async () => {
    try {
      await cleanupDemoComments();
    } catch {
      // best effort — a failed run should still report its real failure
    }
    await pool.end();
    process.exitCode = failures.length === 0 ? 0 : 1;
  });
