# WebSecLab — Report draft

Course: Cyber Forensics & Laws (IA2 · CFL 216H02C501)
Submission: 18 Oct 2026

This is a working draft. Replace every `[[ … ]]` placeholder, paste your own
screenshots where marked, and re-verify figures against your final database
before submitting. Everything else here is already true of the delivered code.

---

## 1. Title, group and roles

| Member | Role | Owned areas |
|---|---|---|
| `[[ Member 1 name / roll no ]]` | Core, authentication, SQL injection | application wiring, schema, auth, SQLi lab, dashboard queries, hardening |
| `[[ Member 2 name / roll no ]]` | UI, XSS, IDOR, dashboard | views, design system, XSS and IDOR labs, dashboard, client-side JS |
| `[[ Member 3 name / roll no ]]` | Detection, logging, forensics | detectors, risk model, security monitor, event log, forensics, evidence, tests |

All three members contributed code, not just documentation: see the contribution
table in §12 and `git shortlog -sn` if the repository is submitted with history.

---

## 2. Problem statement and objective

Web applications commonly fail at the same three points: they build database
queries from user input, they render user input without context-aware encoding,
and they trust identifiers supplied by the client. All three are exploitable, and
all three are invisible after the fact unless the application records what
happened and can reconstruct it.

Attacks are frequently demonstrated without the other half of the story: what a
defender sees. This project builds both halves at once.

**Objective:** build a single application in which a chosen attack can be
performed, detected by a transparent rule set, scored, logged, investigated,
remediated by switching a protection on, and re-tested against the same recorded
input — with an evidence package whose integrity can be verified.

The application is deliberately weakened in three routes so the attacks are real
rather than simulated, and it is deliberately hardened everywhere else.

---

## 3. Case studies

WebSecLab is **independently implemented**. The labs below are teaching
references whose vulnerability classes the project reproduces from scratch; no
code, payload list or dataset from these platforms is reused.

The step-by-step reproduction of each attack in *this* project — the payload, the
expected response in both modes, and the security event it produces — is in
`docs/ATTACK_DEMOS.md`, one runbook per group member.

### 3.1 PortSwigger Web Security Academy

| WebSecLab lab | Reference lab | Vulnerability class |
|---|---|---|
| SQL Injection — product search | *Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data* | Injection in a `WHERE` clause; unreleased rows become visible |
| XSS — comments | *Lab: Stored XSS into HTML context with nothing encoded* | Stored XSS in an HTML context with no output encoding |
| IDOR — documents | *Lab: Insecure direct object references* | Broken access control on a user-owned object referenced directly by id |

The IDOR theme also appears in PortSwigger's *User ID controlled by request
parameter* lab family (including the *unpredictable user IDs* and *data leakage
in redirect* variants), which shows the same root cause with a different
identifier strategy.

Sources read for the exact titles:

- <https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data>
- <https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded>
- <https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references>
- <https://portswigger.net/web-security/access-control/idor>

### 3.2 OWASP Juice Shop

| WebSecLab lab | Closest Juice Shop challenge | Notes |
|---|---|---|
| SQL Injection — product search | *Order the Christmas special offer of 2014* | The official companion guide's solution identifies the product-search endpoint (`/rest/products/search?q=`) as SQL-injectable. *Retrieve a list of all user credentials via SQL Injection* is the more dramatic variant of the same flaw. |
| XSS — comments | *DOM XSS*, *API-only XSS*, *Server-side XSS Protection* | Juice Shop separates DOM, API-persisted and server-rendered XSS; WebSecLab demonstrates the stored/server-rendered case. |
| IDOR — documents | *View Basket* | The guide's solution for this challenge consists of changing a basket identifier — the same missing-ownership-check pattern. |

Source: <https://pwning.owasp-juice.shop/companion-guide/latest/part2/injection.html> ·
<https://pwning.owasp-juice.shop/companion-guide/latest/part2/xss.html> ·
<https://pwning.owasp-juice.shop/companion-guide/latest/part2/broken-access-control.html>

### 3.3 OWASP Top 10 (2021)

| WebSecLab lab | Category |
|---|---|
| SQL Injection | **A03:2021 – Injection** |
| XSS | **A03:2021 – Injection** — in the 2021 edition Cross-Site Scripting is grouped under Injection and is no longer a separate category |
| IDOR | **A01:2021 – Broken Access Control** |

Sources: <https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/> ·
<https://top10.owasp.org/2021/A03_2021-Injection/>

---

## 4. Architecture, lifecycle and stack

The lifecycle is the spine of the whole system:

```
Attack → Detect → Log → Investigate → Secure → Re-test
```

```
              ┌────────────────────────────────────────────────────┐
   Browser ──▶│ helmet / static / session / CSRF                   │
              │   │                                                │
              │   ├─ loadUser, loadSecurityMode   (mode per request)
              │   ├─ securityMonitor  ← /labs/* only               │
              │   └─ routes                                        │
              │        ├─ /labs/sql|xss|idor   (intentional flaws) │
              │        ├─ /dashboard, /security/events  (ADMIN)    │
              │        └─ /forensics/*                  (ADMIN)    │
              └───────────────┬────────────────────────────────────┘
                              │ res.on('finish')
                     ┌────────▼─────────┐
                     │  detectors (9)   │  → risk score → security_events
                     └────────┬─────────┘
                              │
              ┌───────────────▼────────────────────────────┐
              │ forensics: timeline, mitigation, evidence  │
              │ exports/evidence-<uuid>-<stamp>.json +     │
              │ SHA-256 recorded in incident_actions       │
              └────────────────────────────────────────────┘
```

Detection runs on `res.on('finish')` because the outcome of a request is only
known after the controller has responded. This means the monitor can never alter
a response: blocking happens in the controller, logging happens in the monitor,
and a failure inside the monitor is caught and logged rather than propagated.

Stack: Node.js, Express, EJS, Bootstrap 5, vanilla JS, Chart.js, PostgreSQL
(`pg`), bcrypt, express-session, express-validator, helmet, express-rate-limit
and Node's `crypto`. Bootstrap and Chart.js are vendored from `node_modules` so
the demonstration works offline and the Content-Security-Policy stays strict.

**Interface layer.** The styling is a small token-based design system in
`public/css/tokens.css` (semantic custom properties) plus `public/css/app.css`
(components), not a pile of per-page rules. That choice paid for itself twice:
it made a **light / dark / system theme switch** cost one extra token block, and
it let the mobile layout be a drawer plus two CSS breakpoints rather than a
second set of templates. One layout detail is worth naming because it is the
kind of thing that only shows up on a tall page: the sidebar rail stretches to
the full column height and the stickiness lives on an inner box, because a
sticky box is sized by its own content and would otherwise leave the rail's
border hanging in mid-page. Acceptance check 24 pins that structure. The theme is resolved **server-side** from a cookie so
the first paint is already correct — no flash, and no inline script, which the
strict CSP forbids outside the XSS lab. This is a documented override of
specification §12.5, which asked for no dark mode: the requirement was written
to keep the project small, and with tokens that goal is still met (one file, no
build step, no new dependency). The charts read the same tokens and rebuild on a
`themechange` event, so the dashboard follows the toggle instead of keeping
stale colours.

**Design decision worth defending in the viva:** the SQLi lab's vulnerable query
runs on a *second* database connection using a `lab_reader` role that has
`SELECT` on `products` and nothing else. A successful injection therefore cannot
read `users`, `password_hash`, or write anything. The intended weakness is fully
preserved — the blast radius is not.

---

## 5. Database design

Eight tables, all defined in `database/schema.sql`:

| Table | Purpose |
|---|---|
| `users` | accounts; `password_hash` is always a bcrypt hash |
| `app_settings` | single row holding the global `SAFE`/`VULNERABLE` mode |
| `products` | SQLi lab data; `is_released = FALSE` rows are the hidden data |
| `comments` | XSS lab data, stored raw once and rendered per mode |
| `user_documents` | IDOR lab data, sequential ids on purpose |
| `monitored_requests` | every request to `/labs/*`, with a `flagged` marker |
| `security_events` | the audit record: rule, risk, severity, sanitized request data, result |
| `incident_actions` | investigation trail: `INVESTIGATION_OPENED`, `EVIDENCE_EXPORTED`, `EVIDENCE_VERIFIED` |

`security_events` stores exactly one timestamp (`occurred_at`). This is a design
constraint we kept honest rather than papering over — see §8.2.

`[[ paste an ER diagram or the table list output here ]]`

---

## 6. The three labs

For each lab: what the vulnerability is, the vulnerable code path, the safe code
path, the Burp evidence, the detection rule and the logged event.

### 6.1 SQL Injection — `GET /labs/sql?q=`

**Vulnerability.** The search term is concatenated into a SQL string, so an
apostrophe changes the query's meaning. `GET` is used deliberately so the request
can be edited and replayed in Burp Repeater.

**Vulnerable code path** — `src/controllers/sqlController.js`, marked
`INTENTIONALLY VULNERABLE — EDUCATIONAL LAB ONLY`:

```js
const sql = `SELECT id, name, description, price, category FROM products
             WHERE is_released = TRUE AND name ILIKE '%${searchTerm}%'`;
const result = await labQuery(sql);          // lab_reader pool
```

**Safe code path:**

```js
const sql = 'SELECT id, name, description, price, category FROM products ' +
            'WHERE is_released = TRUE AND name ILIKE $1';
const result = await query(sql, ['%' + searchTerm + '%']);
```

**Payload used.** `' OR 1=1--`

**What happens.** The clause becomes `WHERE (is_released = TRUE AND name ILIKE
'%') OR 1=1`, which is true for every row — including the three unreleased
products a normal search never returns. The page shows the executed statement and
marks the extra rows as *unreleased*. In SAFE mode the same payload is a bound
parameter and matches nothing.

`[[ screenshot 4: normal search ]]`
`[[ screenshot 5: Burp Repeater with the modified q parameter ]]`
`[[ screenshot 6: vulnerable result — extra rows + executed SQL ]]`

**Detection.** `SQLI_TAUTOLOGY` (pattern in `docs/CONTRACTS.md` §4).
**Logged event.** VULNERABLE: `SUCCESSFUL`, score 100, CRITICAL. SAFE:
`NEUTRALIZED`, score 85, HIGH.

### 6.2 Cross-Site Scripting — `GET /labs/xss`, `POST /labs/xss/comments`

**Vulnerability.** The comment is stored unmodified and, in VULNERABLE mode,
printed into the page unescaped. The route also relaxes its
Content-Security-Policy, because a strict policy would silently prevent the
demonstration from working — a trap that makes such labs look broken.

**Vulnerable code path** — `views/labs/xss-lab.ejs`, and only there:

```ejs
<%- comment.comment %>     <!-- VULNERABLE branch -->
```

**Safe code path:** `<%= comment.comment %>` under the strict policy, plus the
mode-dependent CSP override in `src/middleware/csp.js`.

**Payload used.** `<script>alert(document.domain)</script>`

**What happens.** In VULNERABLE mode the stored comment executes for every
visitor. The row in the database is byte-identical in both modes: switching to
SAFE and reloading renders the same text as inert characters. The session cookie
is `httpOnly`, so `document.cookie` does not expose it even while script runs.

`[[ screenshot 12: vulnerable execution, then the same comment rendered inert ]]`

**Detection.** `XSS_SCRIPT_TAG` (also `XSS_EVENT_HANDLER`, `XSS_JS_URI`,
`XSS_HTML_INJECTION` for other payload shapes).
**Logged event.** VULNERABLE: `SUCCESSFUL`, score 90, CRITICAL. SAFE:
`NEUTRALIZED`, score 75, HIGH.

### 6.3 IDOR — `GET /labs/idor/documents/:id`

**Vulnerability.** The document is fetched by a sequential id and returned
without comparing its owner to the signed-in user. The query is parameterized in
*both* modes on purpose: this lab isolates broken access control.

**Vulnerable code path:** fetch by id, no ownership comparison.
**Safe code path:**

```js
if (document.owner_id !== req.session.user.id) {   /* HTTP 403, nothing returned */ }
```

**What happens.** Alice requests Bob's document id. VULNERABLE mode returns it
with HTTP 200; SAFE mode returns HTTP 403 and the title and content are not sent
at all. Reading your *own* document works in both modes and deliberately records
no event.

`[[ screenshot 13: 200 in vulnerable mode, 403 in safe mode ]]`

**Detection.** `IDOR_OWNER_MISMATCH` (a logic condition, not a payload pattern).
**Logged event.** VULNERABLE: `SUCCESSFUL`, score 95, CRITICAL. SAFE: `BLOCKED`,
score 80, HIGH.

---

## 7. Detection and risk model

Rules are evaluated in order and the **first match wins**:

| Rule | Attack type | What it matches |
|---|---|---|
| `SQLI_UNION_SELECT` | SQL_INJECTION | `union select` — appends an attacker-controlled result set |
| `SQLI_STACKED_QUERY` | SQL_INJECTION | `;` followed by a second statement |
| `SQLI_TAUTOLOGY` | SQL_INJECTION | `' OR 1=1` style conditions |
| `SQLI_COMMENT_TERMINATOR` | SQL_INJECTION | `--`, `#` or `/*` after a quote |
| `XSS_SCRIPT_TAG` | XSS | inline `<script` |
| `XSS_EVENT_HANDLER` | XSS | any tag with an `on…=` attribute |
| `XSS_JS_URI` | XSS | `javascript:` |
| `XSS_HTML_INJECTION` | XSS | `img`, `svg`, `iframe`, `object`, `embed`, `body`, `link` |
| `IDOR_OWNER_MISMATCH` | IDOR | requested owner differs from the session user |

**Scoring — the WebSecLab Educational Risk Score.** This is *not* CVSS and is
never labelled as such: base per attack type (SQLi 90, XSS 80, IDOR 85), +5 when
the attack succeeded, +5 for an authenticated actor, −10 when the attempt was
blocked or neutralized, clamped to 0–100. Severity bands: ≥90 CRITICAL, 75–89
HIGH, 50–74 MEDIUM, <50 LOW.

| Attack | Mode | Result | Score | Severity |
|---|---|---|---|---|
| SQLi | VULNERABLE | SUCCESSFUL | 100 | CRITICAL |
| SQLi | SAFE | NEUTRALIZED | 85 | HIGH |
| XSS | VULNERABLE | SUCCESSFUL | 90 | CRITICAL |
| XSS | SAFE | NEUTRALIZED | 75 | HIGH |
| IDOR | VULNERABLE | SUCCESSFUL | 95 | CRITICAL |
| IDOR | SAFE | BLOCKED | 80 | HIGH |

**Deliberate trade-off, stated honestly:** there is no detection rule on a bare
apostrophe. Such a rule would false-positive on legitimate input like `O'Brien`
or `men's`, and a detector that cries wolf is worse than one that misses a
narrow case. The trade-off is asserted by a unit test
(`scripts/test-detectors.js`).

**Limits of the model.** Regex matching is evadable by encoding, whitespace
tricks, case variation and comment insertion. It is a teaching instrument that
makes the *shape* of an attack visible and auditable, not a WAF. A production
system would use parameterization and output encoding as the actual controls and
treat detection as a secondary signal — which is exactly the position this
project takes: the protections in SAFE mode are structural, not regex-based.

### 7.1 Residual-risk outcome model

The table above describes what the **mode** decides, and in the default
configuration the mode decides every single result. That reproducibility is a
requirement of the demonstration — the same request, sent twice, changing only
the mode, has to answer differently, or there is nothing to compare — but it is
not what an operations view looks like. A control that engages on every single
attempt produces a log with exactly two possible row shapes.

`src/security/outcomeModel.js` adds the missing minority tail behind one
setting, `RESIDUAL_RISK_RATE` (default `0`, off):

| Setting | SAFE mode | VULNERABLE mode |
|---|---|---|
| `0` (default, and what the report's measurements use) | every attempt stopped | every attempt executes |
| `0.12` | ~1 attempt in 8 skips the controls | unchanged — nothing to fail where the controls are already off |

Three design decisions make this a simulation rather than fabricated evidence:

1. **The application is weakened, not the record.** A gapped SQLi attempt really
   executes the concatenated query and really returns the unreleased rows; a
   gapped XSS attempt really renders the stored comment unescaped *and* relaxes
   the route's Content-Security-Policy in the same response, or the payload would
   be blocked by the very policy the escaping gap is meant to reveal; a gapped
   IDOR attempt really returns the foreign document with HTTP 200. Every event is
   a true description of what the application did.
2. **Provenance is recorded.** Each affected event stores
   `request_data.outcomeBasis = 'RESIDUAL_RISK'`, shown as a *residual risk*
   badge in the events table and an **Outcome basis** row on the incident page.
   Without it, an event claiming "SAFE mode, attack successful" would be
   indistinguishable from a broken control. The risk score also follows the real
   result, so a gapped SQLi attempt scores 100 rather than 85.
3. **Validation is never gapped.** An over-length or control-character payload is
   still refused with HTTP 400 in SAFE mode; the draw only ever skips the
   structural control, and the least-privilege database role keeps applying even
   then.

The model is off by default precisely so that the measured numbers in this
report and the acceptance suite stay reproducible, and check 25 of the suite
fails loudly if it is ever left on.

---

## 8. Forensic investigation

### 8.1 The incident page

`GET /forensics/:uuid` reconstructs an incident: summary, the sanitized request
evidence, the timeline, the recommended mitigation, the evidence package and the
incident action trail. Opening it records `INVESTIGATION_OPENED`.

Only four fields of the original request are ever captured — `parameter`,
`payload`, `resourceId` and `userAgent` — from an allowlist. Keys matching
`/pass|pwd|secret|token|cookie|session|authorization|csrf/i` are replaced with
`[REDACTED]` recursively, and the same function runs again when the evidence
package is built. The acceptance suite asserts that no credential material
reaches either.

`[[ screenshot 8: forensic page with evidence, timeline and mitigation ]]`

### 8.2 Timeline — and its honest limitation

Only two timestamps genuinely exist: the event's `occurred_at` and the
`INVESTIGATION_OPENED` action. Stages 1–4 therefore display the *same* time, and
the page states this in plain text: "Stages 1–4 derive from one recorded event."
We chose an honest single timestamp over fabricating a per-stage timeline.

### 8.3 Evidence package and SHA-256

The package is serialized with a fixed key order and two-space indentation;
those exact bytes are written to `exports/evidence-<uuid>-<yyyymmddThhmmss>.json`
and hashed with SHA-256. The hash is stored in `incident_actions` **outside** the
file, and the download route serves the same bytes that were hashed.

Verification reads the chosen file as text in the browser (`FileReader`), posts
`{ filename, content }` to `POST /forensics/verify`, and the server re-hashes what
it received.

| Step | Result |
|---|---|
| Export, then verify the untouched file | "Evidence integrity verified." |
| Change one character in the JSON, then verify | "Evidence integrity check failed." |

`[[ screenshot 9: evidence JSON + SHA-256 ]]`
`[[ screenshot 10: verify pass, then verify fail after editing one character ]]`

**Stated limitation.** The disclaimer appears on every page that shows a hash:
*"SHA-256 here demonstrates whether the exported file has changed. Hashing by
itself does not establish authenticity or a complete chain of custody."* There is
no signature, no trusted timestamp and no external custody record, so the hash
proves integrity relative to the value recorded in the database — and nothing
more.

---

## 9. Hardening measures

These hold in **both** modes; only the three lab behaviours change.

| Area | Measure |
|---|---|
| SQL | parameterized queries everywhere except the one clearly marked lab function; a least-privilege database role for that function |
| Output | HTML escaping by default; exactly one unescaped render in the whole application, in the VULNERABLE branch of the XSS lab |
| Headers | helmet with a strict CSP; `object-src 'none'`; the relaxation is scoped to `/labs/xss` and only in VULNERABLE mode |
| Sessions | `httpOnly`, `sameSite=lax`, `secure` only in production, and `req.session.regenerate()` on sign-in; the secret comes from `.env` |
| CSRF | per-session token on every unsafe method, including sign-out and the mode switch; `SameSite=Lax` as a second layer |
| Passwords | bcrypt cost 11, generic failure message, no account enumeration |
| Input | `express-validator` on register, sign-in, comments, search and `:id` parameters |
| Abuse | rate limiting on `/login` and `/register` only — deliberately not on `/labs/*`, where it would break the tests |
| Errors | one central handler; no stack traces to the client when `NODE_ENV=production` |
| Data | allowlist + recursive redaction for everything logged or exported |
| Failure | a database outage degrades to sign-out and `SAFE` mode instead of crashing; the monitor catches its own errors |

`[[ screenshot 2: admin dashboard in Safe mode, light theme ]]`
`[[ screenshot 2b: the same dashboard in dark theme — charts restyled from the same tokens ]]`
`[[ screenshot 3: mode switched to Vulnerable — red badge and banner ]]`

---

## 10. Legal and ethical considerations

This project deliberately ships vulnerable code. That is acceptable only because
of the constraints it is built with, and the report should say so plainly:

1. The vulnerabilities exist solely in three lab routes of a local application,
   behind authentication, toggled by an explicit administrator switch that
   defaults to `SAFE`.
2. All data is fictional and seeded locally. No real personal data is used, and
   no third-party system is ever targeted.
3. Testing was performed only against `localhost`, using our own browsers and our
   own Burp Suite installation.
4. The attack techniques demonstrated are the well-documented vulnerability
   classes taught by PortSwigger's Web Security Academy, OWASP and the OWASP
   Top 10 — studied in order to defend against them.
5. The evidence module collects only the four request fields needed to explain an
   incident, and redacts anything credential-shaped. It is a teaching artefact,
   not a surveillance tool.

`[[ add your institution's academic-integrity and computer-use policy reference ]]`

---

## 11. Limitations

1. **Regex-based detection is evadable** by encoding, case and whitespace tricks.
   The structural protections in SAFE mode, not the rules, are what actually stop
   the attacks.
2. **No rule on a bare apostrophe**, deliberately, to avoid false positives on
   ordinary names.
3. **Hashing is not a chain of custody.** There is no signature or trusted
   timestamp; integrity is only relative to the recorded hash.
4. **Single node.** SQLite-free but also cluster-free: the session store is
   in-process memory, so sessions do not survive a restart and the design does
   not scale horizontally.
5. **One global mode.** The mode is global rather than per-user or per-session,
   which is simpler to demonstrate but means the whole application changes state
   at once.
6. **The single-timestamp timeline** described in §8.2.
7. **No automated remediation.** The mitigation text is a recommendation shown to
   the administrator; the code change is made by the developer.

---

## 12. Conclusion and contribution table

WebSecLab demonstrates the full defender's loop on real, self-hosted
vulnerabilities: the same request can be executed against a weak and a strong
implementation, detected by inspectable rules, scored, investigated, exported as
verifiable evidence, and re-tested. The project's central engineering judgement
is that the intentional weakness was confined — to three routes, behind a SAFE
default, with the vulnerable query running as a database role that can read
exactly one table.

| Member | Commits / areas | Verified by |
|---|---|---|
| `[[ Member 1 ]]` | `src/app.js`, `src/config`, `src/controllers/{auth,sql,admin,dashboard}*`, `database/`, hardening | SQLi lifecycle checks 9–10, 19 |
| `[[ Member 2 ]]` | `views/`, `public/`, `src/labs`, `src/middleware/theme.js`, `src/controllers/{xss,idor}*` | XSS and IDOR checks 11–13, interface and copy-button checks 21–24, 26 |
| `[[ Member 3 ]]` | `src/security`, `src/middleware/{securityMonitor,csrf,rateLimit}`, `src/controllers/forensics`, `scripts/` | detection, evidence and resilience checks 1–8, 14–20, 25 |

Final state: `npm run db:reset` → `npm run dev` → `npm run test:acceptance`
reports **26 passed, 0 failed** on a clean database.

`[[ screenshot 15: commit graph / contributors ]]`
