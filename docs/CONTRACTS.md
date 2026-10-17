# WebSecLab — Frozen Contracts

**Do not rename tables, columns, enum values, function names or header names.**
Everything below is implemented in code exactly as written here. When a slice is
handed to another developer (or to a chat model), this file is the context.

---

## 0. Scope

WebSecLab is a web-based attack detection, prevention and forensic analysis
platform for a university Cyber Forensics & Laws assignment. Local educational
use only.

**Lifecycle:** Attack → Detect → Log → Investigate → Secure → Re-test

**Labs (three only):** SQL Injection (product search), XSS (comments),
IDOR (documents).

**Global mode:** `VULNERABLE | SAFE`, stored in PostgreSQL, switched by an ADMIN,
default `SAFE`.

**Isolation rule:** an intentional weakness exists ONLY inside the three lab
controllers/views and ONLY in `VULNERABLE` mode. Authentication, the dashboard,
the event log, forensics and evidence are secure in both modes.

---

## 1. Database contract

Owner of the schema: the role in `DATABASE_URL`. The VULNERABLE SQLi query runs
on a second pool (`LAB_DATABASE_URL`, role `lab_reader`) that holds
`SELECT` on `products` and nothing else.

```sql
users              (id, name, email, password_hash, role, created_at)
app_settings       (id=1, security_mode, updated_by, updated_at)
products           (id, name, description, price, category, is_released)
comments           (id, user_id, comment, created_at)
user_documents     (id, owner_id, title, content, created_at)
monitored_requests (id, occurred_at, user_id, http_method, endpoint, security_mode, status_code, flagged)
security_events    (id, event_uuid, occurred_at, user_id, source_ip, http_method, endpoint,
                    attack_type, severity, risk_score, matched_rule, request_data,
                    security_mode, result, status_code)
incident_actions   (id, event_id, action, description, evidence_filename, evidence_sha256,
                    performed_by, occurred_at)
```

Enumerations (enforced by CHECK constraints):

| Column | Allowed values |
|---|---|
| `users.role` | `USER`, `ADMIN` |
| `app_settings.security_mode` | `VULNERABLE`, `SAFE` |
| `security_events.attack_type` | `SQL_INJECTION`, `XSS`, `IDOR` |
| `security_events.severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `security_events.result` | `DETECTED`, `SUCCESSFUL`, `BLOCKED`, `NEUTRALIZED` |
| `security_events.security_mode` | `VULNERABLE`, `SAFE` |
| `incident_actions.action` | `INVESTIGATION_OPENED`, `EVIDENCE_EXPORTED`, `EVIDENCE_VERIFIED` |

Notes that matter:

- `security_events.occurred_at` is the single stored timestamp for an event; the
  UI shows it as "Timestamp".
- `security_events.event_uuid` is the public incident reference. The events table
  shows the first 8 characters; the full value is the investigation link.
- `user_documents.id` is sequential **on purpose** — enumeration is the lab.
- `monitored_requests` powers "Total Monitored Requests" and `flagged` marks the
  requests that produced an event.
- `incident_actions.evidence_filename` and `evidence_sha256` carry the evidence
  hash **outside** the evidence file.

Least-privilege role:

```sql
CREATE ROLE lab_reader LOGIN PASSWORD '<from LAB_DATABASE_URL>';
GRANT USAGE ON SCHEMA public TO lab_reader;
GRANT SELECT ON products TO lab_reader;
```

---

## 2. Runtime contracts

### 2.1 Middleware order (`src/app.js`)

```
helmet (strict CSP)
→ static: /public, /vendor/bootstrap, /vendor/chart.js
→ body parsers (urlencoded; JSON only on the evidence-verify route)
→ session (httpOnly, sameSite=lax, secure only in production)
→ CSRF token issued
→ locals defaults (user, securityMode, flash, currentPath, csrfToken)
→ flash + currentPath
→ loadUser
→ loadSecurityMode        (read from the DB on EVERY request — never cached)
→ verifyCsrf              (every POST/PUT/PATCH/DELETE, logout and mode switch included)
→ XSS-lab CSP override    (/labs/xss only, VULNERABLE only)
→ securityMonitor         (/labs/* only)
→ routes → 404 → errorHandler
```

Rate limiting applies to `/login` and `/register` only. `/labs/*` is
deliberately unlimited so Burp Repeater/Intruder loops keep working.

### 2.2 Controller → monitor handshake

The monitor cannot know the outcome before the controller responds, so detection
runs on response finish. Controllers set this before responding:

```js
res.locals.labContext = {
  lab: 'SQLI' | 'XSS' | 'IDOR',
  payload: String|null,        // raw tested input (searchTerm / comment / null for IDOR)
  resourceId: Number|null,     // IDOR
  ownerId: Number|null,        // IDOR
  outcome: 'NORMAL' | 'EXECUTED_UNSAFE' | 'BLOCKED' | 'NEUTRALIZED',
  basis: 'MODE' | 'RESIDUAL_RISK'   // defaults to MODE; see §2.4a
};
```

```
securityMonitor:
  res.on('finish', async () => {
    try {
      insert monitored_requests row
      if (!res.locals.labContext) return
      detection = detector[lab].detect(labContext + session user)
      if (!detection.detected) return
      result = mapResult(outcome)
      risk   = riskCalculator.calculate({ attackType, result, authenticated })
      securityLogger.createSecurityEvent({ ... sanitized request_data })
      flag the monitored_requests row
    } catch (e) { console.error(e) }   // never crash, never block the response
  })
```

`status_code` is `res.statusCode` at finish. `source_ip` is `req.ip` (stored as
`::1` or `::ffff:127.0.0.1` on localhost, unchanged).

The parameter names recorded in `request_data` are `q` (SQLi), `comment` (XSS)
and `id` (IDOR).

### 2.3 Detector, risk and result contracts

```js
sqlDetector.detect({ payload })                          -> Detection
xssDetector.detect({ payload })                          -> Detection
idorDetector.detect({ userId, ownerId, resourceId })     -> Detection

Detection = { detected: Boolean, attackType: 'SQL_INJECTION'|'XSS'|'IDOR',
              matchedRule: String|null, baseScore: 90|80|85 }

riskCalculator.calculate({ attackType, result, authenticated }) ->
  { score, severity, label: 'WebSecLab Educational Risk Score', breakdown: [...] }
```

| Component | Value |
|---|---|
| Base | SQL_INJECTION 90 · XSS 80 · IDOR 85 |
| +5 | `result = SUCCESSFUL` |
| +5 | authenticated actor (all lab routes are authenticated) |
| −10 | `result` is `BLOCKED` or `NEUTRALIZED` |
| Clamp | 0–100 |
| Severity | ≥90 CRITICAL · 75–89 HIGH · 50–74 MEDIUM · <50 LOW |

Expected scores (the acceptance suite asserts these exactly):

| Attack | Mode | Result | Score | Severity |
|---|---|---|---|---|
| SQLi | VULNERABLE | SUCCESSFUL | 100 | CRITICAL |
| SQLi | SAFE | NEUTRALIZED | 85 | HIGH |
| XSS | VULNERABLE | SUCCESSFUL | 90 | CRITICAL |
| XSS | SAFE | NEUTRALIZED | 75 | HIGH |
| IDOR | VULNERABLE | SUCCESSFUL | 95 | CRITICAL |
| IDOR | SAFE | BLOCKED | 80 | HIGH |

The label in the UI, the report and the evidence package is always
**WebSecLab Educational Risk Score**. It is never called CVSS.

### 2.4 Result mapping

| Lab | Mode | Behaviour | `outcome` | `result` | HTTP |
|---|---|---|---|---|---|
| SQLi | VULNERABLE | String-built query runs | `EXECUTED_UNSAFE` | SUCCESSFUL | 200 |
| SQLi | VULNERABLE | Database refuses the injected statement (least privilege) | `BLOCKED` | BLOCKED | 500 |
| SQLi | SAFE | Parameterized; payload is a literal, 0 rows | `NEUTRALIZED` | NEUTRALIZED | 200 |
| SQLi | SAFE | Fails validation (>50 chars / control characters) | `BLOCKED` | BLOCKED | 400 |
| XSS | VULNERABLE | Stored, rendered unescaped | `EXECUTED_UNSAFE` | SUCCESSFUL | 302 |
| XSS | SAFE | Stored, rendered escaped | `NEUTRALIZED` | NEUTRALIZED | 302 |
| IDOR | VULNERABLE | Another user's document returned | `EXECUTED_UNSAFE` | SUCCESSFUL | 200 |
| IDOR | SAFE | Ownership check fails | `BLOCKED` | BLOCKED | 403 |

`DETECTED` is reserved for a rule match with an undeterminable outcome.
Reading your own document, or searching for a normal term, records a monitored
request but produces no event.

### 2.4a Residual-risk outcome model (`src/security/outcomeModel.js`)

By default the mode decides the outcome outright, which is what every row in the
table above assumes and what the demonstration depends on.

With `RESIDUAL_RISK_RATE=n` (default `0`) configured, a share `n` of SAFE-mode
attempts are decided the other way, because a control that always engages is not
how controls behave in the field:

| Mode | Gapped? | What happens | `basis` |
|---|---|---|---|
| SAFE + draw < n | yes | The parameterized path, the escaping and the ownership check are genuinely skipped, so the leak is real and the event records what the application actually did | `RESIDUAL_RISK` |
| SAFE otherwise | no | As the table above | `MODE` |
| VULNERABLE | never | Nothing to fail: the controls are off by design. What still stops an attempt here is the least-privilege DB role | `MODE` |

Rules that keep this from becoming fabricated evidence:

1. The application is weakened, not the record. A gapped SQLi attempt really runs
the concatenated query, a gapped XSS attempt really renders unescaped *and*
relaxes the route policy in the same response, a gapped IDOR attempt really
returns the foreign document with HTTP 200.
2. Input validation is never gapped. Over-length or control-character input is
still `BLOCKED` / 400 in SAFE mode.
3. Every affected event stores `request_data.outcomeBasis = 'RESIDUAL_RISK'`, and
the events table, the dashboard and the investigation page display it. The score
still follows the real result, so a gapped SQLi attempt scores 100, not 85.
4. `RESIDUAL_RISK_RATE=0` restores the mode-decides-everything behaviour, and the
acceptance suite asserts that it is off before asserting any exact outcome.

### 2.5 Sanitizer

`request_data` is built from an allowlist — `{ parameter, payload, resourceId,
userAgent, outcomeBasis }` — the first four describe the request, the fifth
records which model decided the result. `req.headers` and `req.body` are never copied wholesale. Strings
are truncated to 500 characters. Any key matching
`/pass|pwd|secret|token|cookie|session|authorization|csrf/i` becomes
`"[REDACTED]"`, recursively. The same function runs again when evidence is built.

---

## 3. Lab implementation

### 3.1 SQL Injection — `GET /labs/sql?q=...`

GET on purpose: trivial to edit and replay in Burp.

| | VULNERABLE | SAFE |
|---|---|---|
| Pool | `labPool` (`lab_reader`) | normal `pool` |
| Query | `` `… WHERE is_released = TRUE AND name ILIKE '%${q}%'` `` | `… name ILIKE $1` with `['%'+q+'%']` |
| Validation | none | string, trimmed, ≤50 chars, no control characters |
| UI extra | the executed SQL string | "Parameterized query: ON" |

- The unsafe query lives in `searchProductsUnsafe()` in
  `src/controllers/sqlController.js` under a
  `// INTENTIONALLY VULNERABLE — EDUCATIONAL LAB ONLY` banner, and is referenced
  by nothing else in the codebase (asserted by the acceptance suite).
- Rows a normal search never shows are marked in the UI as
  `unreleased` (the "hidden data" demo).
- A normal search behaves identically in both modes.

### 3.2 XSS — `GET /labs/xss`, `POST /labs/xss/comments`

| | VULNERABLE | SAFE |
|---|---|---|
| Store | raw comment | raw comment (stored once; the view decides) |
| Render | `<%- c.comment %>` in `xss-lab.ejs` only | `<%= c.comment %>` |
| CSP on this route | `script-src 'self' 'unsafe-inline'`, `script-src-attr 'unsafe-inline'` | strict (`script-src 'self'`, `object-src 'none'`) |
| Outcome | `EXECUTED_UNSAFE` | `NEUTRALIZED` |

- Exactly one unescaped data render exists in the whole application.
- A comment stored in VULNERABLE mode renders as inert text after switching to
  SAFE — the re-test demonstration.
- The session cookie is `httpOnly`, so `document.cookie` never exposes it. The
  demonstrated payload stays harmless (`alert(document.domain)`).

### 3.3 IDOR — `GET /labs/idor/documents/:id`

- The id is in the path, an integer, sequential. Authentication is required in
  both modes. There is no administrator exemption inside the lab.
- The query is parameterized in **both** modes: this lab demonstrates broken
  access control, not SQL injection.
- SAFE + owner mismatch → HTTP 403, and the title/content are not sent.
- Unknown or malformed id → 404 with no security event.
- The page shows the signed-in user, the requested id, the document owner, the
  authorization result and the mode.

---

## 4. Detection rules (first match wins)

| Rule ID | Pattern (case-insensitive) | Type |
|---|---|---|
| `SQLI_UNION_SELECT` | `/union\s+(all\s+)?select/i` | SQL_INJECTION |
| `SQLI_STACKED_QUERY` | `/;\s*(drop\|insert\|update\|delete\|select)\b/i` | SQL_INJECTION |
| `SQLI_TAUTOLOGY` | `/['"]\s*(or\|and)\s+['"]?\w+['"]?\s*=\s*['"]?\w+/i` | SQL_INJECTION |
| `SQLI_COMMENT_TERMINATOR` | `/['"].*(--\|#\|\/\*)/` | SQL_INJECTION |
| `XSS_SCRIPT_TAG` | `/<\s*script\b/i` | XSS |
| `XSS_EVENT_HANDLER` | `/<[^>]+\bon\w+\s*=/i` | XSS |
| `XSS_JS_URI` | `/javascript\s*:/i` | XSS |
| `XSS_HTML_INJECTION` | `/<\s*(img\|svg\|iframe\|object\|embed\|body\|link)\b/i` | XSS |
| `IDOR_OWNER_MISMATCH` | `userId !== ownerId` | IDOR |

**Deliberate trade-off:** there is no rule on a bare apostrophe, because that
would false-positive on legitimate input such as `O'Brien` or `men's`. This is
stated in the report and asserted by `scripts/test-detectors.js`.

**Known limit:** regex detection is evadable by encoding, whitespace and case
tricks. This is an educational detector, not a WAF.

---

## 5. Forensics and evidence

### 5.1 Routes (all `requireAdmin`)

| Route | Purpose |
|---|---|
| `GET /security/events` | table with type/severity/result filters, search, pagination |
| `GET /forensics/:uuid` | investigation page, records `INVESTIGATION_OPENED` (idempotent) |
| `POST /forensics/:uuid/export` | writes `exports/evidence-<uuid>-<stamp>.json`, records `EVIDENCE_EXPORTED` |
| `GET /forensics/:uuid/evidence/:filename` | downloads the exact bytes that were hashed |
| `GET /forensics/verify` | evidence verification page |
| `POST /forensics/verify` | body `{ filename, content }` → verified / failed, records `EVIDENCE_VERIFIED` |

`:uuid` is validated against a UUID regex; an invalid or unknown value is a 404.
Server filesystem paths are never returned. Exported filenames are validated
against `evidence-<uuid>-<yyyymmddThhmmss>.json` before any disk access.

### 5.2 Timeline (honest by construction)

Only two real timestamps exist: the event's `occurred_at` and the
`INVESTIGATION_OPENED` action. Stages 1–4 therefore all carry the same time, and
the page says so explicitly. No intermediate times are invented.

```
Request Received              ← occurred_at
Suspicious Activity Detected  ← occurred_at
Request Processed / Blocked   ← occurred_at + status_code
Security Event Recorded       ← occurred_at
Investigation Opened          ← incident_actions.occurred_at
```

### 5.3 Mitigation map

| Attack | Recommended mitigation |
|---|---|
| SQL_INJECTION | Parameterized queries; server-side validation; least-privilege DB account |
| XSS | Context-aware output encoding; sanitization; strict CSP; `httpOnly` cookies |
| IDOR | Server-side ownership check on every object access; return 403; never trust client ids |

### 5.4 Evidence package

Serialized with a fixed key order and `JSON.stringify(obj, null, 2)`; those exact
bytes are hashed and written.

```json
{
  "evidenceVersion": "1.0",
  "incidentId": "<event_uuid>",
  "exportedAt": "<ISO timestamp>",
  "event": {
    "occurredAt": "<ISO timestamp>",
    "attackType": "SQL_INJECTION",
    "severity": "CRITICAL",
    "riskScore": 100,
    "riskScoreLabel": "WebSecLab Educational Risk Score (not CVSS)",
    "matchedRule": "SQLI_TAUTOLOGY",
    "securityMode": "VULNERABLE",
    "result": "SUCCESSFUL",
    "statusCode": 200,
    "httpMethod": "GET",
    "endpoint": "/labs/sql",
    "sourceIp": "::1",
    "user": { "id": 2, "role": "USER" },
    "requestEvidence": { "parameter": "q", "payload": "<sanitized>", "resourceId": null, "userAgent": "<sanitized>" }
  },
  "recommendedMitigation": "<from the map above>"
}
```

- Hash: `crypto.createHash('sha256').update(fileBytes).digest('hex')`, kept
  outside the file and recorded in `incident_actions`.
- Verify: the browser reads the chosen file as text with `FileReader`, POSTs
  `{ filename, content }` as JSON, and the server re-hashes the received text.
- Mandatory disclaimer on every page that shows a hash: *"SHA-256 here
  demonstrates whether the exported file has changed. Hashing by itself does not
  establish authenticity or a complete chain of custody."*

---

## 6. Hardening invariants (true in BOTH modes)

| Area | Setting |
|---|---|
| Helmet | on; strict CSP; `upgrade-insecure-requests` disabled for the local http demo |
| Session | `httpOnly`, `sameSite=lax`, `secure` only in production, `regenerate()` on sign-in |
| CSRF | per-session token on every unsafe method, including logout and the mode switch |
| Passwords | bcrypt cost 11; one generic "Invalid email or password" message |
| Validation | `express-validator` on register, login, comment, search and `:id` |
| Errors | central handler; stack traces only when `NODE_ENV !== production` |
| Rate limit | `/login` and `/register` only |
| Data | `request_data` allowlist + recursive redaction |

Intentionally weakened in VULNERABLE mode and nowhere else: SQLi query
construction, XSS output encoding, the XSS route's CSP, and the IDOR ownership
check.

---

## 7. Interface contracts (theme and layout)

### 7.1 Theme preference

The theme is an interface preference, not a security control, so it lives in a
readable cookie (`ws_theme`) and is resolved **server-side** on every request.
That is what removes the flash of the wrong theme without an inline script —
which matters here, because the CSP forbids inline script everywhere except the
XSS lab.

| Cookie value | `<html>` attribute | Colours come from |
|---|---|---|
| `light` | `data-theme="light"` | the explicit light token block |
| `dark` | `data-theme="dark"` | the explicit dark token block |
| `system` | (no attribute) | `prefers-color-scheme` in `public/css/tokens.css` |
| absent | (no attribute) | same as `system` |

Rules that the acceptance suite enforces:

- Three semantic token layers only: primitives, light, dark. Components never
  hard-code a colour — `public/css/tokens.css` is the single place a palette is
  defined, and `@media (prefers-color-scheme: dark)` repeats the dark block for
  the `system` case.
- `public/js/theme.js` writes the cookie and rewrites the attribute; it never
  touches the first paint. It dispatches `themechange` on `window` so the charts
  can restyle themselves from the same tokens.
- `prefers-reduced-motion: reduce` disables every transition and animation.
- The print stylesheet forces the light palette regardless of the active theme.

### 7.2 Layout

| Breakpoint | Behaviour |
|---|---|
| `> 900px` | sidebar is a sticky column; the hamburger is not rendered effective |
| `<= 900px` | sidebar becomes an off-canvas drawer, opened by the top-bar toggle |
| `<= 700px` | top bar takes a second row (`--topbar-h` becomes `88px`) |
| `<= 560px` | metric row and segmented-control labels collapse |

Three invariants, all regression-tested:

1. **No horizontal page scroll.** Every multi-track grid uses
   `minmax(0, 1fr)`; a bare `1fr` track cannot shrink below its content, and a
   Chart.js canvas reports a pixel width, so a bare track pushes the whole page
   into sideways scroll. Wide tables scroll inside `.ws-table-scroll` instead.
2. **Responsive overrides come last.** A same-specificity media query only wins
   when it appears after the rule it overrides, so section 21 of `app.css`
   (responsive) sits after section 20 (grid) and before section 22 (print).
3. **The sidebar rail spans the full column.** A sticky box is sized by its own
   content, so `.ws-sidebar` (the rail that owns the background and the right
   border) uses `align-self: stretch` and the stickiness lives on
   `.ws-sidebar__inner`. Inside the `<=900px` drawer the inner box is reset to
   `position: static` so the whole drawer scrolls as one surface.
