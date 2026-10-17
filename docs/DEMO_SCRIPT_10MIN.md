# WebSecLab — video script (target 9:45, hard limit 10:00)

**One owner per attack.** M1 owns SQL injection, M2 owns cross-site scripting,
M3 owns IDOR. Every attack segment is ~1:55 and follows the *same five beats*, so
the three segments are directly comparable and nobody is reading another
member's notes. The lifecycle close is shared; the three attacks are not.

The short 7:30 cut (single presenter, one runbook) is in `docs/DEMO_SCRIPT.md`.
This file is the one to use when the brief says ten minutes and one attack per
member.

**Click-by-click steps for every runbook below, with the expected on-screen
result and the security-event values, are in
[`docs/ATTACK_DEMOS.md`](ATTACK_DEMOS.md).** Use this file for timing and
narration, that one for the keyboard.

**Word-for-word presenter scripts, one per member, are in
[`docs/MEMBER_SCRIPTS.md`](MEMBER_SCRIPTS.md)** — each is self-contained and
prints its own spoken word count and pace, so you can rehearse your part alone.

```bash
npm run db:reset          # clean dashboard, resets the demo passwords
npm run dev
```

Open these before you press record:

1. `http://localhost:3000/login`
2. `/labs/sql`, `/labs/xss`, `/labs/idor` — one tab each
3. `/security/events`, signed in as ADMIN
4. Burp Suite → Repeater (intercept **off**)
5. A terminal at a clear prompt
6. `exports/` open in a file browser

---

## Timing

| Time | Segment | Owner | On screen |
|---|---|---|---|
| 0:00–0:45 | The problem and the lifecycle | M1 | Login page. Three classic flaws; name the loop: Attack → Detect → Log → Investigate → Secure → Re-test |
| 0:45–1:20 | Architecture in one pass | M1 | Dashboard. Express + EJS + PostgreSQL, one global SAFE/VULNERABLE switch, detection runs on response finish so logging can never change a response |
| 1:20–3:15 | **SQL injection, end to end** | **M1** | Runbook 1 |
| 3:15–5:10 | **Cross-site scripting, end to end** | **M2** | Runbook 2 |
| 5:10–7:05 | **IDOR, end to end** | **M3** | Runbook 3 |
| 7:05–8:35 | Forensics: log → investigate → export → verify | M3 leads; M1 and M2 each take one line | Events → Investigate → timeline → Export → download → Verify pass → edit one character → Verify fail |
| 8:35–9:20 | Hardening and the dashboard | M2 | What SAFE actually changes, and what never changes; metrics, both charts, filters |
| 9:20–9:45 | Repository, tests, conclusion | all three | `npm run test:acceptance` → 26/26. One closing line each |

Budgets are deliberately equal for the three attacks. If you overrun, cut from
8:35–9:20 first, never from an attack segment — unequal screen time is the thing
a marker notices.

## The five beats every attack segment uses

| Beat | Length | What the owner says |
|---|---|---|
| 1. The flaw | 0:25 | What the weakness *is*, in one sentence, without jargon |
| 2. It works | 0:30 | Run it against VULNERABLE mode and narrate what changes on screen |
| 3. It is detected | 0:20 | Security Events: rule name, result, score, severity |
| 4. It is stopped | 0:25 | Switch to SAFE, **resend the identical request**, compare |
| 5. Mitigation and limit | 0:15 | The fix, plus one honest limitation |

Beat 4 is the one that earns marks: the request is byte-identical, only the mode
changed. Say that out loud.

---

## Runbook 1 — SQL injection (M1, 1:20–3:15)

| # | Do this | Expect |
|---|---|---|
| 1 | Sign in as ADMIN. Dashboard reads SAFE. | Protected state |
| 2 | `/labs/sql`, search `laptop`. | Normal products only |
| 3 | Switch to VULNERABLE. | Red badge, warning banner, all three controls read OFF |
| 4 | Search `laptop` again. | Same rows — a normal search is unaffected by the mode |
| 5 | Burp Repeater: replay with `q=' OR 1=1--` | 200, extra rows marked *unreleased*, and the executed SQL string printed on the page |
| 6 | Security Events. | One event: SQLI_TAUTOLOGY, VULNERABLE, SUCCESSFUL, 100 CRITICAL |
| 7 | Switch to SAFE. Resend the same request. | 0 rows; second event, NEUTRALIZED, 85 HIGH |
| 8 | Optional: `' UNION SELECT 1,email,password_hash,'1','x' FROM users--` in VULNERABLE | Database refuses it → logged BLOCKED. *The weakness is real; the blast radius is not* |

**Say:** the flaw is string concatenation in the `WHERE` clause.
**Detection:** `SQLI_TAUTOLOGY` (first match wins across nine rules).
**Mitigation:** parameterized queries + server-side validation + least privilege.
**Honest limit:** the vulnerable query runs as `lab_reader`, which holds `SELECT`
on `products` and nothing else, so a `UNION` aimed at `users` fails at the
database. And the detector is regex-based — evadable by encoding, case and
whitespace. This is an educational detector, not a WAF.

## Runbook 2 — Cross-site scripting (M2, 3:15–5:10)

| # | Do this | Expect |
|---|---|---|
| 1 | `/labs/xss`, mode VULNERABLE. Post `<script>alert(document.domain)</script>` | Dialog fires — the comment executed for every visitor |
| 2 | Open browser console, type `document.cookie`. | Only `ws_theme=…`, the theme preference. The **session** cookie is absent: it is `httpOnly`, so script cannot reach it |
| 3 | Switch to SAFE, reload the same page. | The *same* stored comment now renders as inert text |
| 4 | Open the events table. | XSS_SCRIPT_TAG, SUCCESSFUL 90 CRITICAL, then NEUTRALIZED 75 HIGH |

**Say:** the comment is stored **once, raw**; switching modes changes the
*rendering*, not the database. That is exactly why the re-test is meaningful.
**Say:** there is exactly one unescaped data render in the whole application, in
the VULNERABLE branch of this lab — the acceptance suite asserts that.
**Say:** the CSP is relaxed on `/labs/xss` and only while VULNERABLE; every other
route keeps `script-src 'self'`.
**Mitigation:** context-aware output encoding + sanitization + strict CSP +
`httpOnly` cookies.

## Runbook 3 — IDOR (M3, 5:10–7:05)

| # | Do this | Expect |
|---|---|---|
| 0 | Keep an **ADMIN** session in a second browser: only an ADMIN can move the global switch, and this lab has no admin exemption, so the attacker must be a non-owner. | Two sessions: defender (switch) + attacker (screen time) |
| 1 | In the attacker browser sign in as **alice**. `/labs/idor`, open your own document. | Loads, and records **no** event |
| 2 | Edit the id in the URL to Bob's document. | VULNERABLE: 200 with Bob's title and content |
| 3 | Switch to SAFE, request the same id. | 403; title and content are not sent at all |
| 4 | Request your **own** document in SAFE. | Still works, still silent |

**Say:** the ids are sequential *on purpose* — enumeration is the lab.
**Say:** the query is parameterized in **both** modes; this lab demonstrates
broken access control, not injection. There is no administrator exemption inside
it either.
**Detection:** `IDOR_OWNER_MISMATCH` — a logic condition, not a payload pattern.
**Expected:** SUCCESSFUL 95 CRITICAL, then BLOCKED 80 HIGH.
**Mitigation:** a server-side ownership check on every object access; return 403;
never trust a client-supplied id.

---

## Shared close (all three)

**7:05–8:35 — Forensics.** M3 drives; M1 and M2 each take one sentence.

- Events console: filters by type, severity and result, free-text search, pagination.
- Investigate opens on the event UUID: summary, request evidence (already sanitized), timeline, mitigation map.
- **Timeline honesty:** only two timestamps genuinely exist, so stages 1–4 share one time and the page says so in plain text. We chose an honest single timestamp over inventing per-stage times.
- Export writes `exports/evidence-<uuid>-<stamp>.json` with a fixed key order; those exact bytes are hashed, and the SHA-256 is recorded in `incident_actions` **outside** the file.
- Download and verify: passes. Edit one character and verify again: fails.
- Read the disclaimer aloud: hashing proves the file has not changed relative to the recorded value; it is not a complete chain of custody.

**8:35–9:20 — Hardening.** M2.

- What SAFE changes: the SQLi query construction, XSS output encoding, the XSS route's CSP, and the IDOR ownership check.
- What never changes: bcrypt cost 11 and one generic failure message, CSRF on every unsafe method including sign-out and the mode switch, `express-validator` on every input, rate limiting on auth routes only, an allowlist-plus-redaction sanitizer for everything logged, and the `lab_reader` role.
- Resilience worth one sentence: a database outage degrades to sign-out and SAFE instead of crashing, and the monitor catches its own errors.
- Dashboard: monitored requests, event count, successful vs blocked, both charts, then the filters.

**9:20–9:45 — Repository, tests, conclusion.**

Run `npm run test:acceptance` and let **26/26** land on screen. Point at
`docs/CONTRACTS.md` as the frozen interface. Then one line each:

- M1: *Attack → Detect* — "the flaw is real, and the detector sees it."
- M2: *Log → Investigate* — "every attempt is scored and reconstructable."
- M3: *Secure → Re-test* — "one switch proves the fix, on the same request."

## Recording checklist

- [ ] `npm run db:reset` before recording, so the dashboard starts clean
- [ ] Burp intercept **off** except while demonstrating a replay
- [ ] Browser at 100 %, one window, no bookmarks bar, no other tabs visible
- [ ] Each of the three attacks is narrated by its owner end to end
- [ ] The same request is resent in both modes for all three attacks
- [ ] Every attack segment contains the word *mitigation* and one honest limit
- [ ] Total runtime under 10:00
- [ ] No third-party system appears anywhere in the recording
