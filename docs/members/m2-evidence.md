# Evidence — M2 · Cross-site scripting + hardening wrap-up

Filled in **Saturday**. Everything here has to be produced by your own run: the
values below are what you should see, so treat a mismatch as a finding worth
reporting rather than a template to overwrite.

Server state for every screenshot: `npm run db:reset && npm run dev`, signed in as
**ADMIN**, browser at 100 %, one window.

---

## 1. Payload table

| Payload | Mode | Expected result | Score / severity | Rule | My run |
|---|---|---|---|---|---|
| `Great product, thanks!` (normal comment) | both | renders as text, no event | no event | — | |
| `<script>alert(document.domain)</script>` | SAFE | stored raw, rendered **escaped** — inert text | `NEUTRALIZED` / 75 / HIGH | `XSS_SCRIPT_TAG` | |
| `<script>alert(document.domain)</script>` | VULNERABLE | stored raw, rendered **unescaped** — dialog fires | `SUCCESSFUL` / 90 / CRITICAL | `XSS_SCRIPT_TAG` | |
| `<img src=x onerror=alert(document.domain)>` | VULNERABLE | fires on render | `SUCCESSFUL` | `XSS_EVENT_HANDLER` | |
| `<svg onload=alert(document.domain)>` | VULNERABLE | fires on render | `SUCCESSFUL` | `XSS_EVENT_HANDLER` | |

Two facts to state on camera, because they are the interesting part:

- The re-test is a **reload, not a resubmit** — the row in the database is
  identical, only the rendering changes. POST answers HTTP **302**.
- `document.cookie` shows **only the theme preference**. The session cookie is
  `httpOnly`, so the payload cannot read it. That control is on in both modes.

## 2. Screenshots

| # | What it must show | File |
|---|---|---|
| 1 | XSS lab, VULNERABLE, **Protection status 2 / 4 controls on** | `m2-01-protection-2-of-4.png` |
| 2 | The alert dialog with the domain | `m2-02-alert-fires.png` |
| 3 | DevTools console: `document.cookie` → theme only | `m2-03-httponly-cookie.png` |
| 4 | Security Events: `XSS_SCRIPT_TAG`, VULNERABLE, SUCCESSFUL, 90, CRITICAL, status 302 | `m2-04-event-90-critical.png` |
| 5 | Same lab in SAFE after reload: the stored comment as inert text | `m2-05-retest-inert.png` |
| 6 | Protection panel now **4 / 4 controls on** | `m2-06-protection-4-of-4.png` |
| 7 | Events after the re-test: `NEUTRALIZED`, 75, HIGH | `m2-07-retest-75-high.png` |
| 8 | Dashboard for the wrap-up: metrics row + both charts + filters | `m2-08-dashboard-wrapup.png` |

## 3. Test output

```
$ npm test
# paste the tail — detector, risk and outcome-model totals

$ npm run test:acceptance
# paste the tail — must read 26 passed, 0 failed
```

Date run: `____` · Commit: `____` · Node `____` · PostgreSQL `____`

## 4. What I claim, and what I do not

- **Claim:** stored XSS, unescaped on output, executes for any visitor in
  VULNERABLE; the CSP is relaxed on `/labs/xss` **only while vulnerable**; the
  identical stored comment is inert in SAFE.
- **Do not claim:** that the payload is dangerous. It is deliberately harmless —
  `alert` proves execution, nothing else — and the lab is localhost-only.
- **Hardening wrap-up, one line each:** SAFE changed exactly four things — the SQL
  query, output encoding for comments, the CSP on that one route, and the
  ownership check on documents. Everything else is on in both modes (CSRF tokens
  on every unsafe request, bcrypt cost 11, validation, rate limiting on
  login/register, the logging sanitizer) and the app fails closed to SAFE if the
  database is unreachable.

## 5. Report section

Paste your `REPORT.md` section here once it is written, or leave a pointer:
`docs/REPORT.md` → *6.2 Cross-Site Scripting*.
