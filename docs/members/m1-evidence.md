# Evidence — M1 · SQL injection

Filled in **Saturday**. Everything here has to be produced by your own run, not
copied: the values below are what you should see, so treat a mismatch as a finding
worth reporting, not a template to overwrite.

Server state for every screenshot: `npm run db:reset && npm run dev`, signed in as
**ADMIN**, browser at 100 %, one window.

---

## 1. Payload table

| Payload | Mode | Expected result | Score / severity | Rule | My run |
|---|---|---|---|---|---|
| `laptop` (normal search) | SAFE | 2 released products | no event | — | |
| `' OR 1=1--` | SAFE | 0 rows — sent as a bound parameter | `NEUTRALIZED` / 85 / HIGH | `SQLI_TAUTOLOGY` | |
| `' OR 1=1--` | VULNERABLE | 12 rows, including 3 **unreleased** | `SUCCESSFUL` / 100 / CRITICAL | `SQLI_TAUTOLOGY` | |
| `' UNION SELECT 1,email,password_hash,'1','x' FROM users--` | VULNERABLE | refused by the `lab_reader` role, HTTP 500 | `BLOCKED` | — | |
| >50 characters / control characters | SAFE | rejected by validation, HTTP 400 | `BLOCKED` | — | |

The re-test line is the one the rubric looks for: **same payload, byte for byte,
only the mode changed.**

## 2. Screenshots

| # | What it must show | File |
|---|---|---|
| 1 | Dashboard in SAFE, before any attack | `m1-01-dashboard-safe.png` |
| 2 | SQLi lab, SAFE, result: **0 rows** + the statement box showing `$1` | `m1-02-sql-safe-parameter.png` |
| 3 | SQLi lab, VULNERABLE, result: **12 rows** with the 3 unreleased badges | `m1-03-sql-vulnerable-12-rows.png` |
| 4 | Security Events, first row: `SQLI_TAUTOLOGY`, VULNERABLE, SUCCESSFUL, 100, CRITICAL | `m1-04-event-100-critical.png` |
| 5 | Investigation page for that event: summary + sanitized evidence + timeline | `m1-05-investigation.png` |
| 6 | Security Events after the re-test: same rule, `NEUTRALIZED`, 85, HIGH | `m1-06-retest-85-high.png` |

## 3. Test output

```
$ npm test
# paste the tail — detector, risk and outcome-model totals

$ npm run test:acceptance
# paste the tail — must read 26 passed, 0 failed
```

Date run: `____` · Commit: `____` · Node `____` · PostgreSQL `____`

## 4. What I claim, and what I do not

- **Claim:** the flaw is real (unreleased rows leak), the detector names the rule,
  and the identical request is neutralized in SAFE.
- **Do not claim:** that regex detection is a WAF. Encoding, whitespace and
  comment tricks evade it — that limitation is said out loud in beat G, and this
  file is where you can show you know it.
- **Also true:** even in VULNERABLE mode the injected query runs as `lab_reader`,
  which can only read `products`, so the UNION payload aimed at `users` is refused
  by the database itself. Screenshot it if you want the strongest slide.

## 5. Report section

Paste your `REPORT.md` section here once it is written, or leave a pointer:
`docs/REPORT.md` → *6.1 SQL Injection*.
