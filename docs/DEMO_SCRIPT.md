# WebSecLab — video script (target 7:30, hard limit 8:00)

> **Wrong length or brief?** If the requirement is a ten-minute video in which
> each member owns one attack type, use [`docs/DEMO_SCRIPT_10MIN.md`](DEMO_SCRIPT_10MIN.md)
> instead. This file is the 7:30 single-runbook cut.

All three members speak. Record after a full dry run, on a reset database.

```bash
npm run db:reset          # clean dashboard, resets the demo passwords
npm run dev
```

Have these tabs open before you press record:

1. `http://localhost:3000/login`
2. Burp Suite → Repeater (Proxy → Repeater tab ready)
3. A terminal, scrolled to a clear prompt
4. `exports/` open in a file browser

One person drives the keyboard for each segment; that person is also the speaker
unless noted. Click-by-click steps with expected screen results are in
[`docs/ATTACK_DEMOS.md`](ATTACK_DEMOS.md).

| Time | Segment | Speaker | On screen |
|---|---|---|---|
| 0:00–0:30 | Intro and objective | M1 | Login page. State the problem: three classic flaws, and the defender's half of the story. Name the lifecycle: Attack → Detect → Log → Investigate → Secure → Re-test |
| 0:30–1:00 | Architecture and lifecycle | M1 | Scroll the dashboard. Mention: Express + EJS + PostgreSQL, strict helmet CSP, one global SAFE/VULNERABLE switch, detection runs on response finish |
| 1:00–2:45 | SQL injection, end to end | M1 drives, **M3 explains detection at the events step** | See the SQLi runbook below |
| 2:45–3:25 | XSS | M2 | Post the payload in VULNERABLE, show it execute, switch to SAFE, reload the same page, show the same comment inert. Say plainly: the database was never changed, only the rendering |
| 3:25–4:05 | IDOR | M2 | Open your own document, then change the id in the URL. 200 and someone else's content in VULNERABLE; 403 in SAFE. Point out that your own document is silent in both modes |
| 4:05–5:15 | Forensics | M3 | Events table → Investigate → timeline → read the one-timestamp honesty note → Export → download → Verify (pass) → edit one character → Verify (fail) → read the SHA-256 disclaimer aloud |
| 5:15–5:55 | Dashboard and events | M2 | Metrics row, both charts, filters (type/severity/result), search, the rules table at the bottom |
| 5:55–6:35 | Hardening | M1 | Say what SAFE mode actually changes, and what never changes: the lab_reader role means a successful injection still cannot read `users`. Mention CSP scoped to `/labs/xss` only in VULNERABLE, CSRF on every POST, bcrypt cost 11, rate limiting on auth routes only |
| 6:35–7:15 | Repository and contributions | M3 | Code layout, `docs/CONTRACTS.md`, the test suites. Run `npm run test:acceptance` and let 26/26 land on screen. Show `git shortlog -sn` if history is available |
| 7:15–7:30 | Conclusion | All three, one line each | Attack → Detect → Log → Investigate → Secure → Re-test |

## SQL injection runbook (1:00–2:45)

| Step | Do this | Expect |
|---|---|---|
| 1 | Sign in as admin. Dashboard shows SAFE. | Protected state |
| 2 | Search `laptop` in the SQLi lab. | Normal results only |
| 3 | Switch to VULNERABLE (top bar). Note the red badge and the warning banner. | The three protections read OFF |
| 4 | Search `laptop` again. | Same results — normal search is unaffected |
| 5 | In Burp Repeater, replay the request with `q=' OR 1=1--` | 200, extra rows marked *unreleased*, and the executed SQL string is shown on the page |
| 6 | Admin → Security Events. **M3 explains:** the tautology rule fired, the attack succeeded, score 100 CRITICAL, and the sanitized payload is what you see in the table. | One new event, VULNERABLE, SUCCESSFUL |
| 7 | Investigate → Export → download → Verify. | Hash verifies |
| 8 | Switch to SAFE. **Resend the same Burp request.** | 0 rows, and a second event: NEUTRALIZED, 85 HIGH |
| 9 | Optional flourish: send `' UNION SELECT 1,email,password_hash,'1','x' FROM users--` in VULNERABLE mode. | The database refuses it (least-privilege role) — logged as BLOCKED. Say: the weakness is real, the blast radius is not |

## Recording checklist

- [ ] Database reset before recording, so the dashboard starts from a clean state
- [ ] Burp proxy intercept **off** except when demonstrating step 5 (left on, it
      makes the UI look frozen)
- [ ] Browser at 100 % zoom, one window, no bookmarks bar, no other tabs visible
- [ ] Session cookie never appears on screen (it is `httpOnly`, so console
      `document.cookie` shows only the readable `ws_theme` preference, never the
      session cookie — you can demonstrate that on purpose)
- [ ] Every member speaks for at least their segment
- [ ] Total runtime under 8:00 — cut the optional step 9 first
- [ ] No third-party system appears anywhere in the recording
