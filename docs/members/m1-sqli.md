# Script 1 — M1 · SQL injection · 0:00–3:15

**Your file. Nothing else is needed to present your segment.** You own the
opening, the architecture, and **SQL injection**. This is the same text as
`Script 1` in [`../MEMBER_SCRIPTS.md`](../MEMBER_SCRIPTS.md), split out so you can
print only your own pages.


The `Say:` lines are the script — read them out, or paraphrase them, but keep the
meaning. The `Do:` lines are what your hands are doing while you talk, and they
never need narrating. **Bold** lines must be said out loud verbatim, because they
are the lines the rubric is looking for.

Click-level detail for every screen is in
[`../ATTACK_DEMOS.md`](../ATTACK_DEMOS.md).

---

## Pre-flight (five minutes before recording)

```bash
npm run db:reset        # clean dashboard, re-seeds passwords and demo data
npm run dev
```

1. Sign in with the **Use** button on the login page — never type a password on
   camera. You are **ADMIN**.
2. Confirm the top bar reads **SAFE** — you open the video in SAFE mode.
3. Tabs open: **Dashboard**, **`/labs/sql`**, **`/security/events`**.
4. One window, browser at 100 %, no bookmarks bar, no other tabs visible.
5. Burp closed unless you are deliberately doing the optional replay.

**The global switch lives in the top bar on every page.** Each member sets the
mode they need at the *start* of their own segment, because the mode persists.

## Setup before you start

- Signed in as **ADMIN**, top bar on **SAFE**, you are on the **Dashboard**.
- Tabs open: **Dashboard**, **`/labs/sql`**, **`/security/events`**.

---

## Beat A — the problem · 0:00–0:32 · 89 words

> **Say:** "Hello, we're Group `[[ name ]]`, and this is WebSecLab. Most security demonstrations stop at showing you a broken page. We built the other half: what the defender sees. Three weaknesses are built into three routes on purpose — SQL injection, cross-site scripting, and broken access control — and around them is a console that detects each attempt, scores it, logs it, and lets you investigate it and export the evidence. Each of us owns one attack. Every attack follows the same loop."

**Bold, say it directly:**

> **Say:** "Attack, Detect, Log, Investigate, Secure, Re-test."

## Beat B — the architecture you need to understand · 0:32–1:05 · 90 words

> **Say:** "It's Node and Express with EJS templates and PostgreSQL. No mocked data: every number on this dashboard is a real query. Two design decisions matter for everything you're about to see. First, the security mode at the top of the screen is a single row in the database, read on every request — never cached, no restart. Second, detection runs when the response finishes, after the reply has already been sent, so detection can never change what an attacker sees. Blocking happens in the controller; logging happens in the monitor."

## Beat C — the flaw · 1:05–1:25 · 44 words

**Do:** click the **SQL Injection** tab.

> **Say:** "I own SQL injection. The weakness is one line of code: the search term is concatenated straight into the SQL string. There's no bound parameter, so an apostrophe isn't text any more — it ends the string, and whatever follows is parsed as SQL."

## Beat D — it works · 1:25–2:05 · 127 words

**Do:** type `laptop`, **Search**. Then click the **Tautology** example link.

> **Say:** "We're in SAFE mode. A normal search returns two released products. Now the same box, with the payload: apostrophe, OR 1 equals 1, comment. Nothing — zero rows. In SAFE mode that term is sent as a bound parameter, so it is only ever a literal string, and no product is named apostrophe-OR-1-equals-1. The statement box even shows you the parameter."

**Do:** top bar → **VULNERABLE**, accept the dialog. Search `laptop`. Then click the **Tautology** link again.

> **Say:** "Now I flip the switch — it's global, it applies to all three labs — and I resend the identical request. The normal search still returns the same two products, so the mode hasn't broken searching. And the payload: twelve rows. That's every product in the catalogue, including three marked **unreleased** — rows a normal search never shows. Those three amber badges are the data leak."

## Beat E — detected · 2:05–2:30 · 59 words

**Do:** **Security Events** tab, point at the first row, then click **Investigate**.

> **Say:** "Detection ran the moment that response finished — it's already in the log. Rule `SQLI_TAUTOLOGY`, which tells you exactly what matched: first match wins, out of nine rules. Mode VULNERABLE, result SUCCESSFUL, score 100, CRITICAL. Investigate gives the full incident by UUID: the request evidence, already sanitized so no credential is ever stored, a timeline, and the recommended mitigation."

## Beat F — stopped · 2:30–2:55 · 63 words

**Do:** back to the SQLi tab → top bar → **SAFE** → click the **Tautology** link again.

**Bold — this is the marked line:**

> **Say:** "This is the re-test. I switch to SAFE and send the **identical request** — same payload, byte for byte. Only the mode changed. Zero rows."

**Do:** refresh **Security Events**.

> **Say:** "Same rule fired, because the same payload was still sent. But the result is now NEUTRALIZED, and the score drops from 100 to 85, HIGH. The attempt is still recorded: a blocked attempt is evidence, not a non-event."

## Beat G — mitigation, limit, hand-over · 2:55–3:15 · 86 words

> **Say:** "The fix is three things: a bound parameter, so the term can only ever be text; server-side validation on the input; and least privilege — the vulnerable query runs as a database role that can only read the products table, so even while it's vulnerable, a union payload aimed at the users table is refused by the database itself. One honest limitation: detection here is regex-based, so encoding and whitespace tricks can evade it. It's an educational detector, not a WAF. M2 will take cross-site scripting."

## Your closing line · 9:20–9:45

> **Say:** "Attack, then Detect: the flaw is real, and the detector sees it."

## If it goes wrong

| Symptom | Fix |
|---|---|
| Payload returns rows in SAFE | You are still in VULNERABLE — check the top bar; the active side is disabled |
| No new row in the log | Detection runs on response finish — refresh once |
| You forgot which tab is which | The breadcrumb under the title says where you are |

**Your totals (counted from this script):** 570 spoken words over 195 s —
**175 wpm**, above the comfortable range. The two longest beats are **D (127)**
and **B (90)**, so cut there: drop "every number on this dashboard is a
real query" in B, and the statement-box sentence in D. Removing ~80 words puts you
at **490 words / 150 wpm**.

---

## The shared close (all three, 9:20–9:45)

**Do:** run `npm run test:acceptance` and let **26/26** land on screen.

> **M1:** "Thirty-seven detector cases, twenty risk cases, twenty-six end-to-end checks against the real HTTP interface — all green."
> **M2:** "Log, then Investigate: every attempt is scored and reconstructable."
> **M3:** "Secure, then Re-test: one switch proves the fix, on the identical request."
> **M1:** "Attack, Detect, Log, Investigate, Secure, Re-test. Thank you."

The four lines above are the 46 words all three of you say together.
