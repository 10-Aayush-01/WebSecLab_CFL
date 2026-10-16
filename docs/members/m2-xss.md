# Script 2 — M2 · Cross-site scripting · 3:15–5:10 and 8:35–9:20

**Your file. Nothing else is needed to present your segment.** You own **stored
XSS** and the **hardening wrap-up**. This is the same text as `Script 2` in
[`../MEMBER_SCRIPTS.md`](../MEMBER_SCRIPTS.md), split out so you can print only
your own pages.

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
2. Set the top bar to **VULNERABLE** (accept the confirm dialog) — you inherit it
   from M1 and you need to be in the vulnerable mode to start.
3. Tabs open: **`/labs/xss`**, **`/security/events`**.
4. One window, browser at 100 %, no bookmarks bar, no other tabs visible.
5. Burp closed unless you are deliberately doing the optional replay.

**You leave the mode on SAFE**, which is why M3 has to put it back.

## Setup before you start

- Signed in as **ADMIN**, and you have just set the top bar to **VULNERABLE**.
- Tabs open: **`/labs/xss`**, **`/security/events`**.

---

## Beat C — the flaw · 3:15–3:35 · 49 words

**Do:** click the **Cross-Site Scripting** tab. Point at **Protection status**:
**2 / 4 controls on**.

> **Say:** "I own cross-site scripting — stored, not reflected. A comment is written to the database exactly as I submit it, and in vulnerable mode the page prints it back without escaping. So the markup I type becomes part of the page — for every visitor, not just for me."

## Beat D — it works · 3:35–4:15 · 107 words

**Do:** paste `<script>alert(document.domain)</script>`, click **Post comment**, accept the dialog.

> **Say:** "That dialog is my markup, running as code inside this page. It came back from the database, not from my request — which is what makes it stored. And notice the design: the comment is escaped on the way *out*, not on the way in. The row is stored raw in both modes. The mode only decides how it is rendered."

**Do:** open the console (F12), type `document.cookie`.

> **Say:** "Now the honest part. `document.cookie` shows only the theme preference. The session cookie isn't there at all, because it's `httpOnly` — script cannot read it. So the payload runs, but it cannot walk away with my session. That control was never switched off, not even here."

## Beat E — detected · 4:15–4:35 · 54 words

**Do:** **Security Events** tab, first row.

> **Say:** "The log has it: rule `XSS_SCRIPT_TAG`, mode VULNERABLE, SUCCESSFUL, score 90, CRITICAL, and note the status code is 302 — the POST answered a redirect. One more thing worth saying: two protections are off on this route and nowhere else. The output escaping, and the Content-Security-Policy, which is relaxed on `/labs/xss` *only* while vulnerable."

## Beat F — stopped · 4:35–5:00 · 64 words

**Do:** back to the lab, top bar → **SAFE**, reload the page (F5).

**Bold — the marked line:**

> **Say:** "I switch to SAFE and reload — I do not resubmit, I reload. The **same stored comment** is now inert text. Identical payload, identical database row; only the rendering changed. That's why this is a real re-test and not a code diff."

**Do:** refresh **Security Events**.

> **Say:** "The log now shows the same rule with NEUTRALIZED, 75, HIGH. And the panel back here reads four of four controls on."

## Beat G — mitigation, limit, hand-over · 5:00–5:10 · 36 words

> **Say:** "The fix: context-aware output encoding, a strict Content-Security-Policy, and `httpOnly` cookies. Honest limitation: the payload I used is deliberately harmless, and that relaxed policy exists only to make the lab visible. M3 takes broken access control."

## Hardening wrap-up · 8:35–9:20 · 115 words

**Do:** the **Dashboard**. Metrics row, then both charts, then the events filters.

> **Say:** "So what did SAFE actually change? Four things, and nothing else: how the SQL query is built, how comments are encoded on output, the Content-Security-Policy on that one route, and the ownership check on documents. Everything else is on in both modes: CSRF tokens on every unsafe request — including sign-out and the mode switch itself — bcrypt at cost 11 with one generic failure message, validation on every input, rate limiting on login and register only, and a logging sanitizer that redacts anything that looks like a credential. And if the database goes down, the app fails closed to SAFE instead of crashing. This dashboard counts real rows: monitored requests, events, successful against blocked."

## Your closing line · 9:20–9:45

> **Say:** "Log, then Investigate: every attempt is scored and reconstructable."

## If it goes wrong

| Symptom | Fix |
|---|---|
| The alert does not fire | You are in SAFE mode — the relaxed CSP applies only to `/labs/xss` while VULNERABLE |
| The dialog never appears on reload | Reload, don't resubmit: the saved POST would just redirect again |
| `document.cookie` looks empty on your browser | Some browsers hide it in the console before the first write — the theme cookie appears as soon as you switch theme once |

**Your totals (counted from this script):** 434 spoken words over 160 s —
**163 wpm**, slightly fast. The longest block is the **hardening wrap-up (115)**,
so cut there: drop the rate-limiting clause and shorten the sanitizer clause.
Removing ~35 words puts you at **400 words / 150 wpm**.

---

## The shared close (all three, 9:20–9:45)

**Do:** run `npm run test:acceptance` and let **26/26** land on screen.

> **M1:** "Thirty-seven detector cases, twenty risk cases, twenty-six end-to-end checks against the real HTTP interface — all green."
> **M2:** "Log, then Investigate: every attempt is scored and reconstructable."
> **M3:** "Secure, then Re-test: one switch proves the fix, on the identical request."
> **M1:** "Attack, Detect, Log, Investigate, Secure, Re-test. Thank you."

The four lines above are the 46 words all three of you say together.
