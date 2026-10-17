# WebSecLab — presenter scripts, one per member

Word-for-word scripts for a **9:45** video (hard limit 10:00). Three members, one
attack each:

| Member | Owns | Airtime |
|---|---|---|
| **M1** | The problem, the architecture, **SQL injection** | 0:00–3:15 |
| **M2** | **Cross-site scripting**, and the hardening wrap-up | 3:15–5:10, 8:35–9:20 |
| **M3** | **IDOR**, and the forensics segment | 5:10–8:35 |

Each script below is **self-contained**: print only your own section and you have
everything you need. The step-level detail (every screen value, every failure
mode) is in [`ATTACK_DEMOS.md`](ATTACK_DEMOS.md).

**How to use it.** The `Say:` lines are the script — read them out, or paraphrase
them, but keep the meaning. The `Do:` lines are what your hands are doing while
you talk, and they never need narrating. **Bold** lines must be said out loud
verbatim, because they are the lines the rubric is looking for.

**Pace.** 140–150 words per minute is comfortable and clear; above 175 sounds
rushed. Every block below prints its spoken word count, and each script ends with
its own total and pace, so you can tell which of *your* beats is overrunning
before you record. If you are long, cut the analysis, never the switch.

**How the counts are measured**, so you can check any of them: one word = one
whitespace-separated token of the quoted `Say:` text, with the quotation marks
and the `**Say:**` marker removed. Nothing in a `Do:` line is counted, and a
member's total adds their own closing line but not the shared close at the end.

---

## Shared pre-flight (all three, five minutes before recording)

```bash
npm run db:reset        # clean dashboard, re-seeds passwords and demo data
npm run dev
```

1. Sign in with the **Use** button on the login page — never type a password on
   camera.
2. **M1**: sign in as **ADMIN**, confirm the top bar reads **SAFE**.
3. **M2**: sign in as **ADMIN**, set the top bar to **VULNERABLE** (accept the
   confirm dialog).
4. **M3**: two browsers — **Chrome** as ADMIN (this one only shows the log and
   moves the switch), **Firefox** as `alice@webseclab.local`. Set the mode to
   **VULNERABLE** from Chrome.
5. One window, browser at 100 %, no bookmarks bar, no other tabs visible.
6. Burp closed unless you are deliberately doing the optional replay.

**The global switch lives in the top bar on every page.** Each member sets the
mode they need at the *start* of their own segment, because the mode persists —
M2 leaves it on SAFE, so M3 has to put it back.

---

# Script 1 — M1 · 0:00–3:15

### Setup before you start

- Signed in as **ADMIN**, top bar on **SAFE**, you are on the **Dashboard**.
- Tabs open: **Dashboard**, **`/labs/sql`**, **`/security/events`**.

### Beat A — the problem · 0:00–0:32 · 89 words

> **Say:** "Hello, we're Group `[[ name ]]`, and this is WebSecLab. Most security demonstrations stop at showing you a broken page. We built the other half: what the defender sees. Three weaknesses are built into three routes on purpose — SQL injection, cross-site scripting, and broken access control — and around them is a console that detects each attempt, scores it, logs it, and lets you investigate it and export the evidence. Each of us owns one attack. Every attack follows the same loop."

**Bold, say it directly:**

> **Say:** "Attack, Detect, Log, Investigate, Secure, Re-test."

### Beat B — the architecture you need to understand · 0:32–1:05 · 90 words

> **Say:** "It's Node and Express with EJS templates and PostgreSQL. No mocked data: every number on this dashboard is a real query. Two design decisions matter for everything you're about to see. First, the security mode at the top of the screen is a single row in the database, read on every request — never cached, no restart. Second, detection runs when the response finishes, after the reply has already been sent, so detection can never change what an attacker sees. Blocking happens in the controller; logging happens in the monitor."

### Beat C — the flaw · 1:05–1:25 · 44 words

**Do:** click the **SQL Injection** tab.

> **Say:** "I own SQL injection. The weakness is one line of code: the search term is concatenated straight into the SQL string. There's no bound parameter, so an apostrophe isn't text any more — it ends the string, and whatever follows is parsed as SQL."

### Beat D — it works · 1:25–2:05 · 127 words

**Do:** type `laptop`, **Search**. Then click the **Tautology** example link.

> **Say:** "We're in SAFE mode. A normal search returns two released products. Now the same box, with the payload: apostrophe, OR 1 equals 1, comment. Nothing — zero rows. In SAFE mode that term is sent as a bound parameter, so it is only ever a literal string, and no product is named apostrophe-OR-1-equals-1. The statement box even shows you the parameter."

**Do:** top bar → **VULNERABLE**, accept the dialog. Search `laptop`. Then click the **Tautology** link again.

> **Say:** "Now I flip the switch — it's global, it applies to all three labs — and I resend the identical request. The normal search still returns the same two products, so the mode hasn't broken searching. And the payload: twelve rows. That's every product in the catalogue, including three marked **unreleased** — rows a normal search never shows. Those three amber badges are the data leak."

### Beat E — detected · 2:05–2:30 · 59 words

**Do:** **Security Events** tab, point at the first row, then click **Investigate**.

> **Say:** "Detection ran the moment that response finished — it's already in the log. Rule `SQLI_TAUTOLOGY`, which tells you exactly what matched: first match wins, out of nine rules. Mode VULNERABLE, result SUCCESSFUL, score 100, CRITICAL. Investigate gives the full incident by UUID: the request evidence, already sanitized so no credential is ever stored, a timeline, and the recommended mitigation."

### Beat F — stopped · 2:30–2:55 · 63 words

**Do:** back to the SQLi tab → top bar → **SAFE** → click the **Tautology** link again.

**Bold — this is the marked line:**

> **Say:** "This is the re-test. I switch to SAFE and send the **identical request** — same payload, byte for byte. Only the mode changed. Zero rows."

**Do:** refresh **Security Events**.

> **Say:** "Same rule fired, because the same payload was still sent. But the result is now NEUTRALIZED, and the score drops from 100 to 85, HIGH. The attempt is still recorded: a blocked attempt is evidence, not a non-event."

### Beat G — mitigation, limit, hand-over · 2:55–3:15 · 86 words

> **Say:** "The fix is three things: a bound parameter, so the term can only ever be text; server-side validation on the input; and least privilege — the vulnerable query runs as a database role that can only read the products table, so even while it's vulnerable, a union payload aimed at the users table is refused by the database itself. One honest limitation: detection here is regex-based, so encoding and whitespace tricks can evade it. It's an educational detector, not a WAF. M2 will take cross-site scripting."

### Your closing line · 9:20–9:45

> **Say:** "Attack, then Detect: the flaw is real, and the detector sees it."

### If it goes wrong

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

# Script 2 — M2 · 3:15–5:10 and 8:35–9:20

### Setup before you start

- Signed in as **ADMIN**, and you have just set the top bar to **VULNERABLE**.
- Tabs open: **`/labs/xss`**, **`/security/events`**.

### Beat C — the flaw · 3:15–3:35 · 49 words

**Do:** click the **Cross-Site Scripting** tab. Point at **Protection status**:
**2 / 4 controls on**.

> **Say:** "I own cross-site scripting — stored, not reflected. A comment is written to the database exactly as I submit it, and in vulnerable mode the page prints it back without escaping. So the markup I type becomes part of the page — for every visitor, not just for me."

### Beat D — it works · 3:35–4:15 · 107 words

**Do:** paste `<script>alert(document.domain)</script>`, click **Post comment**, accept the dialog.

> **Say:** "That dialog is my markup, running as code inside this page. It came back from the database, not from my request — which is what makes it stored. And notice the design: the comment is escaped on the way *out*, not on the way in. The row is stored raw in both modes. The mode only decides how it is rendered."

**Do:** open the console (F12), type `document.cookie`.

> **Say:** "Now the honest part. `document.cookie` shows only the theme preference. The session cookie isn't there at all, because it's `httpOnly` — script cannot read it. So the payload runs, but it cannot walk away with my session. That control was never switched off, not even here."

### Beat E — detected · 4:15–4:35 · 54 words

**Do:** **Security Events** tab, first row.

> **Say:** "The log has it: rule `XSS_SCRIPT_TAG`, mode VULNERABLE, SUCCESSFUL, score 90, CRITICAL, and note the status code is 302 — the POST answered a redirect. One more thing worth saying: two protections are off on this route and nowhere else. The output escaping, and the Content-Security-Policy, which is relaxed on `/labs/xss` *only* while vulnerable."

### Beat F — stopped · 4:35–5:00 · 64 words

**Do:** back to the lab, top bar → **SAFE**, reload the page (F5).

**Bold — the marked line:**

> **Say:** "I switch to SAFE and reload — I do not resubmit, I reload. The **same stored comment** is now inert text. Identical payload, identical database row; only the rendering changed. That's why this is a real re-test and not a code diff."

**Do:** refresh **Security Events**.

> **Say:** "The log now shows the same rule with NEUTRALIZED, 75, HIGH. And the panel back here reads four of four controls on."

### Beat G — mitigation, limit, hand-over · 5:00–5:10 · 36 words

> **Say:** "The fix: context-aware output encoding, a strict Content-Security-Policy, and `httpOnly` cookies. Honest limitation: the payload I used is deliberately harmless, and that relaxed policy exists only to make the lab visible. M3 takes broken access control."

### Hardening wrap-up · 8:35–9:20 · 115 words

**Do:** the **Dashboard**. Metrics row, then both charts, then the events filters.

> **Say:** "So what did SAFE actually change? Four things, and nothing else: how the SQL query is built, how comments are encoded on output, the Content-Security-Policy on that one route, and the ownership check on documents. Everything else is on in both modes: CSRF tokens on every unsafe request — including sign-out and the mode switch itself — bcrypt at cost 11 with one generic failure message, validation on every input, rate limiting on login and register only, and a logging sanitizer that redacts anything that looks like a credential. And if the database goes down, the app fails closed to SAFE instead of crashing. This dashboard counts real rows: monitored requests, events, successful against blocked."

### Your closing line · 9:20–9:45

> **Say:** "Log, then Investigate: every attempt is scored and reconstructable."

### If it goes wrong

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

# Script 3 — M3 · 5:10–7:05 and 7:05–8:35

### Setup before you start

- **Two browsers.** Chrome signed in as **ADMIN** (switch and log only). Firefox
  signed in as **alice@webseclab.local** — all your screen time is here.
- From Chrome, set the top bar to **VULNERABLE**.
- Firefox tabs: **`/labs/idor`**, and Chrome tabs: **`/security/events`**,
  **`/forensics/verify`**.
- Have the ids from Alice's **Your documents** table in front of you: *any id not
  in that list belongs to Bob.*

### Beat C — the flaw · 5:10–5:30 · 49 words

**Do:** in Firefox, the `/labs/idor` tab — point at the **Your documents** table.

> **Say:** "I own broken access control — specifically IDOR, insecure direct object reference. Documents are fetched by the id in the URL, and those ids are sequential on purpose. In vulnerable mode the controller never compares the owner of the document with the signed-in user. I'm signed in as Alice."

### Beat D — it works · 5:30–6:10 · 85 words

**Do:** click **Open** on Alice's first document, then change the id in the URL to Bob's.

> **Say:** "This is my own document. It loads, and no event is recorded — because nothing happened. Now I change exactly one thing: the number at the end of the URL. This one belongs to Bob. Full title, full content, HTTP 200 — and the page is honest about why: **ownership check, not performed**. The authorized request and the attack differ by a single character. That's the whole point of an IDOR: there is no payload, so there is nothing for an input filter to catch."

### Beat E — detected · 6:10–6:30 · 53 words

**Do:** switch to Chrome, refresh **Security Events**, point at the first row.

> **Say:** "But the defender still has it. Rule `IDOR_OWNER_MISMATCH`, mode VULNERABLE, SUCCESSFUL, score 95, CRITICAL. Notice the payload column is empty — and that's not a bug. Every other rule matches a string in the request. This rule matches a *condition*: the signed-in user is not the owner of the row that was returned."

### Beat F — stopped · 6:30–6:55 · 76 words

**Do:** Chrome → top bar → **SAFE**. Firefox → reload the exact same URL.

**Bold — the marked line:**

> **Say:** "Same switch. Same id, same request, byte for byte. Now: 403 — you do not own this document. And look at what is *not* in the response: the title and the content are withheld entirely. A 403 that still returned the body would defeat the point of the check. In the log: BLOCKED, 80, HIGH."

**Do:** Firefox → open Alice's own document again.

> **Say:** "And my own document still works in SAFE mode. Legitimate access was not broken — only the unauthorized path was closed."

### Beat G — mitigation, limit, hand-over · 6:55–7:05 · 40 words

> **Say:** "Fix: an authorization check on every object access, server-side, comparing the session user with the row's owner — and never trusting a client-supplied id. Note the query is parameterized in *both* modes: this lab is about access control, not injection."

### Forensics segment · 7:05–8:35 · 162 words

**Do:** Chrome. Filter **Attack type** IDOR + **Severity** CRITICAL → **Apply**.
Then type `sql` in **Search** → **Apply** → **Reset**.

> **Say:** "Now the shared part: what a defender does with all of this. The events console filters by type, severity and result, with free-text search and pagination. Open an incident: summary, the sanitized request evidence, a timeline, and the mitigation map. And one deliberate honesty point on that timeline — only two timestamps genuinely exist in this system, when the event occurred and when the investigation was opened. So the first four stages share a single time, and the page says so, rather than inventing four."

**Do:** **Export** → **Download** → **Verify Evidence** → choose the file → **Verify**.

> **Say:** "Export writes a JSON file with a fixed key order, hashes those exact bytes, and records the SHA-256 *outside* the file. Download it and verify: it passes. Now I change one character and verify again — and it fails. That's the demonstration."

**Do:** point at the disclaimer on the page, read it.

> **Say:** "And the disclaimer, because this is the part people overstate: hashing proves the file has not changed compared with the recorded value. It is not a chain of custody, and it does not establish authenticity."

### Your closing line · 9:20–9:45

> **Say:** "Secure, then Re-test: one switch proves the fix, on the identical request."

### If it goes wrong

| Symptom | Fix |
|---|---|
| You land on one of Alice's documents | Keep stepping the id up — any id outside her list is Bob's |
| `403` when you expected `200` | Chrome is already on SAFE — check before Beat D |
| You can't move the switch in Firefox | Correct: Alice is a USER. The switch lives in Chrome, the admin session |
| The investigation page 404s | Forensics routes require ADMIN — use the Chrome session |

**Your totals (counted from this script):** 477 spoken words over 205 s —
**140 wpm**, comfortably inside the range and the slowest of the three. That is
fine for the segment with the most to point at, but you have room: either slow
down further, or add one sentence to the forensics block. Nothing needs cutting.
(Your count excludes the four lines in the shared close below — the 46 words all
three of you say together at 9:20.)

---

## The 25-second close (all three, 9:20–9:45)

**Do:** run `npm run test:acceptance` and let **26/26** land on screen.

> **M1:** "Thirty-seven detector cases, twenty risk cases, twenty-six end-to-end checks against the real HTTP interface — all green."
> **M2:** "Log, then Investigate: every attempt is scored and reconstructable."
> **M3:** "Secure, then Re-test: one switch proves the fix, on the identical request."
> **M1:** "Attack, Detect, Log, Investigate, Secure, Re-test. Thank you."

## Rehearsal checklist

- [ ] Each member sets the **mode** at the start of their own segment
- [ ] Every attack segment contains the **identical request in both modes**
- [ ] Every attack segment names a **mitigation** and one **honest limitation**
- [ ] The mode is explained **once** (M1 architecture) and summarised **once** (M2 hardening) — never three times
- [ ] Every member speaks for their own segment and their own closing line
- [ ] Total under 10:00, and each member is within ~10 % of their word target
