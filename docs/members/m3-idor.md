# Script 3 — M3 · IDOR · 5:10–8:35

**Your file. Nothing else is needed to present your segment.** You own **broken
access control (IDOR)** and the **forensics segment**. This is the same text as
`Script 3` in [`../MEMBER_SCRIPTS.md`](../MEMBER_SCRIPTS.md), split out so you can
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

**Two browsers, on purpose:**

- **Chrome** signed in as **ADMIN** — this session only shows the log and moves
  the switch. Set the top bar to **VULNERABLE** from here.
- **Firefox** signed in as `alice@webseclab.local` — all your screen time is here.

Chrome tabs: **`/security/events`**, **`/forensics/verify`**.
Firefox tabs: **`/labs/idor`**.

Sign in with the **Use** button on the login page — never type a password on
camera. M2 leaves the mode on **SAFE**, so putting it back to **VULNERABLE** is
your first action.

## Setup before you start

- **Two browsers.** Chrome signed in as **ADMIN** (switch and log only). Firefox
  signed in as **alice@webseclab.local** — all your screen time is here.
- From Chrome, set the top bar to **VULNERABLE**.
- Firefox tabs: **`/labs/idor`**, and Chrome tabs: **`/security/events`**,
  **`/forensics/verify`**.
- Have the ids from Alice's **Your documents** table in front of you: *any id not
  in that list belongs to Bob.*

---

## Beat C — the flaw · 5:10–5:30 · 49 words

**Do:** in Firefox, the `/labs/idor` tab — point at the **Your documents** table.

> **Say:** "I own broken access control — specifically IDOR, insecure direct object reference. Documents are fetched by the id in the URL, and those ids are sequential on purpose. In vulnerable mode the controller never compares the owner of the document with the signed-in user. I'm signed in as Alice."

## Beat D — it works · 5:30–6:10 · 85 words

**Do:** click **Open** on Alice's first document, then change the id in the URL to Bob's.

> **Say:** "This is my own document. It loads, and no event is recorded — because nothing happened. Now I change exactly one thing: the number at the end of the URL. This one belongs to Bob. Full title, full content, HTTP 200 — and the page is honest about why: **ownership check, not performed**. The authorized request and the attack differ by a single character. That's the whole point of an IDOR: there is no payload, so there is nothing for an input filter to catch."

## Beat E — detected · 6:10–6:30 · 53 words

**Do:** switch to Chrome, refresh **Security Events**, point at the first row.

> **Say:** "But the defender still has it. Rule `IDOR_OWNER_MISMATCH`, mode VULNERABLE, SUCCESSFUL, score 95, CRITICAL. Notice the payload column is empty — and that's not a bug. Every other rule matches a string in the request. This rule matches a *condition*: the signed-in user is not the owner of the row that was returned."

## Beat F — stopped · 6:30–6:55 · 76 words

**Do:** Chrome → top bar → **SAFE**. Firefox → reload the exact same URL.

**Bold — the marked line:**

> **Say:** "Same switch. Same id, same request, byte for byte. Now: 403 — you do not own this document. And look at what is *not* in the response: the title and the content are withheld entirely. A 403 that still returned the body would defeat the point of the check. In the log: BLOCKED, 80, HIGH."

**Do:** Firefox → open Alice's own document again.

> **Say:** "And my own document still works in SAFE mode. Legitimate access was not broken — only the unauthorized path was closed."

## Beat G — mitigation, limit, hand-over · 6:55–7:05 · 40 words

> **Say:** "Fix: an authorization check on every object access, server-side, comparing the session user with the row's owner — and never trusting a client-supplied id. Note the query is parameterized in *both* modes: this lab is about access control, not injection."

## Forensics segment · 7:05–8:35 · 162 words

**Do:** Chrome. Filter **Attack type** IDOR + **Severity** CRITICAL → **Apply**.
Then type `sql` in **Search** → **Apply** → **Reset**.

> **Say:** "Now the shared part: what a defender does with all of this. The events console filters by type, severity and result, with free-text search and pagination. Open an incident: summary, the sanitized request evidence, a timeline, and the mitigation map. And one deliberate honesty point on that timeline — only two timestamps genuinely exist in this system, when the event occurred and when the investigation was opened. So the first four stages share a single time, and the page says so, rather than inventing four."

**Do:** **Export** → **Download** → **Verify Evidence** → choose the file → **Verify**.

> **Say:** "Export writes a JSON file with a fixed key order, hashes those exact bytes, and records the SHA-256 *outside* the file. Download it and verify: it passes. Now I change one character and verify again — and it fails. That's the demonstration."

**Do:** point at the disclaimer on the page, read it.

> **Say:** "And the disclaimer, because this is the part people overstate: hashing proves the file has not changed compared with the recorded value. It is not a chain of custody, and it does not establish authenticity."

## Your closing line · 9:20–9:45

> **Say:** "Secure, then Re-test: one switch proves the fix, on the identical request."

## If it goes wrong

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

## The shared close (all three, 9:20–9:45)

**Do:** run `npm run test:acceptance` and let **26/26** land on screen.

> **M1:** "Thirty-seven detector cases, twenty risk cases, twenty-six end-to-end checks against the real HTTP interface — all green."
> **M2:** "Log, then Investigate: every attempt is scored and reconstructable."
> **M3:** "Secure, then Re-test: one switch proves the fix, on the identical request."
> **M1:** "Attack, Detect, Log, Investigate, Secure, Re-test. Thank you."

The four lines above are the 46 words all three of you say together.
