# Attack demonstration steps — one owner per attack

Click-by-click runbooks for the three attacks this project ships:

| Owner | Attack | Route | Segment |
|---|---|---|---|
| **M1** | SQL injection | `GET /labs/sql?q=` | 1:20–3:15 |
| **M2** | Cross-site scripting | `GET /labs/xss`, `POST /labs/xss/comments` | 3:15–5:10 |
| **M3** | IDOR (broken access control) | `GET /labs/idor/documents/:id` | 5:10–7:05 |

This is the detail sheet behind [`DEMO_SCRIPT_10MIN.md`](DEMO_SCRIPT_10MIN.md)
(the timed script) and [`MEMBER_SCRIPTS.md`](MEMBER_SCRIPTS.md) (the word-for-word
narration, one script per member), and it is also the checklist for a viva or for
the report screenshots. Every "Expect" value below is what the running
application actually does — the same values the acceptance suite asserts.

> "Owner" here means the **presenter**, not the author of that lab's code. The
> code-ownership split (M2 built the XSS *and* IDOR labs) is the contributor table
> in [`README.md`](../README.md). Presenting an attack someone else implemented is
> the normal arrangement, and it keeps each member responsible for explaining all
> five beats of one attack.

> **Attacks covered: these three only.** SQL injection, stored XSS and IDOR —
> there is no fourth lab in the codebase and nothing below assumes one.

**No tooling is required.** Every step works through the normal UI. Burp is used
only for the optional byte-identical replay in [Appendix A](#appendix-a--optional-byte-identical-replay-in-burp).

---

## 0. Pre-flight (once, before any of the three segments)

```bash
npm run db:reset        # clean dashboard, re-seeds the demo data and passwords
npm run dev
```

Leave `RESIDUAL_RISK_RATE` unset (it defaults to `0`). Every segment below ends
by re-sending the identical request after the mode switch, and that comparison
only lands if the mode is what decides the result. With the model on, a minority
of attempts are deliberately decided the other way — useful for making the
dashboard look like a live environment, fatal to a live comparison.

Want the log to look lived-in before you start? `npm run demo:traffic` sends 21
recorded attacks plus 6 benign requests through the real labs and self-verifies
every one of them.

Then, in one browser window:

| Tab | URL | Used by |
|---|---|---|
| 1 | `http://localhost:3000/login` | all three |
| 2 | `http://localhost:3000/dashboard` | mode switch + metrics |
| 3 | `http://localhost:3000/security/events` | M1, M2, M3 |
| 4 | `http://localhost:3000/labs/sql` | M1 |
| 5 | `http://localhost:3000/labs/xss` | M2 |
| 6 | `http://localhost:3000/labs/idor` | M3 |

Sign in as **ADMIN** (`admin@webseclab.local` / `Admin-Lab-Demo-2026`) — use the
**Use** button on the login page and it fills both fields for you. Only an ADMIN
can move the global switch, and every lab is reachable from the same session.

### The one control that matters

The **Global mode** switch lives in the top bar, as a segmented control, on
**every page** — you never have to leave the lab to change it:

```
Global mode  [ SAFE ][ VULNERABLE ]
```

- Clicking **VULNERABLE** pops a browser confirm dialog. Accept it.
- Switching back to **SAFE** has no dialog.
- The switch is **global**: one row in `app_settings`, read from the database on
  *every* request, and it covers all three labs at once.
- The active side of the switch is disabled, so it is never ambiguous which mode
  you are in. Non-admins see a read-only `SAFE` / `VULNERABLE` badge instead.

**Every runbook starts by setting the mode it needs.** Segments are therefore
independent: they can be recorded in any order, and a member who overruns cannot
leave the next member in the wrong mode.

### The five beats each member follows

| Beat | What you do | Why it earns marks |
|---|---|---|
| 1. State the flaw | One sentence, no jargon, before touching the keyboard | Shows you understand the *cause*, not just a payload |
| 2. Make it work | Mode = **VULNERABLE** → run the payload → narrate what changed on screen | Proves the weakness is real |
| 3. Show it is detected | Open **Security Events**, read rule / result / score / severity | Closes Attack → Detect → Log |
| 4. Stop it | Switch to **SAFE** → **send the identical request again** → compare | The re-test. Say "identical request" out loud |
| 5. Mitigate and admit a limit | The fix from the mitigation map, then one honest limitation | Markers reward honesty |

---

## Runbook 1 — M1 · SQL injection (~1:55)

**The flaw (say it first):** *"The search term is concatenated straight into the
SQL string, so an apostrophe in the box stops being text and starts being code."*

### Steps

| # | Do this | Expect on screen |
|---|---|---|
| 1 | Top bar → **SAFE**. Open tab 4 (`/labs/sql`). | Protection status: **3 / 3 controls on** — parameterized query, server-side validation, and the always-on least-privilege role. No warning banner |
| 2 | In **Search term** type `laptop`, click **Search**. | **2 rows**: *AeroBook 14 Laptop*, *AeroBook Pro 16 Laptop*. Header reads `Parameterized query: ON`. No unreleased rows |
| 3 | Click the **Tautology** example link (`' OR 1=1--`). | **0 rows** — *"In SAFE mode an injection payload is a literal string, so it matches nothing."* The statement box shows `name ILIKE $1`. **This is the baseline:** the exact payload that exposes 12 rows in step 6 does nothing here |
| 4 | Top bar → **VULNERABLE** → accept the confirm. | Red **VULNERABLE** badge; warning banner *"Intentionally insecure behaviour is enabled"*; protection panel now **1 / 3 controls on**; the always-on one is the least-privilege database role |
| 5 | In **Search term** type `laptop` again → **Search**. | Still **2 rows**. Say: *a normal search is unaffected — the mode changes how the query is built, not what a search means* |
| 6 | Click the **Tautology** example link (`' OR 1=1--`). | **12 rows** and an amber badge **3 unreleased rows exposed** — *Falcon Pre-Release Laptop*, *Helios Internal Test Server*, *Aurora Prototype Display*, each tagged `unreleased`. Below the header, the box **"Statement sent to the database"** shows the concatenated SQL with your payload inside it |
| 7 | Open tab 3 (**Security Events**), first row. | `SQL_INJECTION` · rule `SQLI_TAUTOLOGY` · mode `VULNERABLE` · **CRITICAL** · score **100** · result **SUCCESSFUL** · HTTP **200** |
| 8 | Click **Investigate** on that row. | Investigation page: summary, sanitized request evidence, timeline, mitigation map |
| 9 | Back to tab 4. Top bar → **SAFE**. **Search the identical payload again** (`' OR 1=1--`). | **0 rows** — *"In SAFE mode an injection payload is a literal string, so it matches nothing."* The statement box now shows `name ILIKE $1` |
| 10 | Back to tab 3, refresh. | A **second** event, same rule: mode `SAFE` · **HIGH** · score **85** · result **NEUTRALIZED** · HTTP 200 |

**Optional flourish (15 s).** Click the **Reach for another table** example link —
`' UNION SELECT 1,email,password_hash,'1','x' FROM users--`. In VULNERABLE mode:

- The page shows an error from the database, HTTP **500**, and the event is
  logged **BLOCKED**.
- Say: *"The weakness is real; the blast radius is not. The vulnerable query runs
  as `lab_reader`, which holds `SELECT` on `products` and nothing else, so the
  database itself refuses to reach `users`."*

If you run that link while SAFE is on instead, it returns HTTP **400** —
the payload is 57 characters and SAFE validates the term to 50.

### What to say

> "Detection is regex-based and it runs when the response finishes, so it can
> never change the response — blocking happens in the controller, logging happens
> in the monitor. The mitigation is three things: a bound parameter so the term
> can only ever be text, server-side validation, and least privilege so a
> mistake cannot reach the user table. **Limitation:** regex detection is
> evadable by encoding, case and whitespace tricks. This is an educational
> detector, not a WAF."

---

## Runbook 2 — M2 · Cross-site scripting (~1:55)

**The flaw (say it first):** *"A comment is stored exactly as submitted, and in
VULNERABLE mode the page prints it without escaping — so the markup I type becomes
part of the page every visitor loads."*

### Steps

| # | Do this | Expect on screen |
|---|---|---|
| 1 | Top bar → **VULNERABLE**. Open tab 5 (`/labs/xss`). | Red badge; warning banner; **Stored comments** header shows the badge **rendered unescaped**; protection panel shows **2 / 4 controls on** — *output escaping* and *strict CSP* are OFF, while *httpOnly cookie* and *comment validation* show **always on** |
| 2 | In **Comment** paste `<script>alert(document.domain)</script>` → **Post comment**. | The page reloads and an **alert dialog fires** showing the host you are on (`localhost`). Accept it. (The POST itself answered **302**; detection logs the attempt as soon as the redirect completes) |
| 3 | Look at **Stored comments**, the top entry. | Your raw `<script>…</script>` text is *the page content*, not text on the page — it is a real stored row (the 4th comment on a fresh seed), authored by the signed-in account |
| 4 | Open the browser console (F12) and type `document.cookie`. | Only `ws_theme=…` — the theme preference. **The session cookie is not there**: it is `httpOnly`, so script cannot read it. This is the mitigation that was *not* switched off |
| 5 | Open tab 3 (**Security Events**), first row. | `XSS` · rule `XSS_SCRIPT_TAG` · `VULNERABLE` · **CRITICAL** · score **90** · **SUCCESSFUL** · HTTP **302** |
| 6 | Back to tab 5. Top bar → **SAFE**. Reload the page (F5). | The **same stored comment** now renders as visible inert text — `<script>alert(document.domain)</script>` as characters. Info banner: *"A comment stored in VULNERABLE mode is now inert text — the database row is unchanged."* Header badge flips to **rendered escaped**; protection panel back to **4 / 4 controls on** |
| 7 | Back to tab 3, refresh. | A **second** event, same rule: `SAFE` · **HIGH** · score **75** · **NEUTRALIZED** · HTTP 302 |

**Two things to point at, because they are the interesting part:**

- **The database never changed.** One row, one payload, written once in
  VULNERABLE mode. Only the rendering changed — which is exactly why the re-test
  is meaningful rather than a code diff.
- **The row was not deleted or sanitized.** The fix is at the output, in the
  view, plus the policy. There is exactly one unescaped data render in the entire
  application, and you were just looking at it.

### What to say

> "Stored XSS, not reflected: the payload lives in the database and would run for
> every visitor. SAFE mode closes it twice, independently — the view escapes the
> comment, and the route drops back to `script-src 'self'`, which only ever
> relaxes on `/labs/xss` while VULNERABLE. Mitigation: context-aware output
> encoding, a strict CSP, and `httpOnly` session cookies. **Limitation:** the
> demonstrated payload is deliberately harmless (`alert`), and the relaxed CSP
> exists only to make the lab visible — in production that second layer is what
> catches the cases escaping misses."

---

## Runbook 3 — M3 · IDOR (~1:55)

**The flaw (say it first):** *"The document id in the URL is never compared with
the signed-in user. The ids are sequential on purpose, so guessing one is the
whole attack."*

### Setup: two sessions, on purpose

Only an ADMIN can move the global switch, and this lab has **no administrator
exemption** — so the attacker cannot be the account that owns the switch. Use two
browsers (Chrome + Firefox, or a normal and an incognito window):

| | Browser | Sign in as | Role in the demo |
|---|---|---|---|
| **A** | Chrome | `admin@webseclab.local` | Owns the top-bar switch. Nothing else |
| **B** | Firefox / incognito | `alice@webseclab.local` / `User-Lab-Demo-2026` | The attacker. All the screen time |

This is a better demo than a single session: the defender and the attacker are
genuinely separate, which is the point of an access-control bug.

> **Shorter single-session alternative.** Sign in as ADMIN only, and open another
> user's document instead of "your own": VULNERABLE → HTTP **200** with their
> title and content, SAFE → HTTP **403**. You lose only the "my own document is
> silent" beat, and the lab index will read *"This account owns no documents"* —
> which is itself worth one sentence: *there is no exempt administrator inside
> this lab*.

### Steps

| # | Do this | Expect on screen |
|---|---|---|
| 1 | Browser A: top bar → **VULNERABLE**. | Red badge in A |
| 2 | Browser B: open `/labs/idor`. Read the **Your documents** table. | Alice's own documents, with their **Id** column. Write those ids down or keep the list visible — the section below the table tells you the full range (7 documents, ids 1–7) |
| 3 | Browser B: click **Open** on your own first document. | It loads. Blue banner *"You own this document, so it is served in both modes and no security event is recorded."* Authorization result **NO EVENT**; ownership check **PERFORMED**; HTTP **200** |
| 4 | Browser B: click **Try id …** at the foot of that page (it requests the next id up), or type an id that is **not** in your list into **Document id** and press **Open document**. | The rule that always works: *any id that is not in your own list belongs to the other account*. If you land on one of your own, you stay in the "you own it" state — step up one id and try again |
| 5 | Browser B: land on someone else's document. | Amber banner *"Another user's document was returned — this belongs to bob@webseclab.local"*, badge **SUCCESSFUL**, **Ownership check: NOT PERFORMED**, HTTP **200**, and the full title and content are shown |
| 6 | Browser **A** (the events console is ADMIN-only): open `/security/events`, first row. | `IDOR` · rule `IDOR_OWNER_MISMATCH` · `VULNERABLE` · **CRITICAL** · score **95** · **SUCCESSFUL** · HTTP **200**. Note the **Payload** column is `—`: this rule matches a *logic condition*, not a string |
| 7 | Browser A: top bar → **SAFE**. | Swap to the SAFE side |
| 8 | Browser B: request the **identical id** again (reload, or re-submit the URL). | Red banner **"HTTP 403 — You do not own this document"**; badge **BLOCKED**; ownership check **PERFORMED — owner mismatch, request refused**; a *"Document withheld"* card where the content was. **The title and content are not sent at all** |
| 9 | Browser B: open **your own** document again. | Still **200**, still no event. SAFE mode did not break legitimate access |
| 10 | Browser A: refresh `/security/events`. | A **second** event for the same document: `SAFE` · **HIGH** · score **80** · **BLOCKED** · HTTP **403** |

**Why the score drops by only 15.** The attempt is still logged and still
`HIGH`: a blocked attempt is evidence, not a non-event. The −10 for
BLOCKED/NEUTRALIZED is applied on top of the base score, it does not erase it.

### What to say

> "Broken access control, not injection — the document query is parameterized in
> **both** modes, so the only thing that changes is the ownership comparison. The
> ids are sequential because that is the lab. Mitigation: an authorization check
> on every object access, server-side, comparing the session user with the row's
> owner, returning 403, and never trusting a client-supplied id. Note the 403
> body: the title and content are not sent at all — a 403 that still leaks the
> payload would defeat the check. **Limitation:** this is a per-resource check; a
> real system needs it as a single enforced rule on every query, and the unknown-id
> case must stay a plain 404 so it does not become an oracle."

---

## Shared segment — Forensics (M3 leads, 7:05–8:35)

All three speak; M3 drives. Start on `/security/events` in the ADMIN session.

| # | Do this | Expect |
|---|---|---|
| 1 | Filter **Attack type** = `IDOR`, **Severity** = `CRITICAL`, click **Apply**. | The table narrows; the count in the header follows |
| 2 | Type `sql` in **Search**, **Apply**, then **Reset**. | Free-text search across endpoint, rule and payload text |
| 3 | **Investigate** on any event. | Full incident by UUID |
| 4 | Read the **timeline** and the honesty note under it. | Stages 1–4 share a single timestamp, and **the page says why** in plain text: only two real timestamps exist, and we chose an honest one over inventing four |
| 5 | **Export** to JSON. | `exports/evidence-<uuid>-<stamp>.json` appears; a SHA-256 is recorded in `incident_actions`, **outside** the file |
| 6 | **Download** it, then open **Verify Evidence**, choose the file, **Verify**. | **Verified** — the re-hashed bytes match |
| 7 | Edit one character of the JSON, verify again. | **Failed** — this is the demonstration |
| 8 | Read the disclaimer aloud. | *"Hashing proves the file has not changed relative to the recorded value. It is not a chain of custody and does not establish authenticity."* |

---

## Failure recovery (rehearse these once)

| Symptom | Cause | Fix |
|---|---|---|
| The payload returns rows in SAFE mode | You are still in VULNERABLE | Check the top-bar switch; the active side is disabled |
| The XSS payload does not execute | SAFE mode | VULNERABLE, and reload `/labs/xss` |
| `403` when you expected `200` on IDOR | SAFE mode, or you requested your **own** document | Check the ownership row on the page |
| No new row in Security Events | You are looking at a stale page | Detection runs on response finish — refresh once |
| Sign-in silently does not stick | `NODE_ENV=production` on `http://localhost` makes the cookie `secure` | Use `development` in `.env` |
| `EADDRINUSE` | Something else holds port 3000 | Change `PORT` |
| The dashboard is full of old events | Previous runs and test suites leave their audit trail | `npm run db:reset` before recording |

---

## Appendix A — Optional byte-identical replay in Burp

Only worth doing for **one** of the three attacks, to make the "same request"
claim literal. Full procedure: [`BURP_STEPS.md`](BURP_STEPS.md).

1. Burp listener on `127.0.0.1:8080`, intercept **off**.
2. Browse `http://127.0.0.1:3000` (or use Burp's browser) — browsers bypass the
   proxy for `localhost`.
3. Sign in, put the mode on VULNERABLE, run the attack once through the UI.
4. **Proxy → HTTP history** → right-click the request → **Send to Repeater**.
5. Switch the mode to SAFE **without editing the request**.
6. **Send** in Repeater — the bytes are identical, only the server state changed.
   Compare the response with the one you captured in step 4.

| Attack | Request to replay | VULNERABLE → SAFE |
|---|---|---|
| SQLi | `GET /labs/sql?q=' OR 1=1--` | `200`, 12 rows → `200`, 0 rows |
| XSS | `POST /labs/xss/comments` with `comment=<script>…</script>` | `302` → `302` (then reload the page: executes → inert) |
| IDOR | `GET /labs/idor/documents/<other user's id>` | `200` + content → `403`, content withheld |

## Appendix B — Print the document id map (rehearsal only)

Seed order is not guaranteed, so the ids on the IDOR lab page are the source of
truth. To see the map before you record:

```bash
node -e "require('dotenv').config();const{Pool}=require('pg');const p=new Pool({connectionString:process.env.DATABASE_URL});p.query('SELECT d.id,d.title,u.email FROM user_documents d JOIN users u ON u.id=d.owner_id ORDER BY d.id').then(r=>{r.rows.forEach(x=>console.log(x.id,'|',x.email,'|',x.title));return p.end()})"
```

Whichever ids are **not** in Alice's list are the IDOR targets.

---

## Rehearsal checklist

- [ ] `npm run db:reset` immediately before recording
- [ ] Sign-in via the **Use** button — no password typed on camera
- [ ] Each member sets the mode at the **start** of their own segment
- [ ] All three attacks: the same request is sent in both modes
- [ ] All three attacks name a **mitigation** and one **honest limitation**
- [ ] The mode is left on **SAFE** at the end
- [ ] `npm run test:acceptance` lands **26/26** on screen
- [ ] Nothing on screen targets any system other than `localhost`
