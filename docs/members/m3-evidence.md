# Evidence — M3 · IDOR + forensics

Filled in **Saturday**. Everything here has to be produced by your own run: the
values below are what you should see, so treat a mismatch as a finding worth
reporting rather than a template to overwrite.

Server state for every screenshot: `npm run db:reset && npm run dev`. **Two
browsers:** Chrome as **ADMIN** (log + switch), Firefox as
`alice@webseclab.local` (all your screen time).

---

## 1. Request table

Record Alice's own document ids first — everything not in this list is Bob's.

| Alice's ids | `____`, `____`, `____`, `____` |
|---|---|

| Request | Mode | Expected result | Score / severity | Rule | My run |
|---|---|---|---|---|---|
| `GET /labs/idor/documents/<alice id>` | both | 200, own content, **no event** | — | — | |
| `GET /labs/idor/documents/<bob id>` | VULNERABLE | 200, Bob's full title and content, page says **ownership check, not performed** | `SUCCESSFUL` / 95 / CRITICAL | `IDOR_OWNER_MISMATCH` | |
| `GET /labs/idor/documents/<bob id>` | SAFE | **403**, title and content withheld entirely | `BLOCKED` / 80 / HIGH | `IDOR_OWNER_MISMATCH` | |
| `GET /labs/idor/documents/<alice id>` | SAFE | 200 — legitimate access still works | — | — | |

The point to say out loud: the attack and the authorized request differ by **one
character**, there is no payload, so nothing an input filter could catch. The rule
matches a *condition* — session user ≠ row owner — which is why the payload column
on the event is empty.

## 2. Evidence export

| Step | Expected | My run |
|---|---|---|
| **Export** → **Download** | JSON file, fixed key order | |
| **Verify Evidence** on the untouched file | **passes** — SHA-256 matches the recorded value | |
| Change one character, verify again | **fails** | |

Disclaimers to state, because this is the part people overstate: hashing proves
the file has not changed *compared with the recorded value*. It is **not** a chain
of custody and it does **not** establish authenticity.

## 3. Screenshots

| # | What it must show | File |
|---|---|---|
| 1 | IDOR lab, Alice's document list with the ids visible | `m3-01-alice-documents.png` |
| 2 | Bob's document, VULNERABLE, HTTP 200, "ownership check, not performed" | `m3-02-bob-document-200.png` |
| 3 | Events: `IDOR_OWNER_MISMATCH`, VULNERABLE, SUCCESSFUL, 95, CRITICAL, **payload empty** | `m3-03-event-95-critical.png` |
| 4 | Same URL in SAFE: **403 — you do not own this document**, no body | `m3-04-403-withheld.png` |
| 5 | Alice's own document still 200 in SAFE | `m3-05-own-document-still-works.png` |
| 6 | Events after the re-test: `BLOCKED`, 80, HIGH | `m3-06-retest-80-high.png` |
| 7 | Investigations page: summary, sanitized evidence, timeline, mitigation map | `m3-07-investigation.png` |
| 8 | Verify page: pass, then fail after the one-character edit | `m3-08-verify-pass-then-fail.png` |
| 9 | Events console filters applied (type IDOR + severity CRITICAL) and free-text search | `m3-09-filters.png` |

## 4. Test output

```
$ npm test
# paste the tail — detector, risk and outcome-model totals

$ npm run test:acceptance
# paste the tail — must read 26 passed, 0 failed
```

Date run: `____` · Commit: `____` · Node `____` · PostgreSQL `____`

## 5. What I claim, and what I do not

- **Claim:** no ownership check in VULNERABLE, so another user's document is
  returned; the check in SAFE returns 403 and withholds the body; the console
  still records the attempt, because a blocked attempt is evidence.
- **Do not claim:** that the evidence hash is chain of custody. Say the limitation
  out loud — it earns more marks than glossing over it.
- **Timeline honesty:** only two timestamps genuinely exist (when the event
  occurred, when the investigation was opened), so the first four stages share one
  time and the page says so rather than inventing four.

## 6. Report section

Paste your `REPORT.md` section here once it is written, or leave a pointer:
`docs/REPORT.md` → *6.3 IDOR* and *8. Forensic investigation*.
