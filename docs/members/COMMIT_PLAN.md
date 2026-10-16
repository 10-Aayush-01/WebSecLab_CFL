# What to commit — Friday 16 and Saturday 17 October

**Everything must be pushed and merged before Sunday 18 October.** Sunday is a
freeze: no code changes, you record the video and run the tests.

Three people, three branches, two days.

**Everyone has every file.** The owner pushes the complete project once, and
`git clone` then copies all ~100 files to each member's machine, with the full
history. The lists below say which files you may *change* — not which files you
receive. Git records a commit only for something you actually changed, so each
member's commits are the edits in their own area, their own documentation and
their own evidence.

| When | Who | What lands | Cut-off |
|---|---|---|---|
| **Fri morning** | Owner | The complete, running project, pushed to `main` | Fri 12:00 |
| **Fri afternoon** | M1, M2, M3 | Each member's own changes, one branch each | Fri 23:59 |
| **Sat morning** | M1, M2, M3 | Your own docs, evidence and one real fix | Sat 14:00 |
| **Sat afternoon** | Owner | Merge train, rehearsal fixes, acceptance run | Sat 20:00 |
| **Sun** | everyone | Freeze — record, verify, no commits | — |

---

## The rules (read once, they save a bad evening)

1. **One branch per member.** Nobody commits straight to `main` except the owner,
   once, to publish the project.
2. **`git add -A` only on that first owner commit.** After it, stage named
   paths — `git add -A` sweeps up a teammate's half-finished file, and one day it
   will sweep up `.env`.
3. **`.env`, `node_modules/`, `exports/*.json` are never committed.** `.gitignore`
   already blocks them; do not force them in.
4. **Shared files have one owner.** `src/app.js`, `package.json`, `README.md`,
   `views/partials/*`, `public/css/*`, `docs/CONTRACTS.md` and
   `docs/REPORT.md` belong to the owner. If you need a change in one, ask in the
   group chat first — two people editing one shared file on the same day is the
   single most likely way this goes wrong.
5. **`npm test` before every push, `npm run test:acceptance` before every merge**
   (the dev server must be running; it ends at **26/26**).
6. **A commit needs a real change.** If git answers `nothing to commit`, you have
   not changed anything in your own area yet — make a real improvement instead
   of re-staging files that are already committed.

---

## Who may change which files

### M1 — SQL injection, detection core, the shell

```
src/controllers/sqlController.js
views/labs/sql-lab.ejs
src/security/detectors/sqlDetector.js
src/security/detectors/index.js
src/security/detectors/rules.js
src/middleware/securityMonitor.js
src/security/securityLogger.js
src/security/riskCalculator.js
src/security/resultMapper.js
src/security/sanitizer.js
docs/members/m1-sqli.md
```

### M2 — XSS, CSP, dashboard and the hardening wrap-up

```
src/controllers/xssController.js
views/labs/xss-lab.ejs
src/security/detectors/xssDetector.js
src/middleware/csp.js
src/controllers/dashboardController.js
views/dashboard.ejs
public/js/dashboard.js
src/services/eventService.js
docs/members/m2-xss.md
```

### M3 — IDOR, forensics, evidence

```
src/controllers/idorController.js
views/labs/idor-lab.ejs
views/labs/idor-document.ejs
src/security/detectors/idorDetector.js
src/controllers/forensicsController.js
src/controllers/securityController.js
src/security/evidence.js
views/forensics/investigation.ejs
views/forensics/verify.ejs
views/security/events.ejs
public/js/forensics.js
src/routes/forensicsRoutes.js
src/routes/securityRoutes.js
docs/members/m3-idor.md
```

### Owner — the shared core and the first push (whoever created the GitHub repo,
usually M1)

```
src/server.js  src/app.js  src/config/*  src/labs/labContent.js  src/utils/format.js
src/middleware/{auth,csrf,flash,errorHandler,rateLimit,securityMode,theme}.js
src/routes/{index,authRoutes,dashboardRoutes,adminRoutes,labRoutes}.js
src/controllers/{authController,adminController}.js
src/security/{outcomeModel,password}.js
database/*  package.json  package-lock.json  .env.example  .gitignore  README.md
views/partials/*  views/auth/*  views/errors/error.ejs
public/css/*  public/js/{app,theme}.js  public/favicon.svg
scripts/*  exports/.gitkeep
docs/{CONTRACTS,MEMBER_SCRIPTS,ATTACK_DEMOS,BURP_STEPS,DEMO_SCRIPT,DEMO_SCRIPT_10MIN,REPORT}.md
docs/members/README.md  docs/members/COMMIT_PLAN.md
```

The owner's first commit is the **whole project**, these three scripts included:
everyone clones from it, so it has to be complete and it has to run. After that
first push, the lists above are boundaries rather than task sheets — you change
files in your own row and leave everyone else's alone.

---

## Friday 16 October

### Owner, first — publish the whole project

```bash
# only if the repository does not exist yet: git init -b main
git add -A
git status --short                     # .env and node_modules must not appear
npm test && npm run test:acceptance    # green before you publish it, 26/26

git commit -m "Initial commit: WebSecLab — three vulnerable labs with detection, scoring, logging and forensic evidence"
git remote add origin <REPO-URL>       # skip if origin already exists
git push -u origin main
```

The commit that lands is the complete application, so the moment it is pushed
every collaborator can clone it and run it. Check that before you tell the group:
`git ls-files | wc -l` should print ~100, not 10.

Then invite the other two: repo → **Settings → Collaborators and teams → Add
people → Write**.

### Every member — clone, then change your own area

```bash
git clone <REPO-URL> webseclab && cd webseclab
git config user.name  "Your Name"        # match your GitHub account
git config user.email "your@email.com"   # so the commits are credited to you
npm install && cp .env.example .env      # fill in the 5 values, then:
npm run db:reset && npm run dev
```

Your clone already holds **every file** — all three labs, the detectors, the
views, the docs. Nothing is missing and nothing is per-member: the lists above
tell you which files you may change, not which files you get.

So today you commit what you actually **change**. Four options, all inside your
own files:

1. **Your presenter script** — trim it to your measured pace (the totals are at
   the bottom of your own file).
2. **An extra payload example on your lab page** — useful in the viva, and safe:
   acceptance check 26 asserts *at least* a minimum number of copy targets, not
   an exact count. Give the new `<code>` a fresh unique `id` and pair it with the
   `copyButton` partial exactly as the existing rows do.
3. **A wording or hint fix** your rehearsal exposed.
4. **Your `docs/members/<m>-evidence.md`** — or leave that for tomorrow and keep
   today's commit small.

**M1**

```bash
git switch main && git pull
git switch -c m1/sql-injection
git add docs/members/m1-sqli.md views/labs/sql-lab.ejs   # only what you changed
git status --short                     # every staged path must be yours
git commit -m "Add a UNION payload example to the SQLi lab and trim the presenter script"
git push -u origin m1/sql-injection
```

**M2**

```bash
git switch main && git pull
git switch -c m2/xss-and-hardening
git add docs/members/m2-xss.md views/labs/xss-lab.ejs    # only what you changed
git status --short
git commit -m "Add an svg onload payload example to the XSS lab and tighten the wrap-up wording"
git push -u origin m2/xss-and-hardening
```

**M3**

```bash
git switch main && git pull
git switch -c m3/idor-and-forensics
git add docs/members/m3-idor.md views/labs/idor-lab.ejs  # only what you changed
git status --short
git commit -m "Add an id hint to the IDOR lab and trim the forensics segment"
git push -u origin m3/idor-and-forensics
```

Then open a pull request for your own branch and ask one teammate to review it
rather than merging it yourself.

> The **copy buttons** already work on all three attacks and arrive with the
> owner's first commit. While you are editing your own lab page, check it: every
> payload and every request path should have one, and
> `npm run test:acceptance` check **26** fails if any of them stops resolving.

---

## Saturday 17 October

Today you document your own segment and fix one real thing. Both live in files
only you touch, so there are no conflicts.

**Each member adds:**

1. One new file — `docs/members/m1-evidence.md` (or `m2-`/`m3-`): your payload
   table, the before/after screenshots you will use in the video, and the exact
   `npm test` / `npm run test:acceptance` output.
2. Your presenter script again, if the first full read-through moved the numbers —
   the pace totals are at the bottom of `docs/members/m1-sqli.md`, `m2-xss.md`
   and `m3-idor.md`.
3. One real fix in your own files above — something you found while rehearsing.

```bash
git switch main && git pull
git switch -c <your-branch>-docs
git add docs/members/<your-evidence-file>.md docs/members/<your-script>.md <the files you fixed>
git commit -m "Document the <SQL injection | XSS | IDOR> segment and fix <the one thing>"
git push -u origin <your-branch>-docs
```

**Your own report section** is the exception, because `docs/REPORT.md` is one
file. Branch from the latest `main`, add **only your section**, push immediately,
and let the owner merge in the order **M1 → M2 → M3** so the sections never
interleave.

**For the video, all three need these before Saturday night:**

- [ ] `npm run db:reset` then `npm run dev` — the demo state is reproducible
- [ ] `npm test` green, and a screenshot of `npm run test:acceptance` at **26/26**
- [ ] The mode switch moves, and both modes give the opposite answer for the same request
- [ ] Your segment's payload copied with the copy button, not typed by hand
- [ ] You are within ~10 % of your word target (M1 175 wpm → cut, M2 163 → trim the wrap-up, M3 140 → fine)

**Owner, Saturday afternoon**

```bash
git switch main && git pull
# merge each member's PR after their branch shows a green acceptance run
npm test && npm run test:acceptance      # 26/26 before you merge anything
git push origin main
```

Then post in the group chat: **frozen at 20:00 Saturday.** After that, fixes only
if something is broken — and never on `main` directly.

---

## Sunday — freeze

```bash
npm run db:reset && npm run dev
npm test && npm run test:acceptance      # the 26/26 you show on camera
```

No commits. Record the three segments in order — M1 sets SAFE, M2 sets
VULNERABLE, M3 has to put it back — following [`README.md`](README.md) for the
pre-flight and your own file for the words.
