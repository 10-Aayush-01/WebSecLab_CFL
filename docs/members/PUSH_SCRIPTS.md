# Push scripts — today and tomorrow, one per member

Copy-paste blocks. Replace `<REPO-URL>` once with your repository's clone URL
(the green **Code** button on the repo page).

**How "all files" gets pushed:** the **owner pushes all ~101 files once**, in
step 0. That single commit is the entire project, so every member clones a
complete, working copy. After that each member pushes their **own changes** on
top — because git records a commit only for something that actually changed.

| Who | Today (Friday 16) | Tomorrow (Saturday 17) |
|---|---|---|
| **Owner** | Step 0: push all files, invite the two members | Merge the PRs, tag the freeze |
| **M1** | Clone, run it, trim their script, push `m1/sql-injection` | Evidence + report section, push `m1/docs` |
| **M2** | Clone, run it, trim their script, push `m2/xss-and-hardening` | Evidence + report section, push `m2/docs` |
| **M3** | Clone, run it, trim their script, push `m3/idor-and-forensics` | Evidence + report section, push `m3/docs` |

**Everyone, before every push:** `npm test` must be green.
**Owner, before every merge:** `npm run test:acceptance` must end at **26/26**.

---

## Step 0 — Owner, today, once: push every file

```bash
cd "C:/Users/Aayush/OneDrive/Desktop/WEB_SEC_LAB"    # the folder with package.json
git init -b main
git add -A

git status --short | wc -l                            # 101
git status --short | grep -E "\.env$|node_modules/" && echo "STOP: unstage those" || echo "clean"

git commit -m "Initial commit: WebSecLab — three vulnerable labs with detection, scoring, logging and forensic evidence"
git remote add origin <REPO-URL>
git push -u origin main
```

Verify before telling anyone:

```bash
git status -sb          # ## main...origin/main
git ls-files | wc -l    # 101
```

Then repo → **Settings → Collaborators and teams → Add people → Write** for both
members, and remind them: `.env` is **not** in the repository — they copy
`.env.example` and fill in their own local PostgreSQL passwords.

---

## M1 — today

```bash
# 1. accept the collaborator invitation in your email first, or every push 403s
git clone <REPO-URL> webseclab && cd webseclab

# 2. your own identity, so the commits are credited to you
git config user.name  "M1 Full Name"
git config user.email "m1@example.com"        # the email on your GitHub account

# 3. get it running
npm install
cp .env.example .env                          # fill in the 5 values
npm run db:reset
npm run dev                                   # http://localhost:3000, "Use" button → ADMIN
npm test                                      # must be green before you change anything

# 4. make your change: trim docs/members/m1-sqli.md to your measured pace
#    (targets are at the bottom of that file: cut beat D and the "real query" line in beat B)

# 5. push it
git switch main && git pull
git switch -c m1/sql-injection
git add docs/members/m1-sqli.md views/labs/sql-lab.ejs
#   the lab page only if you added the UNION example row — an unchanged path just stages nothing
git status --short                            # every staged path must be yours
git commit -m "Trim the SQLi presenter script to 150 wpm"
git push -u origin m1/sql-injection
```

The push prints a link — open it, click **Create pull request**, and tag a
teammate as reviewer. Do not merge it yourself.

**Optional, if you want a code commit as well:** add a fourth payload example to
your own lab page — a fresh unique `id` on the `<code>` plus the `copyButton`
partial, exactly like the existing rows. Acceptance check 26 asserts *at least* a
minimum number of copy targets, so one more is safe.

## M1 — tomorrow

```bash
git switch main && git pull
git switch -c m1/docs

# add docs/members/m1-evidence.md: your payload table, the before/after
# screenshots you will use in the video, and the exact output of
#   npm test
#   npm run test:acceptance     (must end 26/26)
# then your report section in docs/REPORT.md — your section only

git add docs/members/m1-evidence.md docs/members/m1-sqli.md docs/REPORT.md
git status --short
git commit -m "Document the SQL injection segment: evidence, screenshots and report section"
git push -u origin m1/docs
```

## M2 — today

```bash
git clone <REPO-URL> webseclab && cd webseclab
git config user.name  "M2 Full Name"
git config user.email "m2@example.com"

npm install
cp .env.example .env
npm run db:reset
npm run dev
npm test

# your change: trim docs/members/m2-xss.md — the hardening wrap-up is the long
# block; drop the rate-limiting clause and shorten the sanitizer clause

git switch main && git pull
git switch -c m2/xss-and-hardening
git add docs/members/m2-xss.md views/labs/xss-lab.ejs
#   the lab page only if you added the svg example — an unchanged path just stages nothing
git status --short
git commit -m "Trim the XSS segment and the hardening wrap-up to 150 wpm"
git push -u origin m2/xss-and-hardening
```

**Optional code commit:** an extra XSS payload example on `views/labs/xss-lab.ejs`
(for example an `svg onload` row) with its own unique id and a copy button.

## M2 — tomorrow

```bash
git switch main && git pull
git switch -c m2/docs

# docs/members/m2-evidence.md + your report section: the CSP override, the
# httpOnly cookie check, and the numbers from npm test / npm run test:acceptance

git add docs/members/m2-evidence.md docs/members/m2-xss.md docs/REPORT.md
git status --short
git commit -m "Document the XSS segment and the hardening summary with evidence"
git push -u origin m2/docs
```

## M3 — today

```bash
git clone <REPO-URL> webseclab && cd webseclab
git config user.name  "M3 Full Name"
git config user.email "m3@example.com"

npm install
cp .env.example .env
npm run db:reset
npm run dev
npm test

# your change: trim docs/members/m3-idor.md — you are at 140 wpm with room to
# spare, so trim nothing structural; tighten the forensics block instead

git switch main && git pull
git switch -c m3/idor-and-forensics
git add docs/members/m3-idor.md views/labs/idor-lab.ejs
#   the lab page only if you added the id hint — an unchanged path just stages nothing
git status --short
git commit -m "Tighten the forensics segment in the IDOR script"
git push -u origin m3/idor-and-forensics
```

**Optional code commit:** a hint line on your own `views/labs/idor-lab.ejs` naming
the id range Alice owns, so the demo never lands on the wrong document.

## M3 — tomorrow

```bash
git switch main && git pull
git switch -c m3/docs

# docs/members/m3-evidence.md + your report section: the 200 → 403 pair, the
# export hash and the verify pass/fail, with the exact test output

git add docs/members/m3-evidence.md docs/members/m3-idor.md docs/REPORT.md
git status --short
git commit -m "Document the IDOR and forensics segments with evidence and screenshots"
git push -u origin m3/docs
```

---

## Owner — tomorrow: merge train

```bash
git switch main && git pull

# for each member PR, in the order M1 → M2 → M3 (docs/REPORT.md is one file,
# so merge it sequentially and never in parallel):
#   1. open the PR, 2. check the branch shows a green npm run test:acceptance
#   3. Merge pull request

npm test && npm run test:acceptance      # 26/26 before you close the day
git push origin main
```

Post the freeze in the group chat: **frozen at 20:00 Saturday**. After that,
fixes only if something is broken, never directly on `main`.

---

## If a push fails

| Message | Cause | Fix |
|---|---|---|
| `403` / `Permission denied` | invitation not accepted, or added as **Read** | accept it; owner sets role **Write** |
| `remote origin already exists` | stale remote | `git remote set-url origin <REPO-URL>` |
| `src refspec main does not match any` | nothing committed, or branch is `master` | commit first, or `git branch -M main` |
| `Updates were rejected ... fetch first` | you branched from a stale `main` | `git switch main && git pull`, then re-branch |
| `nothing to commit` | you changed nothing | make a real change in your own file |
| `Support for password authentication was removed` | no token | personal access token, `repo` scope, used as the password |
| `CONFLICT` in a shared file | two people edited it | edit the `<<<<<<<` markers, `git add <file>`, `git rebase --continue`, push |
