# Presenter scripts — one file per member

Print **your own file only**. Each one is self-contained: your setup, your mode,
your beats, your closing line, your failure fixes, the shared close at the end,
and your own word count and pace.

| Member | File | Owns | Airtime |
|---|---|---|---|
| **M1** | [`m1-sqli.md`](m1-sqli.md) | The problem, the architecture, **SQL injection** | 0:00–3:15 |
| **M2** | [`m2-xss.md`](m2-xss.md) | **Cross-site scripting**, and the hardening wrap-up | 3:15–5:10, 8:35–9:20 |
| **M3** | [`m3-idor.md`](m3-idor.md) | **IDOR**, and the forensics segment | 5:10–8:35 |

Your **commit plan for Friday 16 and Saturday 17 October** — who commits what,
and by when — is [`COMMIT_PLAN.md`](COMMIT_PLAN.md), and the copy-paste commands
for it are [`PUSH_SCRIPTS.md`](PUSH_SCRIPTS.md).

Each member's **evidence file** for Saturday: [`m1-evidence.md`](m1-evidence.md),
[`m2-evidence.md`](m2-evidence.md), [`m3-evidence.md`](m3-evidence.md).

The combined master is [`MEMBER_SCRIPTS.md`](../MEMBER_SCRIPTS.md) — the three
files here are that same text split per person, so there is nothing extra to
reconcile. Click-level detail for every screen is in
[`ATTACK_DEMOS.md`](../ATTACK_DEMOS.md); the Burp procedure is in
[`BURP_STEPS.md`](../BURP_STEPS.md).

## Before anyone records

```bash
npm run db:reset        # clean dashboard, re-seeds passwords and demo data
npm run dev
```

Then:

1. Sign in with the **Use** button on the login page — never type a password on
   camera.
2. **M1** opens on **SAFE**. **M2** sets **VULNERABLE**. **M3** needs two
   browsers (Chrome as ADMIN, Firefox as Alice) and sets **VULNERABLE** again,
   because M2 leaves the switch on SAFE.
3. One window, browser at 100 %, no bookmarks bar, no other tabs visible.
4. Confirm the app is reachable on <http://localhost:3000> before you start
   recording — not after.

**The mode is set at the start of each member's own segment**, because it persists
across the whole app.

## Rehearsal checklist

- [ ] Each member sets the **mode** at the start of their own segment
- [ ] Every attack segment contains the **identical request in both modes**
- [ ] Every attack segment names a **mitigation** and one **honest limitation**
- [ ] The mode is explained **once** (M1 architecture) and summarised **once**
      (M2 hardening) — never three times
- [ ] Every member speaks for their own segment and their own closing line
- [ ] Total under 10:00, and each member is within ~10 % of their word target
