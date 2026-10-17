# Burp Suite procedure

For the report and the video. Use **only your own local WebSecLab instance.**

## Setup

1. Burp Proxy listener on `127.0.0.1:8080`, intercept **on to begin with**, then
   off — an intercept queue makes the app look frozen mid-demo.
2. Use **Burp's built-in browser**, or browse `http://127.0.0.1:3000` rather than
   `http://localhost:3000`. Browsers bypass the proxy for loopback, so
   `localhost` traffic may never reach Burp. In Firefox:
   `network.proxy.allow_hijacking_localhost = true`.
3. Sign in as an ADMIN and switch the global mode to **VULNERABLE** first.

## Step matrix

| Step | SQL Injection<br>`GET /labs/sql?q=` | XSS<br>`POST /labs/xss/comments` | IDOR<br>`GET /labs/idor/documents/:id` |
|---|---|---|---|
| 1 | Burp proxy on `127.0.0.1:8080`, intercept on, Burp's browser | same | same |
| 2 | Sign in as a USER; an admin has already set the mode to VULNERABLE | same | sign in as **Alice** |
| 3 | Search a normal term; send the request to **Repeater** | Post a normal comment; send to Repeater | Open **your own** document; send to Repeater |
| 4 | Edit `q` to `' OR 1=1--`; send | Edit `comment` to `<script>alert(document.domain)</script>`; send | Change the id in the path to a document owned by **Bob**; send |
| 5 | Expect **200** with the three unreleased products and the executed SQL string | Expect **302**, the payload stored, and script executing on the next page load | Expect **200** with Bob's title and content |
| 6 | Admin → Security Events: new event, `SUCCESSFUL` | same | same |
| 7 | Switch to **SAFE**; **resend the same request** | same | same |
| 8 | Expect 0 rows → `NEUTRALIZED` (or **400** if the term is over 50 characters or contains control characters) | Expect the same text rendered inert → `NEUTRALIZED` | Expect **403** "You do not own this document" → `BLOCKED` |
| 9 | Second event, lower score (100 → 85) | Second event (90 → 75) | Second event (95 → 80) |

## Copy-paste payloads

| Purpose | Payload |
|---|---|
| SQLi — tautology (hidden data) | `' OR 1=1--` |
| SQLi — quoted tautology | `' OR '1'='1` |
| SQLi — union (refused by the `lab_reader` role) | `' UNION SELECT 1,email,password_hash,'1','x' FROM users--` |
| SQLi — stacked query | `x'; DROP TABLE products;--` |
| SQLi — validation failure (SAFE only, >50 chars) | `' OR 1=1--` followed by 60 `A` characters |
| XSS — script tag | `<script>alert(document.domain)</script>` |
| XSS — event handler | `<img src=x onerror=alert(document.domain)>` |
| XSS — javascript: URI | `<a href="javascript:alert(document.domain)">click</a>` |
| IDOR | change the integer id in `/labs/idor/documents/<id>` |

## Notes worth having ready for questions

- **Why `GET /labs/sql`?** So the payload is a URL parameter that is trivial to
  edit and replay, which is exactly the workflow Burp is used for.
- **Why does the UNION payload not leak password hashes?** The vulnerable query
  runs on the `lab_reader` role, which holds `SELECT` on `products` only. The
  database returns `permission denied for table users`, the request is logged as
  `BLOCKED`, and the page says so. Confirming this is acceptance check 8.
- **Why is `/labs/*` not rate limited?** Repeater and Intruder loops would trip a
  limiter and make the labs look broken. The limiter is on `/login` and
  `/register`, where it belongs.
- **Why does the XSS demo stop working in SAFE mode?** Two independent reasons,
  which is the point: the view escapes the comment, and the route falls back to
  the strict CSP (`script-src 'self'`).
- **Where is the payload in the event log?** In `request_data.payload`, truncated
  to 500 characters and redacted. Show it on the investigation page.
