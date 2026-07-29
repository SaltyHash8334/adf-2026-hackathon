# Truncated Requests — ADF 2026 Hackathon Writeup

**Challenge:** Web  
**Difficulty:** Easy  
**Flag:** `HTB{trunc4t3d_4nd_byp4553d!_cc131865937a66b9c14d6ccf09364fcb}`

---

## How We Solved It — Reasoning

### Initial Reconnaissance

The challenge provided source code for a Node.js/Express purchase request portal backed by MySQL (MariaDB). Three observations stood out immediately:

1. **`varchar(34)` columns** — Both `username` and `password` columns in the `users` table are `varchar(34)` — an unusually specific width.
2. **Non-strict SQL mode** — `sql_mode=NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER` — critically, `STRICT_TRANS_TABLES` is **absent**, meaning MySQL silently truncates over-long inserts instead of rejecting them.
3. **Random admin password** — `ADMINPASS=$(echo $RANDOM | md5sum | head -c 32)` — a 32-char hex string, unguessable.

The challenge name "Truncated Requests" combined with `varchar(34)` + non-strict mode immediately pointed to the classic **MySQL Truncation Attack**.

### The Vulnerability

MySQL's default collation uses **PAD SPACE** semantics — trailing spaces are ignored in string comparisons. This means `'admin' = 'admin                           '` evaluates to **TRUE** in a `WHERE` clause.

Combined with non-strict mode truncation, the attack chain is:

1. Register a username longer than 34 characters starting with `"admin"` + trailing spaces — e.g. `"admin" + 29 spaces + "x"` (35 chars total).
2. MySQL **silently truncates** to 34 chars: `"admin" + 29 spaces` stored in the database.
3. The `getUser()` duplicate check uses the **full** 35-char string → no match found → registration succeeds.
4. Login as `"admin"` (5 chars) with the attacker's password — MySQL PAD SPACE comparison matches the truncated row → JWT issued.
5. On the dashboard, `getUser()` with the JWT's spaced username returns **both** the real admin (id=1) and the duplicate row. `user[0]` is the real admin → `user[0].username == 'admin'` passes → unapproved products (including the flag) are revealed.

### Exploitation

```python
import requests

TARGET = "http://154.57.164.64:31850"

# Register with 'admin' + 29 spaces + 'x' (35 chars -> truncates to 34)
attack_username = "admin" + " " * 29 + "x"
attack_password = "hijacked123"

requests.post(f"{TARGET}/api/register", json={
    "username": attack_username,
    "password": attack_password
})

# Login as 'admin' — PAD SPACE matches the truncated row
resp = requests.post(f"{TARGET}/api/login", json={
    "username": "admin",
    "password": attack_password
})
session = resp.cookies["session"]

# Dashboard now shows unapproved products with the flag
resp = requests.get(f"{TARGET}/dashboard", cookies={"session": session})
# Flag: HTB{trunc4t3d_4nd_byp4553d!_cc131865937a66b9c14d6ccf09364fcb}
```

### Why It Works — Deep Dive

**MySQL PAD SPACE collation:** When comparing two strings, MySQL pads the shorter one with spaces to match the longer one's length, then compares character by character. So `WHERE username = 'admin'` matches a row containing `'admin                           '` (admin + 29 spaces).

**Non-strict mode (no `STRICT_TRANS_TABLES`):** An INSERT of a 35-character value into a `VARCHAR(34)` column produces a **warning** (not an error), and the value is truncated to 34 characters.

**Why the duplicate check fails but login succeeds:**

- `getUser('admin                           x')` — 35 chars: MySQL pads the real admin ('admin', 5 chars) to 35 chars → `'admin                           '` (30 spaces). Compared to `'admin                           x'` → position 35: space vs 'x' → **no match** → registration proceeds.
- `loginUser('admin', 'ourpass')` — 5 chars: MySQL pads 'admin' to 34 chars → matches the truncated row → password check passes → login succeeds.

**Why the dashboard admin check passes:**

The JWT contains `username: 'admin                           '` (34 chars). When `getUser()` queries with this, PAD SPACE matches BOTH rows. The real admin (id=1, inserted first) appears as `user[0]`, so `user[0].username == 'admin'` is true in JavaScript.

### Key Takeaways

- Always use `STRICT_TRANS_TABLES` (or `STRICT_ALL_TABLES`) in MySQL `sql_mode` for applications
- Never rely on column width as a security boundary — enforce length validation in application code
- PAD SPACE collation can cause unexpected behavior when combined with truncation
- The `VARCHAR(34)` column width was the intended clue — the random admin password is 32 chars, leaving exactly 2 chars of headroom to hint at the truncation path
