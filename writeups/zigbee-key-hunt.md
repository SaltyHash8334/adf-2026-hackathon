# ZigBee Key Hunt — Forensics Write-Up

**CTF:** Salty Hash443 / ADF2026 Hackathon  
**Category:** Forensics  
**Challenge:** ZigBee Key Hunt  
**Flag:** `HTB{Z1gB33_N3tw0rk_K3y_3xtr4ct3d}`

---

## Scenario

Coalition EW captured a short IEEE 802.15.4 / ZigBee packet trace from a temporary perimeter sensor mesh near a forward site. During the recording, a new end device joined the PAN, received Trust Center provisioning material, and then sent its first encrypted application report.

The task was to analyse `capture.pcap`, recover the relevant keying material from the join sequence, decrypt the protected ZigBee traffic, and extract the flag.

---

## Evidence Sources

| Artifact | Description |
|---|---|
| `capture.pcap` | 32-frame IEEE 802.15.4 capture with FCS |
| Frame 13 | Association Request from EUI-64 `00:00:00:00:00:00:00:15` |
| Frame 15 | Successful Association Response; short address `0x0015` |
| Frame 17 | ZigBee APS Transport Key command |
| Frame 23 | First long encrypted report from the newly joined device |

Initial triage confirmed IEEE 802.15.4/ZigBee traffic:

```text
capture.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4
(802.15.4 with FCS, capture length 65535)
```

The capture contains beacons, association traffic, one Transport Key command, and encrypted ZigBee NWK data frames.

---

## Analysis

### PAN and Join Sequence

The beacons advertise PAN ID `0xab12` and Extended PAN ID `00:00:00:00:00:00:01:18`. The join sequence is:

| Frame | Event | Relevant result |
|---:|---|---|
| 13 | Association Request | Device EUI-64 ends in `0x15` |
| 15 | Association Response | Association successful; assigned short address `0x0015` |
| 17 | APS Transport Key | Network key material delivered to `0x0015` |
| 23 | First encrypted report | 49-byte encrypted NWK payload from `0x0015` |

Frame 17 is the key discovery point. Wireshark dissects the APS command as:

```text
Command Frame: Transport Key
Command Identifier: Transport Key (0x05)
Key Type: Standard Network Key (0x01)
Key: 328da53757f3e5cf09fe8326942326de
Sequence Number: 0
Extended Destination: 00:00:00:00:00:00:00:15
Extended Source: 00:00:00:00:00:00:00:01
```

### Protected Frame Structure

The encrypted NWK frames use Security Control `0x2d`:

- Security level: `0x05` — AES-128 encryption with 32-bit MIC
- Key identifier: Network Key
- Extended nonce: present
- Frame counter: starts at `1` for each device

For frame 23, the relevant fields are:

```text
NWK header:       0812000015000a071500000000000000
Security header:  2d01000000150000000000000000
Ciphertext:       cb79821ab489734bc60b533b53b7a913041efdc992d156161ecea28c1f905920b63b6ca0348b4f689b51f16fc781e72f98
MIC:              f6572b06
```

---

## Solution

### Step 1 — Enumerate the Capture

```bash
tshark -r capture.pcap
```

The packet list shows the join sequence and identifies frame 23 as the first large encrypted report from the new device:

```text
13  Association Request
15  Association Response, PAN: 0xab12 Addr: 0x0015
17  ZigBee Transport Key
23  0x0015 → 0x0000  ZigBee 94 Data
```

### Step 2 — Extract the Transport Key

```bash
tshark -r capture.pcap -V -Y "frame.number==17"
```

The extracted Transport Key value is:

```text
328da53757f3e5cf09fe8326942326de
```

The challenge's packet construction uses this value as an encrypted key block. Decrypting it with the standard Trust Center Link Key (`ZigBeeAlliance09`) gives the actual NWK key:

```text
Trust Center Link Key: 5a6967426565416c6c69616e63653039
Network Key:          99df0108b1c4d6ad38cdc2fc078661a2
```

The derivation is reproducible with:

```python
from Cryptodome.Cipher import AES

trust_center_link_key = bytes.fromhex("5a6967426565416c6c69616e63653039")
transport_key = bytes.fromhex("328da53757f3e5cf09fe8326942326de")
network_key = AES.new(trust_center_link_key, AES.MODE_ECB).decrypt(transport_key)
print(network_key.hex())
```

Output:

```text
99df0108b1c4d6ad38cdc2fc078661a2
```

### Step 3 — Build the ZigBee CCM* Nonce

For each protected frame, the nonce is:

```text
Extended Source (8 bytes, little-endian)
|| Frame Counter (4 bytes, little-endian)
|| FULL Security Control byte (1 byte)
```

A critical challenge-specific detail is that the final nonce byte is the complete Security Control value `0x2d`, not merely the security-level bits `0x05`.

For frame 23:

```text
Extended Source: 1500000000000000
Frame Counter:   01000000
Security Ctrl:   2d
Nonce:           1500000000000000010000002d
```

### Step 4 — Decrypt the Protected Payloads

The following solver performs the payload decryption for all 11 protected frames and extracts printable strings. The ciphertext portion reproduces consistently across every protected frame. Standard CCM* MIC verification does not succeed with the capture's AAD/authentication construction, so the solver explicitly treats this as payload decryption rather than claiming standard CCM* authentication verification.

```python
#!/usr/bin/env python3
from Cryptodome.Cipher import AES
import struct
from scapy.all import rdpcap

TC_LINK_KEY = bytes.fromhex("5a6967426565416c6c69616e63653039")
TRANSPORT_KEY = bytes.fromhex("328da53757f3e5cf09fe8326942326de")
NETWORK_KEY = AES.new(TC_LINK_KEY, AES.MODE_ECB).decrypt(TRANSPORT_KEY)


def aes_ctr_decrypt(key, nonce13, ciphertext):
    plaintext = bytearray()
    for i in range((len(ciphertext) + 15) // 16):
        counter = b"\\x01" + nonce13 + struct.pack(">H", i + 1)
        stream = AES.new(key, AES.MODE_ECB).encrypt(counter)
        chunk = ciphertext[i * 16:(i + 1) * 16]
        plaintext.extend(a ^ b for a, b in zip(chunk, stream[:len(chunk)]))
    return bytes(plaintext)

pkts = rdpcap("capture.pcap")
for frame_no, pkt in enumerate(pkts, 1):
    raw = bytes(pkt)
    for off in range(15, min(40, len(raw) - 15)):
        if raw[off] != 0x2d:
            continue

        security_control = raw[off]
        frame_counter = raw[off + 1:off + 5]
        extended_source = raw[off + 5:off + 13]
        encrypted = raw[off + 14:-6]
        nonce = extended_source + frame_counter + bytes([security_control])
        plaintext = aes_ctr_decrypt(NETWORK_KEY, nonce, encrypted)

        print(frame_no, plaintext.hex())
        print("".join(chr(b) if 32 <= b < 127 else "." for b in plaintext))
        break
```

The full working solver is included as `solve.py` alongside the capture.

### Step 5 — Decrypted Report

Frame 23 decrypts to:

```text
400101000004010718010105000042214854427b5a31674233335f4e33747730726b5f4b33795f3378747234637433647d
```

The printable representation is:

```text
@.............B!HTB{Z1gB33_N3tw0rk_K3y_3xtr4ct3d}
```

The flag is embedded in the application report:

```text
HTB{Z1gB33_N3tw0rk_K3y_3xtr4ct3d}
```

---

## How We Solved It — Reasoning

The first useful hypothesis was that the join sequence would expose a network key. The association frames alone do not contain enough material to decrypt later traffic, so I followed the newly assigned address `0x0015` and inspected the next coordinator-to-device packet. Frame 17 was an APS Transport Key command, making it the natural key-recovery point.

A second hypothesis was that the displayed Transport Key value could be used directly as the NWK key. Direct CCM* attempts failed. The important correction was to treat the displayed 16-byte value as an encrypted key block and decrypt it with the well-known Trust Center Link Key. This produced `99df0108b1c4d6ad38cdc2fc078661a2`, which generated valid plaintext for every protected frame.

A third dead end was using only the low three security-level bits (`0x05`) as the last nonce byte, following the simplified CCM* description. That produced incorrect output. The capture's implementation uses the full Security Control byte (`0x2d`) in the counter nonce. With the derived network key and full control byte, the ciphertext decrypts consistently across all 11 protected frames. Standard CCM* MIC verification still fails, indicating that the capture's authentication/AAD construction is customized or inconsistent with the standard profile.

The repeated short reports from devices `0x0011` through `0x0014` serve as a useful cross-check: they all decrypt into similarly structured 16-byte application messages. The long frame from newly joined device `0x0015` is the only payload large enough to contain the flag, and its plaintext contains the expected `HTB{...}` marker.

The key insights were therefore:

1. Follow the association and Transport Key sequence rather than brute-forcing encrypted payloads.
2. Decrypt the Transport Key with the Trust Center Link Key before using it.
3. Use the full Security Control byte `0x2d` in this capture's nonce construction.
4. Validate the result across all protected frames, not just the flag-bearing packet.

---

## Key Takeaways

- ZigBee join traffic can expose enough provisioning material to recover a network key.
- A Transport Key field may itself be wrapped with the Trust Center Link Key.
- IEEE 802.15.4/ZigBee captures must be parsed with exact byte offsets; the FCS and MIC are separate from the encrypted payload.
- Decryption should be validated across multiple frames and with the expected flag prefix, rather than trusting one plausible plaintext.

---

## Reproduction

From this directory:

```bash
/tmp/ais_env/bin/python solve.py
```

Verified result:

```text
Total frames decrypted: 11
Flag: HTB{Z1gB33_N3tw0rk_K3y_3xtr4ct3d}
```

---

## Caveats

The challenge capture uses a simplified/customized key-wrapping and nonce convention. The solver above documents the convention required to reproduce this capture's plaintext; it should not be assumed to be a drop-in implementation for every ZigBee stack or production capture.

---

## Files

- `capture.pcap` — supplied packet capture
- `solve.py` — verified decryption and extraction script
- `writeup.md` — this write-up

---

## Security Implications

A passive observer who captures an unsecured or improperly protected join sequence may recover the network key and decrypt subsequent sensor reports. Trust Center Link Keys, Transport Key delivery, and network-key rotation should be configured and protected according to the ZigBee security profile. Captures containing key material should be treated as sensitive.

---

**Flag:** `HTB{Z1gB33_N3tw0rk_K3y_3xtr4ct3d}`
