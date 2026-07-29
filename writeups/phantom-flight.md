# Phantom Flight — CTF Write-up

**Challenge:** Operation Ghostlink — Decode seized Kestrel Dawn PX4 firmware, recover keying material, decrypt telemetry log, extract mission token.

**Flag:** `HTB{R0MFS_3mb3dd3d_K3ys_Gh0stl1nk_D3crypt3d}`

**Category:** Forensics  
**Event:** ADF 2026 Hackathon

---

## How We Solved It — Reasoning

### Step 1: Decode the .px4 package

The `.px4` file is a JSON wrapper. The `image` field is base64-encoded, zlib-compressed ARM Cortex-M7 firmware (STM32H7, board ID 56, PX4 FMUv6C).

```python
import json, base64, zlib
with open('firmware.px4') as f:
    px4 = json.load(f)
img = zlib.decompress(base64.b64decode(px4['image']))
# → 1,938,540 bytes
```

### Step 2: Extract the CROMFS/LZF filesystem

The firmware embeds a PX4 compressed ROM filesystem (CROMFS) at the end of the binary. Files are stored in LZF-compressed blocks with 7-byte ZV headers. The ROMFS entry marker is `24 81 00 00` for extras/secure files.

Two key entries were recovered:

| Entry | LZF Output | Content |
|-------|-----------|---------|
| `secure_bootstrap.cfg` | 169 bytes | Bootstrap config with transport key |
| `flight_capture.bin` | 403 bytes | PFLG encrypted bundle |

**Key insight:** LZF is Marc Lehmann's liblzf. Control bytes `< 0x20` are literal-run lengths, `>= 0x20` are LZ77 back-references. `flight_capture.bin` contains exactly 13 pure literal-run tokens with zero back-references — the decompression is a trivial byte-stripping operation.

### Step 3: Recover the transport key

`secure_bootstrap.cfg` (LZF decompressed, verbatim):

```ini
capture_slot=7
crypto_profile=aes256-gcm+gzip
transport_key_b64=Z770pY/oa3qWpHLHdNCgaR1EwIjvqKwr6NoTWZnnYOc=
bundle=flight_capture.bin
note=log replay channel bootstrap
```

**Transport key:** `67bef4a58fe86b7a96a472c774d0a0691d44c088efa8ac2be8da135999e760e7` (32 bytes, verified via base64 encode/decode round-trip)

### Step 4: Parse the PFLG container

The PFLG structure (24-byte header):

```
Offset  Size  Field
0       4     Magic "PFLG" (0x50464c47)
4       1     Version (0x01)
5       1     Algorithm (0x01 = AES-256-GCM/CTR)
6       1     Nonce length (0x0c = 12)
7       4     Reserved (0x00000001)
11      1     Separator (0x7b)
12      12    Nonce: 50461511a29f585352b36183
24      N-16  Ciphertext (AES-256-CTR)
N-16    16    GCM authentication tag
```

### Step 5: Decrypt and decompress

**Critical finding:** Despite the `crypto_profile` saying "gcm", the actual encryption is **AES-256-CTR** with the GCM counter mode. The counter block is `nonce || 0x00000002` (the standard GCM first-counter construction). The final 16 bytes are the GCM authentication tag (excluded from the ciphertext before decryption).

The plaintext is gzip-compressed. After decryption, decompress with gzip to reveal JSON telemetry events.

```python
from Cryptodome.Cipher import AES
import gzip

key = bytes.fromhex('67bef4a58fe86b7a96a472c774d0a0691d44c088efa8ac2be8da135999e760e7')
nonce = pf[12:24]  # 12 bytes at offset 12
ct = pf[24:-16]    # everything between header and last 16 bytes (tag)

counter = nonce + b'\x00\x00\x00\x02'
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=counter)
plaintext = cipher.decrypt(ct)
telemetry = gzip.decompress(plaintext)
```

### Step 6: Extract the mission token

The decrypted telemetry is a JSON-lines flight log:

```json
{"ts":"2026-05-18T04:15:02Z","level":"INFO","event":"power_on","lat":35.6898,"lon":51.389,"alt_m":13.2}
{"ts":"2026-05-18T04:15:11Z","level":"INFO","event":"gps_lock","satellites":17,"hdop":0.74}
{"ts":"2026-05-18T04:15:19Z","level":"INFO","event":"arm","mode":"AUTO_MISSION"}
{"ts":"2026-05-18T04:15:44Z","level":"INFO","event":"waypoint","seq":1,"lat":35.6942,"lon":51.4014,"groundspeed_mps":18.5}
{"ts":"2026-05-18T04:16:08Z","level":"WARN","event":"telemetry_drop","packet_loss_pct":14.2}
{"ts":"2026-05-18T04:16:16Z","level":"INFO","event":"failsafe_clear"}
{"ts":"2026-05-18T04:16:39Z","level":"INFO","event":"payload_link","relay":"KD-AJAX-4"}
{"ts":"2026-05-18T04:17:03Z","level":"INFO","event":"operator_note","note":"HTB{R0MFS_3mb3dd3d_K3ys_Gh0stl1nk_D3crypt3d}"}
```

### Flag

```
HTB{R0MFS_3mb3dd3d_K3ys_Gh0stl1nk_D3crypt3d}
```

---

## Key Insights

1. **Off-by-one in PFLG header:** The nonce starts at byte 12, not byte 11. The byte at offset 11 (`0x7b`) is a separator between the reserved field and the nonce. Ciphertext starts at byte 24, not byte 23. This 1-byte shift was fatal to all prior decryption attempts.

2. **CTR, not GCM:** Despite `crypto_profile=aes256-gcm+gzip`, the encryption mode is AES-256-CTR using the standard GCM counter block (`nonce || 0x00000002`). The GCM authentication tag is appended but not needed for decryption — it's there for integrity verification only.

3. **LZF is simple:** The `flight_capture.bin` LZF stream contains zero back-references (all literal runs), making decompression a trivial byte-stripping operation.

4. **No firmware code needed:** The encryption was performed externally at challenge-build time. No decrypt function exists in the ARM binary. All parameters are in the extracted artifacts.
