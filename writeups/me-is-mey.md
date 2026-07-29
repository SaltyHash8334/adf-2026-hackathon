# Me is Mey — Crypto

**CTF:** ADF 2026 Hackathon  
**Category:** Crypto  
**Challenge:** Me is Mey  
**Flag:** `HTB{sh4256_bu7_w17h_4_7w157_83f023_c4n_c4u5e_c011i51on5}`

---

## Scenario

For the concluding challenge, the creator's final statement echoes: "Only the one who is me can be me." These words refer to the creator's personal signature — a custom hash function. The key to unlocking the final challenge lies in finding a collision: a different message that produces the same hash as `ready_play_one!`.

---

## Analysis

The server implements a custom `hash` class:

```python
from hashlib import sha256

class hash():
    def __init__(self, message):
        self.message = message

    def rotate(self, message):
        return [((b >> 4) | (b << 3)) & 0xff for b in message]

    def hexdigest(self):
        rotated = self.rotate(self.message)
        return sha256(bytes(rotated)).hexdigest()

def main():
    original_message = b"ready_play_one!"
    original_digest = hash(original_message).hexdigest()

    message = bytes.fromhex(input("Enter your message: "))
    digest = hash(message).hexdigest()

    if ((original_digest == digest) and (message != original_message)):
        print(f"{FLAG}")
```

The hash function applies a per-byte **rotate** transformation before passing the result to standard SHA-256. We need:
1. A message `M ≠ M₀ = b"ready_play_one!"`
2. Such that `SHA256(rotate(M)) == SHA256(rotate(M₀))`

### The Rotate Function: Bit-Level Analysis

For an 8-bit input byte with bits `[b₇ b₆ b₅ b₄ b₃ b₂ b₁ b₀]`:

```
(b >> 4)  →  [0  0  0  0  b₇ b₆ b₅ b₄]     (bits 7-4 move to positions 3-0)
(b << 3)  →  [b₄ b₃ b₂ b₁ b₀ 0  0  0 ]     (bits 4-0 move to positions 7-3)
           & 0xff                         (mask to 8 bits)

OR result →  [b₄ b₃ b₂ b₁ b₀ b₇ b₆ b₅]
```

**Critical observation**: Bit `b₄` from `(b << 3)` lands at position 7, while bit `b₄` from `(b >> 4)` lands at position 0. However, bits `b₅`, `b₆`, `b₇` from `(b << 3)` are shifted out of the 8-bit range and **lost**. Only 5 bits from `(b << 3)` survive; 4 bits from `(b >> 4)` survive. With the overlap at bit `b₄`, this means only 7 independent bits of information produce the output — not 8.

| Input Range | Output Property | Count |
|-------------|----------------|-------|
| b₅ = b₇ (output parity fixed) | 1 input byte → 1 rotated value | 64 values |
| b₅ ≠ b₇ | 3 input bytes → 1 rotated value | 64 values |

**Result**: The rotate function maps 256 input bytes onto only **128 distinct output values**, making it a **non-injective** function. This information loss is the vulnerability.

---

## How We Solved It — Reasoning

### Initial Hypothesis (rejected)
My first thought was that `((b >> 4) | (b << 3)) & 0xff` was a simple bit permutation (bijection). If all 8 bits survived, the function would be invertible, and finding a collision would require breaking SHA-256 — computationally infeasible. I wrote the inverse and was puzzled when it failed on some test cases.

### The Breakthrough
When I enumerated all 256 input-output pairs, I discovered the output set was only 128 distinct values. This immediately reframed the problem: we don't need a SHA-256 collision — we need a **rotate preimage collision**. If we find a message M ≠ M₀ where `rotate(M) == rotate(M₀)`, then `SHA256(rotate(M)) == SHA256(rotate(M₀))` trivially by the determinism of SHA-256.

### Collision Construction
For each byte in the original message `ready_play_one!`, I checked whether its rotated value had multiple preimages. 10 out of 15 bytes were in triplet output sets, each with 2 alternative partner bytes. The partner bytes differ by their upper bit patterns (`b₅`, `b₆`, `b₇`) which are lost during rotation.

| Pos | Orig | Rotated | Partners |
|-----|------|---------|----------|
| 0 | `r` (0x72) | 0x97 | singleton — no alt |
| 1 | `e` (0x65) | 0x2e | 0xe4, 0xe5 |
| 2 | `a` (0x61) | 0x0e | 0xe0, 0xe1 |
| 3 | `d` (0x64) | 0x26 | singleton |
| 4 | `y` (0x79) | 0xcf | 0xf8, 0xf9 |
| 5 | `_` (0x5f) | 0xfd | 0xde, 0xdf |
| 6 | `p` (0x70) | 0x87 | singleton |
| 7 | `l` (0x6c) | 0x66 | singleton |
| 8 | `a` (0x61) | 0x0e | 0xe0, 0xe1 |
| 9 | `y` (0x79) | 0xcf | 0xf8, 0xf9 |
| 10 | `_` (0x5f) | 0xfd | 0xde, 0xdf |
| 11 | `o` (0x6f) | 0x7e | 0xee, 0xef |
| 12 | `n` (0x6e) | 0x76 | singleton |
| 13 | `e` (0x65) | 0x2e | 0xe4, 0xe5 |
| 14 | `!` (0x21) | 0x0a | 0xa0, 0xa1 |

**10 swappable positions × 2 choices each = 2¹⁰ = 1024 valid collision messages.**

---

## Exploitation

```python
from hashlib import sha256

def rotate_byte(b):
    return ((b >> 4) | (b << 3)) & 0xff

# Build collision map
collision_map = {}
for b in range(256):
    r = rotate_byte(b)
    collision_map.setdefault(r, []).append(b)

orig = b"ready_play_one!"
collision = bytearray()

for b in orig:
    partners = collision_map[rotate_byte(b)]
    other = [x for x in partners if x != b]
    collision.append(other[0] if other else b)  # swap if possible

print(collision.hex())  # 72e4e064f8de706ce0f8deee6ee4a0
```

```bash
$ echo "72e4e064f8de706ce0f8deee6ee4a0" | nc 154.57.164.82 31135

Find a message that generate the same hash as this one:
  fd9c3208d1bc1a2678e3aaf7c3ce498ee754d112a3cbae586cb7dce7f45cc582
Enter your message: HTB{sh4256_bu7_w17h_4_7w157_83f023_c4n_c4u5e_c011i51on5}
```

---

## Key Takeaways

1. **Custom transformations before hashing do not guarantee security.** The rotate function introduced information loss (7 effective bits from 8), making the effective SHA-256 input space smaller than the message space.

2. **Always test for injectivity.** A quick enumeration of all 256 byte mappings would have revealed the 128-output property immediately.

3. **SHA-256 remains collision-resistant.** We never broke SHA-256 — we exploited the pre-processing step's non-injectivity to produce identical SHA-256 inputs from different original messages.

4. **"Only the one who is me can be me"** — the creator's "signature" is the rotate function itself. By analyzing it and finding its collision partners, we "reproduced" the signature to forge a valid message.