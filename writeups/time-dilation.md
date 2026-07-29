# Time Dilation — Forensics Challenge Writeup

**Category:** Forensics  
**Challenge:** Time Dilation  
**Flag:** `HTB{h3avy_Pr0cc3s_h0ll0w1ng_l3ads_t0_s1ngular1ty!}`

---

## Overview

The challenge provides a PCAP file (`time.pcap`) containing HTTP traffic. A client (192.168.1.130) downloads two files from `windowsliveupdater.com:80`:

1. `GET /r.ps1` → PowerShell dropper (2,030 bytes)
2. `GET /mal.vbs` → VBScript dropper with .NET payload (196,108 bytes)

The malware chain uses .NET deserialization to load an embedded assembly that performs **process hollowing** — injecting malicious code into a legitimate `vbc.exe` process.

---

## How We Solved It — Reasoning

### Phase 1: PCAP Triage

The PCAP contains 45 packets over 0.344 seconds. Two HTTP GET requests and their responses. Extracted both files:

```bash
tshark -r time.pcap -q -z "follow,tcp,raw,0" | tail -n +5 > stream.txt
```

**r.ps1** decodes to a simple PowerShell script:
- Generates a random 10-character filename
- Downloads `mal.vbs` from `windowsliveupdater.com/mal.vbs`
- Saves to `%TEMP%`, marks as hidden, executes via `wscript.exe`

### Phase 2: VBScript Analysis

**mal.vbs** (196KB) uses .NET COM objects:
- Sets CLR version (`v4.0.30319` or `v2.0.50727`)
- Contains a 157,380-character base64 string built via `s = s & "..."` concatenation
- Deserializes it with `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`
- The deserialized object is a **delegate chain** that loads a .NET assembly via `Assembly.Load(byte[])`
- Creates an instance of `SpaceTravel.Singularity`

### Phase 3: .NET Assembly Extraction

The base64 decodes to 118,035 bytes of BinaryFormatter data containing an embedded .NET PE assembly (`Mono_dll.dll`).

**Key findings from dnfile analysis:**
- **Class `SpaceTravel.Cipher`**: Fields `BlockSize`, `DerrivationIterations` (=256)
  - Methods: `Encrypt`, `Decrypt`, `GenerateEntropy`
- **Class `SpaceTravel.CMemoryExecute`**: P/Invoke wrappers for process hollowing
  - `CreateProcess`, `VirtualAllocEx`, `NtWriteVirtualMemory`, `NtResumeThread`, etc.
- **Class `SpaceTravel.Singularity`**: Single method `.ctor` (constructor)
- Encrypted payload: 54,060-character base64 in the `#US` metadata heap

### Phase 4: Understanding the Encryption

**Decrypt method IL analysis:**
- Takes `(string ct, string passphrase)` → returns `string`
- Splits input: `salt[32]` + `IV[32]` + `ciphertext`
- Uses `Rfc2898DeriveBytes(passphrase, salt, 299)` for key derivation
- **Rijndael-256-CBC** (not standard AES!) — `BlockSize = 256` (32-byte blocks)
- `PaddingMode = 2` (PKCS7)

**Constructor (.ctor) IL analysis revealed the passphrase is deterministic:**
```
BlockCopy(vbcExe, 0, local2, 0, 2)    // Copy first 2 bytes of vbc.exe (="MZ")
BitConverter.ToUInt16(local2, 0)      // = 0x5A4D = 23117
new Random(23117)                      // Seeded PRNG
Random.NextBytes(byte[32])             // 32 deterministic pseudo-random bytes
Convert.ToBase64String(byte[32])       // This IS the passphrase!
```

### Phase 5: Replicating .NET Random

The .NET `System.Random` class uses a subtractive lagged Fibonacci generator. Implemented in Python:

```python
class DotNetRandom:
    MBIG = 0x7FFFFFFF
    MSEED = 161803398
    
    def __init__(self, seed):
        self.SeedArray = [0] * 56
        subtraction = self.MBIG if seed == -0x80000000 else abs(seed)
        mj = self.MSEED - subtraction
        # ... full implementation in solve script
    
    def Next(self):
        # Lagged Fibonacci sample
        self.inext = (self.inext + 1) % 56
        self.inextp = (self.inextp + 1) % 56
        num = self.SeedArray[self.inext] - self.SeedArray[self.inextp]
        if num < 0: num += self.MBIG
        self.SeedArray[self.inext] = num
        return num
```

**Seed verification:** `Random(0).Next() = 1559595546` ✅ matches .NET Framework

### Phase 6: Rijndael-256 Implementation

AES (128-bit blocks) ≠ Rijndael-256 (256-bit blocks, Nb=8 columns). Custom implementation required:

```python
NB = 8   # 256-bit block = 8 columns of 4 bytes each
NK = 8   # 256-bit key = 8 words
NR = 14  # max(NK,NB)+6 = 14 rounds

# State layout: 4 rows × 8 columns = 32 bytes
# byte[row + 4*col]

# Inverse ShiftRows offsets for Nb=8:
INV_SHIFT = [0, NB-1, NB-3, NB-4]  # [0, 7, 5, 4]
```

### Phase 7: Decryption

```python
# Deterministic passphrase
rnd = DotNetRandom(23117)
sb = bytearray(32); rnd.NextBytes(sb)
passphrase = base64.b64encode(bytes(sb)).decode()
# Result: NjJYbGlMDTRU+/EFoHt8+VKJ0hdjmvCSLZNI6WDHaA0=

# Load encrypted payload (40544 bytes — note: dnfile gives correct length)
salt = enc[:32]
iv = enc[32:64]
ct = enc[64:]     # Exactly 1265 blocks of 32 bytes ✓

# Derive key
key = PBKDF2(passphrase, salt, dkLen=32, count=299)

# Rijndael-256-CBC decrypt
pt = cbc_decrypt(ct, key, iv)
```

**Decrypted output:** 40,448-byte PE executable (debug build, Visual C++).

### Phase 8: Flag Extraction

The decrypted PE is a space-themed program that:
1. Checks admin privileges → prints "Speciment unfit for Spacetravel" if not admin
2. Creates local user "Antares" with password encoded at offset 0x7b8c
3. Adds to "Remote Desktop Users" group
4. Handles failures with space-themed error messages

The encoded password is XOR'd with `"Canopus - Alpha Carinae"` (function at `0x401580`):

```python
encoded = bytes.fromhex(
    "0b352c1418461256547f111e400b0213303e1a59020d553450"
    "00082f19404149531e18403712112d0607050f135437184f1200"
)
key = b"Canopus - Alpha Carinae"
decoded = bytes(e ^ key[i % len(key)] for i, e in enumerate(encoded))
# Result: HTB{h3avy_Pr0cc3s_h0ll0w1ng_l3ads_t0_s1ngular1ty!}p
```

---

## Flag

```
HTB{h3avy_Pr0cc3s_h0ll0w1ng_l3ads_t0_s1ngular1ty!}
```

---

## Key Tools Used

| Tool | Purpose |
|------|---------|
| `tshark` / `tcpdump` | PCAP analysis |
| `dnfile` | .NET PE parsing |
| `dncil` | CIL bytecode disassembly |
| `pefile` | PE structure analysis |
| `pycryptodome` | PBKDF2, AES |
| Custom Rijndael-256 | 32-byte block CBC decryption |
| `x86_64-linux-gnu-objdump` | x86 disassembly |
| `radare2` | Binary analysis |

---

## Caveats & Lessons Learned

1. **Rijndael ≠ AES.** The malware uses `BlockSize = 256` (32-byte blocks). Standard AES libraries only support 16-byte blocks. A custom Rijndael-256 implementation was required.

2. **Base64 payload length.** Manual extraction from the `#US` heap gave 40,543 bytes (off by 1). Using `dnfile` directly gave the correct 40,544 bytes, which divides evenly by 32.

3. **.NET Random replication.** The `.NET System.Random` class uses a lagged Fibonacci generator, not Mersenne Twister. The seed calculation: `MSEED - abs(seed)`, NOT `seed ^ 0x7FFFFFFF`.

4. **The passphrase is deterministic.** It's derived from `new Random(23117).NextBytes()` where 23117 comes from the first 2 bytes of `vbc.exe` ("MZ" = 0x5A4D). This means the encrypted payload can ONLY be decrypted with knowledge of the vbc.exe header bytes.

5. **Corrupted metadata.** The `Module` table row count in the `#~` stream was `0x3301FA00` (~855M rows), causing `dnfile` to parse only a subset of metadata tables. Manual IL analysis was needed for the Constant table.

6. **The flag was NOT in the encrypted payload's plaintext strings.** It was XOR-encoded and only revealed through static analysis of the decoder function's key ("Canopus - Alpha Carinae").
