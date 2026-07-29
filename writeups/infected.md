# Infected — Forensics Challenge Writeup

**CTF**: ADF2026 Hackathon  
**Category**: Forensics / Memory Analysis  
**Flag**: `HTB{p4y1ng_th3_r4ns0m_1s_n0t_4_g00d_1d34}`

---

## Overview

A Windows 7 SP1 x86 PAE machine was infected with ransomware after the user Wilson visited `windowsliveupdater.com`. All files on the desktop were encrypted with a `.enc` extension. A VirtualBox core dump (`mem.dmp`, ELF64 format) was captured shortly after the incident.

**Goal**: Analyze the memory dump, recover the encryption key, and decrypt `clients_information.xlsx.enc`.

---

## How We Solved It — Reasoning

### Phase 1: Initial Recon

The memory dump was a VirtualBox ELF64 core dump — not a standard LiME format. Initial string analysis revealed:

- **Malware**: `Atac4D.exe` — .NET Core 3.1, self-contained win-x86 deployment
- **Download URL**: `https://windowsliveupdater.com/Atac4D.exe` (via Internet Explorer by user `Wilson`)
- **Crypto stack**: `RijndaelManaged`, `Rfc2898DeriveBytes`, `SHA256`, `PKCS7`
- **Target file**: `C:\Users\Wilson\Desktop\clients_information.xlsx` → `clients_information.xlsx.enc` (15,616 bytes)
- **Kernel**: `ntkrpamp.pdb` GUID `2F6693D273A446AA8740983BC3D539C2`

### Phase 2: Volatility (The Struggle)

Volatility 3 couldn't auto-detect the kernel layer from the VirtualBox dump. Two key problems:

1. **ISF symbol files unavailable** — All symbol server URLs returned 404
2. **VirtualBox dump format** — The `WindowsIntelStacker` DTB scanner couldn't find self-referential page tables at the expected scan ranges

**Breakthrough #1**: Downloaded the kernel PDB (`ntkrpamp.pdb`, 6.9MB) from Microsoft's symbol server at `https://msdl.microsoft.com/download/symbols/ntkrpamp.pdb/2F6693D273A446AA8740983BC3D539C22/ntkrpamp.pdb` and converted it to ISF format (18,631 symbols, 882 types) using Volatility's built-in `PdbReader`.

**Breakthrough #2**: Patched Volatility's `elf.py` to accept ELF segments where `p_filesz` ≠ `p_memsz` (VirtualBox dumps have segments with `filesz=0, memsz>0`). Added automatic PAE DTB detection by scanning for the self-referential page table pattern.

**Breakthrough #3**: The PAE DTB was found at physical address `0x185000` (self-ref pattern confirmed), and the PDPT at `0x189000`. With this, Volatility's `windows.info.Info` successfully identified:

```
Kernel Base    0x82819000
DTB            0x185000
NTBuildLab     7601.18939.x86fre.win7sp1_gdr.15
IsPAE          True
```

### Phase 3: Process Analysis

`windows.filescan.FileScan` located the Atac4D extraction directory:
```
\Users\Wilson\AppData\Local\Temp\.net\Atac4D\pkEXd_gSpg1xnFryO9TJxtZrmSM5qt8=\Atac4D.dll
```

The Atac4D process had already exited (no PID in pslist), but `windows.dumpfiles.DumpFiles` successfully dumped both the EXE and DLL from the file system cache.

### Phase 4: Decompilation

The Atac4D.dll (16KB .NET assembly) was decompiled using `System.Reflection.Metadata`. The malware had obfuscated method names:
- `IzBEwwlnt` — Network check (pings `www.google.com`)
- `SpkNtCBIT` — Persistence (registry `Run` key)
- `DEuLGJtoN` — File enumeration with extension filter
- `CZmDwSoeZ` — Main encryption logic
- `VhYahoLew` — AES crypto implementation

### Phase 5: Key Extraction

The IL bytecode analysis revealed the encryption chain:

```
Password = "dXcIcaCPoCiUXKMO"
passwordBytes = UTF8.GetBytes(Password)
keyMaterial = SHA256(passwordBytes)                    // 32 bytes
AES_Key = PBKDF2-SHA1(keyMaterial, keyMaterial, 1000).GetBytes(32)  // 32 bytes
AES_IV  = PBKDF2-SHA1(keyMaterial, keyMaterial, 1000).GetBytes(16)  // 16 bytes
Cipher   = AES-256-CBC(Key, IV) with PKCS7 padding
```

**Key insight**: The **password** (`dXcIcaCPoCiUXKMO`) and **salt** are both the SHA256 hash of the password string. This double-hashing with PBKDF2-SHA1 (1000 iterations) is unusual but deterministic.

### Phase 6: Decryption

Using Python's `Cryptodome` to replicate the .NET crypto:

```python
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA1
from Cryptodome.Cipher import AES
import hashlib

password = "dXcIcaCPoCiUXKMO"
pw_hash = hashlib.sha256(password.encode()).digest()  # 32 bytes
material = PBKDF2(pw_hash, pw_hash, dkLen=48, count=1000, hmac_hash_module=SHA1)
key, iv = material[:32], material[32:48]
cipher = AES.new(key, AES.MODE_CBC, iv=iv)
decrypted = unpad(cipher.decrypt(encrypted_data), 16)
```

The decrypted file is a valid XLSX spreadsheet with 708 rows of client data and the flag embedded in shared strings.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Volatility 3** | Memory forensics (pslist, filescan, dumpfiles, banners, info) |
| **Python Cryptodome** | AES decryption, PBKDF2 key derivation |
| **.NET 8.0 SDK** | Metadata decompilation with `System.Reflection.Metadata` |
| **Microsoft Symbol Server** | Kernel PDB download for ISF generation |

---

## Flags

| Flag | Location | Method |
|------|----------|--------|
| `HTB{p4y1ng_th3_r4ns0m_1s_n0t_4_g00d_1d34}` | `xl/sharedStrings.xml` in decrypted XLSX | Memory forensics → DLL decompilation → AES key extraction → decryption |

---

## Caveats & Gotchas

1. **VirtualBox ELF dumps** — Volatility's Elf64Layer requires `p_filesz == p_memsz` which doesn't hold for VirtualBox dumps. Must patch `elf.py` or convert to raw.
2. **PAE self-referencing** — The DTB scanner's default scan range `(0x30000, 0x1000000)` missed the actual DTB at `0x185000`. Extended scanning was required.
3. **ISF generation** — Couldn't download pre-built ISF files; had to generate ISF (2.5MB JSON) from the PDB using Volatility's `pdbconv.py`.
4. **Double hashing** — The ransomware doesn't use the password directly as PBKDF2 input. It SHA256-hashes the password first, then uses the hash as both password and salt for PBKDF2-SHA1.
5. **PBKDF2 hash algorithm** — .NET's `Rfc2898DeriveBytes` defaults to SHA1 (not SHA256), which was critical to match.
6. **MemberRef token mapping** — Required careful 1-based row indexing to map IL tokens to the correct MemberRef entries.
