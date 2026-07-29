# World Hello — Reverse Engineering

**CTF:** ADF 2026 Hackathon (Cyber Apocalypse 2026)  
**Category:** Reverse Engineering  
**Challenge:** World Hello  
**Flag:** `HTB{RUNT1M3_G0_R3V34L5_1NT3NT}`

---

## Scenario

> While poking around the JIT devices inside The Big House, we noticed a small binary that definitely wasn't added by us. It wasn't doing anything obvious, wasn't crashing, and wasn't even printing anything — which made it feel extra suspicious.
>
> It's probably nothing.
> …But then again, that's usually how it starts.
>
> So we decide to take a closer look and figure out what this binary is really up to.

---

## Analysis

### Binary Properties

| Property | Value |
|----------|-------|
| File | `rev_world_hello/telemetry` (1,605,816 bytes) |
| Format | ELF 64-bit LSB executable, x86-64 |
| Compiler | Go 1.25.6, statically linked, stripped |
| Build flags | `-gcflags=all=-l -trimpath=true` |
| Build ID | `35ccc68a3a2054e7ba816c36035250fdc2ef722c` |
| Sections | `.text` (0x401000), `.rodata` (0x4ac000), `.gopclntab` (0x4e6820), `.data` (0x581fe0), `.noptrdata` (0x57d1c0) |

### Symbol Recovery via pclntab

Despite being stripped, Go binaries retain the `.gopclntab` section with complete function metadata. Parsing it with Go's `debug/gosym` package (or manually parsing the 0xFFFFFFF1 header format) reveals 3,611 functions including:

| Function | Size | Purpose |
|----------|------|---------|
| `main.main` | 96 B | Entry point — loops 50x through noise chain |
| `main.buildCampaignTag` | 128 B | Assembles `HTB{...}` from global string fragments |
| `main.buildRuntimeStats` | 320 B | Collects flag content fragments, formats with `%[2]s%[1]s%[3]s%[4]s` |
| `main.reportStatus` | 160 B | Calls buildCampaignTag, outputs result |
| `main.noiseDispatch` | 8,608 B | Dispatch table: calls `noiseFunc[rax % 750]` |
| `main.seed` | 32 B | Returns `0x539` (1337) |
| `main.statA` | 32 B | Returns flag fragment 1 |
| `main.statB` | 32 B | Returns flag fragment 2 |
| `main.statC` | 32 B | Returns flag fragment 3 |
| `main.statD` | 32 B | Returns flag fragment 4 |
| `main.noiseFunc0`–`main.noiseFunc749` | 32 B each | **750 noise functions** — distraction |

### Noise Function Red Herring

Every noise function is identical in structure (32 bytes):
```asm
add    $0x0D + 7*N, %rax    ; add = 0x0d increments by 7 per function
xor    $0x5D + 3*N, %rax    ; xor = 0x5d increments by 3 per function
ret
```

These 750 functions form a simple arithmetic PRNG chain. The `main.main` function calls `seed()` → 50× `noiseDispatch(rax)` → `reportStatus()`. The noise chain exists purely to distract reverse engineers — **the noise value is never used to construct the flag**.

### Flag Construction

The real flag is assembled by `buildCampaignTag` from **hardcoded string fragments** stored in the Go packed `.rodata` string table:

| Fragment | Virtual Addr | Length | Value |
|----------|-------------|--------|-------|
| Frame 1 | `0x4d168b` | 2 | `HT` |
| Frame 2 | `0x4e0448` | 1 | `B` |
| Frame 3 | `0x4d1678` | 1 | `{` |
| Frame 4 | `0x4d1679` | 1 | `}` |
| Content 1 | `0x4d16d3` | 3 | `G0_` |
| Content 2 | `0x4d1cde` | 8 | `RUNT1M3_` |
| Content 3 | `0x4d1ce6` | 8 | `R3V34L5_` |
| Content 4 | `0x4d1944` | 6 | `1NT3NT` |

The `buildRuntimeStats` function calls `statA`→`statD` to retrieve these fragments and formats them with `%[2]s%[1]s%[3]s%[4]s`.

### Anti-Analysis

1. **CPUID "GenuineIntel" check** at `0x47b03d` — checks for physical Intel CPU, exits early under QEMU emulation
2. **750 noise functions** — designed to overwhelm naive string extraction and function enumeration
3. **0-byte stdout write** — when run without C2 infrastructure, the binary writes nothing, hiding the flag assembly from dynamic analysis
4. **Go binary internals** — statically linked, stripped, with complex pclntab format exploitation

---

## How We Solved It — Reasoning

### Hypothesis 1: The binary exfiltrates the flag over HTTP
**Rejected.** We set up listeners on 14 common C2 ports (80, 443, 8080, 8443, 9090, 4242, 1337, 31337, 4444, 5555, 6666, 7777, 8888, 9999) and ran the binary under `qemu-x86_64 -strace`. Zero network activity — no `socket`, `connect`, or `sendto` syscalls.

### Hypothesis 2: The CPUID anti-VM check blocks execution
**Partially confirmed.** The binary checks for "GenuineIntel" via `CPUID` at startup. We patched the `je` at `0x47b040` to `jmp` to always set the flag. The binary still produced no output — the CPUID check wasn't the primary blocker.

### Hypothesis 3: The flag is XOR-encoded in the binary
**Rejected.** Scanned all 1.6MB with every 8-bit XOR key (0x00–0xFF). No `HTB{` pattern found. Also tried base64, base32, hex, ROT13/ROT47, reversed byte order, interleaved reads, and bitwise NOT.

### Hypothesis 4: The noise functions collectively spell the flag
**Partially investigated.** Each noise function is just `add + xor + ret` — no string data. The noise dispatch loop produces pseudo-random values that are **never used** for flag assembly.

### Hypothesis 5: The flag is assembled from hardcoded string fragments
**CONFIRMED.** By parsing the Go pclntab with `debug/gosym`, we recovered the addresses of `statA`–`statD`, which are 32-byte leaf functions. Each loads a string fragment from `.rodata` via RIP-relative LEA:

```
statA: lea 0x2ce84(%rip), %rax → "G0_"       (3 bytes)
statB: lea 0x2ce4d(%rip), %rax → "RUNT1M3_"  (8 bytes)
statC: lea 0x2ce53(%rip), %rax → "R3V34L5_"  (8 bytes)
statD: lea 0x2ceb3(%rip), %rax → "1NT3NT"    (6 bytes)
```

The `buildCampaignTag` function loads frame pieces (`HT`, `B`, `{`, `}`) from globals and combines them with the content from `buildRuntimeStats`. The format string `%[2]s%[1]s%[3]s%[4]s` reorders the fragments from natural ABCD order to BACD, producing: **`HTB{RUNT1M3_G0_R3V34L5_1NT3NT}`**

The flag decodes from leetspeak to: **"RUNTIME GO REVEALS INTENT"**

### Key Insight

The challenge name **"World Hello"** (Hello World reversed) is a triple clue:
1. **"rev"** — the directory is `rev_world_hello`, indicating reverse engineering
2. **"World Hello"** → **"Hello World"** reversed → hints that the binary's true purpose is hidden (reversed from obvious)
3. The binary **does nothing when run** — its "Hello World" output is null, forcing static analysis

The flag decodes from leetspeak to: **"RUNTIME GO REVEALS INTENT"** — the Go runtime binary reveals its true intent (the flag) only through static reverse engineering, not dynamic execution.

---

## Key Takeaways

- **Go's `.gopclntab` is an invaluable reverse engineering resource** — even stripped Go binaries retain complete function metadata
- **750 noise functions were pure distraction** — don't assume every function is meaningful
- **CPUID anti-VM checks are common in Go malware** — easily patched but not the real obstacle
- **Static analysis won where dynamic execution failed** — the flag was never meant to be revealed through runtime behavior