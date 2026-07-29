# Uncoding — ADF2026 Hackathon

**Category:** Reverse Engineering / Cryptography
**Flag:** `HTB{0n3_t1m3_p4d_tw0_t1m3_p4d_thr33_t1m3_p4d...}`

---

## 0. Summary

### Access & Environment
- Single x86-64 ELF binary (`uncoding`), not stripped, dynamically linked
- Compiled with GCC 10.2.1 (Debian), PIE enabled
- Presents a text menu: "Which memory would you like to review today (0 -> 3)?"

### Critical Findings
- The binary contains **4 encrypted messages** stored in `.rodata`
- All 4 messages are XOR-encrypted with the **same 16-byte key** (embedded in `decrypt_message`)
- Messages 0–2 are decrypted and displayed; message 3 is deliberately **locked** with an early-return check
- The flag is in **message 3**, trivially recoverable by applying the same XOR key

### Security Implications
- The classic **one-time pad reuse** (many-time pad) vulnerability: using the same keystream for multiple plaintexts. The flag text itself references this: `0n3_t1m3_p4d_tw0_t1m3_p4d_thr33_t1m3_p4d...`

---

## 1. Binary Enumeration

### File Identification

**Code:**
```bash
file uncoding
```

**Output:**
```
uncoding: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=d2de2a09db228585d5d038e78a2ea06c5d4dc5e6,
for GNU/Linux 3.2.0, not stripped
```

**Description:**
- 64-bit x86-64 ELF, PIE-enabled, not stripped — symbols and function names are preserved.

### Strings Analysis

**Code:**
```bash
strings uncoding
```

**Output (key strings):**
```
-- ERROR -- [That memory has been locked away!] -- ERROR --
-- ERROR -- [That memory does not exist] -- ERROR --
Which memory would you like to review today (0 -> 3)?
decrypt_message
messages
```

**Description:**
- Two error messages, a prompt for input 0–3, and symbols revealing `decrypt_message` and `messages`.

---

## 2. Disassembly — `decrypt_message`

Disassembled with `x86_64-linux-gnu-objdump -d`:

```asm
0000000000001185 <decrypt_message>:
    1185:  push   %rbp
    1186:  mov    %rsp,%rbp
    1189:  sub    $0x30,%rsp
    118d:  mov    %edi,-0x24(%rbp)          ; choice = arg
    1190:  cmpl   $0x3,-0x24(%rbp)          ; if choice == 3
    1194:  jne    11a7
    1196:  lea    0xfc3(%rip),%rdi          ; "That memory has been locked..."
    119d:  call   puts
    11a2:  jmp    125a                      ; return early
    11a7:  cmpl   $0x3,-0x24(%rbp)
    11ab:  jg     11b3
    11ad:  cmpl   $0x0,-0x24(%rbp)
    11b1:  jns    11c4                      ; if (choice >= 0 && choice <= 3)
    11b3:  lea    0xfe6(%rip),%rdi          ; "That memory does not exist..."
    11ba:  call   puts
    11bf:  jmp    125a                      ; return early
    ; --- valid choice (0, 1, or 2) ---
    11c4:  mov    -0x24(%rbp),%eax
    11c7:  cltq
    11c9:  lea    0x0(,%rax,8),%rdx         ; rdx = choice * 8
    11d1:  lea    0x2ea8(%rip),%rax         ; rax = &messages
    11d8:  mov    (%rdx,%rax,1),%rax        ; rax = messages[choice]
    11dc:  mov    %rax,-0x10(%rbp)          ; msg_ptr = messages[choice]
    ; --- load 16-byte XOR key ---
    11e0:  movabs $0xc3e2af1e8edad4c6,%rax  ; key bytes 0-7 (LE)
    11ea:  movabs $0xee602548c0d4060c,%rdx  ; key bytes 8-15 (LE)
    11f4:  mov    %rax,-0x20(%rbp)          ; key[0:8] on stack
    11f8:  mov    %rdx,-0x18(%rbp)          ; key[8:16] on stack
    ; --- decrypt loop ---
    11fc:  movl   $0x0,-0x4(%rbp)           ; i = 0
    1203:  jmp    123a
    1205:  mov    -0x4(%rbp),%eax           ; i
    1208:  movslq %eax,%rdx
    120b:  mov    -0x10(%rbp),%rax          ; msg_ptr
    120f:  add    %rdx,%rax                 ; &msg_ptr[i]
    1212:  movzbl (%rax),%ecx               ; c = msg_ptr[i]
    1215:  mov    -0x4(%rbp),%eax           ; i
    1218:  cltd
    1219:  shr    $0x1c,%edx
    121c:  add    %edx,%eax
    121e:  and    $0xf,%eax
    1221:  sub    %edx,%eax                 ; eax = i % 16 (signed)
    1223:  cltq
    1225:  movzbl -0x20(%rbp,%rax,1),%eax   ; key[i % 16]
    122a:  xor    %ecx,%eax                 ; c ^= key[i % 16]
    122c:  movsbl %al,%eax
    122f:  mov    %eax,%edi
    1231:  call   putchar                   ; putchar(c)
    1236:  addl   $0x1,-0x4(%rbp)           ; i++
    123a:  ... check if msg_ptr[i] != 0 ...
    124c:  jne    1205                      ; loop until null byte
    124e:  lea    0xf80(%rip),%rdi          ; "\n"
    1255:  call   puts
    125a:  leave
    125b:  ret
```

### Algorithm Summary

```
key = [0xc6, 0xd4, 0xda, 0x8e, 0x1e, 0xaf, 0xe2, 0xc3,
       0x0c, 0x06, 0xd4, 0xc0, 0x48, 0x25, 0x60, 0xee]

for i in range(len(message)):
    putchar(message[i] ^ key[i % 16])
```

**Key insight:** The XOR key is **identical** for all four messages — classic OTP reuse. Message 3 is "locked" by an early `if (choice == 3) return` guard, but the encrypted data is present and the key is known.

---

## 3. Extracting the Messages

### Messages Array

From `.data` at `0x4080`:
```
messages[0] = 0x2008  (in .rodata)
messages[1] = 0x2068
messages[2] = 0x20f0
messages[3] = 0x2128
```

The `.rodata` segment is at file offset == virtual address 0x2000, so file offsets match.

---

## 4. Exploitation — Decrypt All Messages

**Code:**
```python
import struct

with open('uncoding', 'rb') as f:
    data = f.read()

messages = [0x2008, 0x2068, 0x20f0, 0x2128]

# 16-byte XOR key from decrypt_message
key = bytes([0xc6, 0xd4, 0xda, 0x8e, 0x1e, 0xaf, 0xe2, 0xc3,
             0x0c, 0x06, 0xd4, 0xc0, 0x48, 0x25, 0x60, 0xee])

for i, offset in enumerate(messages):
    end = offset
    while data[end] != 0:
        end += 1
    encrypted = data[offset:end]
    decrypted = bytes([encrypted[j] ^ key[j % 16] for j in range(len(encrypted))])
    print(f"Message {i}: {decrypted.decode()}")
```

**Output:**
```
Message 0: Three hidden challenges test worthy traits, revealing three hidden keys to three magic gates
Message 1: I suppose you could say they're invisible, hidden in a dark room that's at the centre of a maze, that's located somewhere up here.
Message 2: Nice racing, padawan. You're the first to finish.
Message 3: HTB{0n3_t1m3_p4d_tw0_t1m3_p4d_thr33_t1m3_p4d...}
```

---

## 5. How We Solved It — Reasoning

### Initial Observations
The binary name "Uncoding" and the prompt "Which memory would you like to review" suggested encoded/encrypted data. The strings output showed `decrypt_message` and `messages` as symbols — a clear hint at the structure.

### Key Discoveries
1. **The guard clause at `choice == 3`** was immediately suspicious — why single out one index? The natural human response is "what's behind door #3?"
2. **Same XOR key for all messages** — the `decrypt_message` function loads the 16-byte key unconditionally, before the decryption loop. The loop uses `key[i % 16]` regardless of which message is selected. This is textbook many-time pad.
3. **Offline decryption** — since the key and ciphertext are both in the binary, we don't need to patch the `if (choice == 3)` check. Extracting both from the ELF and XORing them yields the flag directly.

### Rejected Hypotheses
- **Patching the binary** — possible (NOP out the `jne` at 0x1194 or change the `cmpl` value) but unnecessary; offline extraction is simpler and faster.
- **Different key per message** — disproven by analyzing the disassembly: only one `movabs` pair loads the key, shared across all calls.
- **Key derived from input** — disassembly shows the key is hardcoded constants, not computed from user input.

### Key Insight
The flag itself is self-referential: `0n3_t1m3_p4d` (one-time pad), `tw0_t1m3_p4d` (two-time pad), `thr33_t1m3_p4d` (three-time pad). The joke is that using the same OTP key 4 times makes it a "four-time pad" — completely insecure. The challenge teaches through irony: message 3 is "locked" but the reused key makes it trivially recoverable.

---

## 6. Flag

```
HTB{0n3_t1m3_p4d_tw0_t1m3_p4d_thr33_t1m3_p4d...}
```
