# Cryptic Jumble — ADF2026 Hackathon

**Category:** Cryptanalysis
**Flag:** `FLAG{39db93b4c4f-2ca4-4d7b-93a4-4ae8d9b18e01d}`

---

## 0. Summary

### Access & Environment
- Single text file: `file_d691b.txt` (16,740 chars)
- Challenge category: **Cryptanalysis** — "decode the layers, unlock the secrets"

### Critical Findings
- The file is a **4-layer encoding onion**, alternating base64, JavaScript (JSFuck), base64, and string reversal
- Layer 1: base64 → **JSFuck** source (12,554 chars)
- Layer 2: JSFuck (eval'd) → a 124-char **base64** payload
- Layer 3: base64 → a tiny **Python script** that reverses a string
- Layer 4: the reversed string **is the flag**, character-for-character

### Security Implications
- Layered obfuscation (encoding + JSFuck + reversal) is a common malware / flag-hiding evasion pattern — each layer is trivially unwrapped but together they evade naive signature detection and `strings`-style scanning.

---

## 1. Initial Inspection

**Code:**
```bash
file file_d691b.txt
head -c 200 file_d691b.txt
```

**Output:**
```
W11bKCFbXStbXSlbK1tdXSsoIVtdK1tdKVshK1tdKyErW11dKyghW10rW10pWyshK1tdXSsoISFbXStbXSlbK1tdXV1bKFtd...
```

**Description:**
- The payload is a single long line of printable ASCII — immediately recognisable as **base64** (the `W11b...` prefix decodes to `[]`).

---

## 2. Layer 1 — Base64 → JSFuck

**Code:**
```bash
base64 -d file_d691b.txt > layer1.js
head -c 200 layer1.js
```

**Output:**
```
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+...
```

**Description:**
- The decoded text starts with `[][(![]+[])[+[]]...` — the signature of **JSFuck**, an esoteric JavaScript dialect built only from `[]`, `!`, `+`, and parentheses that evaluates to arbitrary JavaScript.
- Anything that can be evaluated in Node/browser JS can be hidden in JSFuck.

---

## 3. Layer 2 — JSFuck → Base64

**Code:**
```bash
node -e 'const fs=require("fs");eval(fs.readFileSync("layer1.js","utf8"))'
```

**Output:**
```
cyA9ICd9ZDEwZTgxYjlkOGVhNC00YTM5LWI3ZDQtNGFjMi1mNGM0YjM5YmQ5M3tHQUxGJwpyZXZlcnNlZF9zID0gc1s6Oi0xXQpwcmludChyZXZlcnNlZF9zKQ==
```

**Description:**
- Evaluating the JSFuck with Node prints a **second base64** string — the JSFuck was constructing the next layer's source and printing it.

---

## 4. Layer 3 — Base64 → Python Source

**Code:**
```bash
echo 'cyA9ICd9ZDEwZTgxYjlkOGVhNC00YTM5LWI3ZDQtNGFjMi1mNGM0YjM5YmQ5M3tHQUxGJwpyZXZlcnNlZF9zID0gc1s6Oi0xXQpwcmludChyZXZlcnNlZF9zKQ==' | base64 -d
```

**Output:**
```python
s = '}d10e81b9d8ea4-4a39-b7d4-4ac2-f4c4b39bd93{GALF'
reversed_s = s[::-1]
print(reversed_s)
```

**Description:**
- A 3-line Python script: assigns a string, reverses it with `[::-1]`, prints it.
- Note the string ends in `{GALF` — "GALF" is "FLAG" backwards. The whole string is the flag written in reverse.

---

## 5. Layer 4 — Flag

**Code:**
```bash
python3 -c "s='}d10e81b9d8ea4-4a39-b7d4-4ac2-f4c4b39bd93{GALF'; print(s[::-1])"
```

**Output:**
```
FLAG{39db93b4c4f-2ca4-4d7b-93a4-4ae8d9b18e01d}
```

---

## 6. How We Solved It — Reasoning

### Initial Observations
The challenge description explicitly says "decode the layers" — so the approach was deterministic layer-by-layer unwrapping, not cryptanalysis of a cipher. The file content's base64 prefix (`W11` → `[]`) was the first giveaway.

### Key Discoveries
1. **Recognising base64**: The all-printable, `A-Za-z0-9+/=` alphabet and the `W11b` → `[]` decode immediately identified layer 1.
2. **Recognising JSFuck**: The decoded output's `[][(![]+[])[+[]]` prefix is the canonical JSFuck bootstrap — evaluating it in Node is the only sane way to unwrap it (it is valid, executable JavaScript).
3. **The nested base64**: The JSFuck's stdout was itself base64 — a deliberate "one more layer" trick to make people think they were done.
4. **The reversal hint**: The final string's `{GALF` suffix is the dead giveaway — `GALF` is `FLAG` mirrored. Reversing the whole string yields the flag directly.

### Rejected Hypotheses
- **It's a cipher (ROT/XOR/AES)**: Ruled out immediately — no key material, no ciphertext structure; the data is pure encoding, not encryption.
- **JSFuck must be decoded by hand**: Ruled out — JSFuck is designed to be *evaluated*, and Node executes it natively. Hand-decoding 12.5KB of JSFuck would be pointless.
- **The base64 output was the flag**: The decoded Python source showed it was still one layer away.

### Key Insight
Every layer advertised the next one: base64 is self-identifying, JSFuck has an unmistakable signature, the Python script literally contained `[::-1]` and a `{GALF`-terminated string. This challenge is about **layer recognition** — knowing what each encoding looks like and picking the right unwrap tool. A real defender benefits the same way: obfuscation chains are only as strong as their weakest recognisable layer, and automated detonation (sandboxed eval) strips JSFuck instantly.

---

## 7. Flag

```
FLAG{39db93b4c4f-2ca4-4d7b-93a4-4ae8d9b18e01d}
```
