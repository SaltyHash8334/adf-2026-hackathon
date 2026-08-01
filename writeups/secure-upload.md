# Secure Upload — ADF2026 Hackathon

**Category:** Encryption Techniques
**Flag:** `FLAG{h3r3s_y0ur_s3curely_transferred_fl4g}`

---

## 0. Summary

### Access & Environment
- Target: `10.0.6.214` — port 80 only, `Werkzeug/3.1.3` (Python 3.9.21 Flask app)
- Challenge category: **Encryption Techniques** — "secure upload facility uses public key cryptography… using the simple and modern age encryption tool"
- No files provided; everything is done over HTTP against the live service

### Critical Findings
- The service is an **age** (https://age-encryption.org) key-exchange web app: it publishes its age public key, and asks you to encrypt *your* public key with *its* public key and upload it; it then decrypts your key and re-encrypts the flag to you
- **The trap:** age's default (armored) output is **not pure ASCII** — the payload after the `--- <MAC>` line is raw binary. It can never survive a `application/x-www-form-urlencoded` textarea round-trip (Werkzeug decodes form fields as UTF-8 with `errors='replace'`), so every "standard" upload attempt fails with `Could not decrypt your public key.`
- **The fix:** the age spec mandates that files transmitted as 7-bit ASCII SHOULD use **PEM encoding (RFC 7468)** with the label `AGE ENCRYPTED FILE` — produced with `age -a/--armor`. The PEM blob is pure base64 ASCII, survives the form field intact, and the server's age library parses it natively.

### Security Implications
- Transport of encrypted blobs through text-only channels (HTML forms, JSON, email) silently corrupts binary payloads. Using the spec-mandated PEM armor is not just cosmetic — it is the difference between a decryptable file and a corrupted one.
- The design itself (encrypt-to-recipient key exchange) is sound; the challenge's difficulty is entirely in the *encoding layer* around the ciphertext.

---

## 1. Initial Inspection

**Code:**
```bash
curl -s http://10.0.6.214/
nmap -p- 10.0.6.214
```

**Output:**
```html
<h2>Secure Upload Area</h2>
<p>Our age public key is:</p>
<code>age15prc8mv6q23cxa7h44pw0k8zx8gacp60hl9gszc585g4eflg9cxsru3d6m</code>
<form id=pubkeyform action=/upload method=POST>
  <textarea name=pubkey cols=80 rows=30 placeholder="Your encrypted public key.."></textarea>
  <input type=submit value=Upload></input>
</form>
```

**Description:**
- Single endpoint: `POST /upload` with a form field `pubkey`
- The page advertises the server's age public key and asks for your public key, encrypted to that key
- Known-good error messages: `missing pubkey file` (400, field absent) and `Could not decrypt your public key.` (200, field present but undecryptable) — a small oracle into the handler logic

---

## 2. Key Exchange Setup

**Code:**
```bash
age-keygen -o key.txt                      # generate my keypair
age-keygen -y key.txt > mypub.txt          # extract my public key
SRV=age15prc8mv6q23cxa7h44pw0k8zx8gacp60hl9gszc585g4eflg9cxsru3d6m
age -r "$SRV" -o mypub.age mypub.txt       # encrypt my pubkey to the server
curl -s -X POST --data-urlencode "pubkey@mypub.age" http://10.0.6.214/upload
```

**Output:**
```
Could not decrypt your public key.
```

**Description:**
- My public key: `age1xw6wwssk3nuyn94e7f7nunas3zhsd9204amdjqzylepq7dwvrumqyyndfp`
- The blob is *structurally valid* (local round-trip decrypts fine), so the failure is in how the server receives it

---

## 3. Systematic Probing — Every Standard Transport Fails

A 13-variant encoding matrix against `/upload` (raw bytes, base64 ± padding/newlines, URL-safe base64, hex, latin-1, armor-only, multipart form-field, multipart file upload, raw request body, CRLF variants, `charset=iso-8859-1`/`windows-1252` Content-Type headers):

| Variant | Result |
|---|---|
| raw blob (urlencoded) | `Could not decrypt` |
| raw blob, no trailing newline | `Could not decrypt` |
| base64 / base64+NL / wrapped / url-safe / unpadded | `Could not decrypt` |
| hex | `Could not decrypt` |
| latin-1 passthrough | `Could not decrypt` |
| multipart file upload (any field name) | `missing pubkey file` |
| raw body `pubkey=` + binary | `missing pubkey file` |
| charset tricks (latin-1 / windows-1252) | `Could not decrypt` |

**Description:**
- The handler only reads `request.form['pubkey']`; file uploads never reach decryption
- Werkzeug decodes urlencoded/multipart field values as UTF-8 with `errors='replace'` — every non-UTF-8 byte in the age payload (which is random ciphertext) is replaced by `U+FFFD`, guaranteeing a MAC mismatch
- No re-encoding of the client side can fix this: the binary payload is unrecoverable after the server's own decode step
- Dead ends ruled out: no source disclosure, no Werkzeug console, no exposed key files, public key valid & stable (bech32-valid X25519 recipient, identical across 5 fetches), timing shows no post-decrypt work

---

## 4. The Breakthrough — PEM Armor from the Age Spec

**Code:**
```bash
age -a -r "$SRV" -o mypub.pem mypub.txt    # -a / --armor = PEM encoding
cat mypub.pem
```

**Output:**
```
-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaRmdXa3NwNDk5MXJVN3Mv
ZlVFV1U0Yk9YZVpZV2M5ZFJGQmpqMkpkRDM4CkVoaE5FNithNVJPVCtiVlV1cU1r
...
-----END AGE ENCRYPTED FILE-----
```

**Description:**
- The age spec (age-encryption.org/v1, "ASCII armor" section) states: *"age files that need to be transmitted as 7-bit ASCII SHOULD be encoded according to the strict PEM encoding specified in RFC 7468, Section 3, with case-sensitive label 'AGE ENCRYPTED FILE'."*
- The `age` CLI implements this via `-a, --armor` — producing a fully ASCII, base64-wrapped PEM document that survives any text channel byte-for-byte

---

## 5. Solution

**Code:**
```bash
# 1. Upload the PEM-armored blob (pure ASCII -> survives the form field)
curl -s -X POST --data-urlencode "pubkey@mypub.pem" \
     http://10.0.6.214/upload -o resp.age

# 2. The server decrypts my public key, encrypts the flag to it, returns PEM
head -c 60 resp.age
# -----BEGIN AGE ENCRYPTED FILE----- ...

# 3. Decrypt the returned flag file with my private key
age -d -i key.txt resp.age
```

**Output:**
```
FLAG{h3r3s_y0ur_s3curely_transferred_fl4g}
```

---

## 6. How We Solved It — Reasoning

### Initial model
The description ("simple and modern age encryption tool") pointed straight at `age`. The intended flow was obvious: download server key → generate my keypair → encrypt my public key with their public key → upload → get the flag encrypted to me → decrypt locally.

### Rejected hypotheses
1. **Wrong key / broken server** — ruled out: the advertised key is bech32-valid, parses as an X25519 recipient in pyrage, and is stable across requests; the server *does* attempt decryption (distinct error for absent vs present-but-bad field).
2. **Server expects base64/hex** — ruled out: a 13-variant encoding matrix all returned `Could not decrypt`; the server passes the form string straight into `age.decrypt` with no decoding step.
3. **Multipart file upload** — ruled out: `missing pubkey file` for every field name; the handler exclusively reads `request.form['pubkey']`.
4. **Charset smuggling** — ruled out: `Content-Type: …; charset=iso-8859-1` and `windows-1252` on both urlencoded and multipart still failed; Werkzeug re-encodes with UTF-8 regardless.
5. **Alternative age implementations (pyrage / pyage)** — tested both: they emit the same structure (ASCII header, binary payload), so they cannot help.

### The key insight
Every failure pointed at one fact: **the binary payload of a standard age file cannot pass through a UTF-8 form field.** The author obviously *did* have a working client, so there had to be a spec-defined text transport. Reading the age spec's "ASCII armor" section revealed it: **PEM (RFC 7468) with the `AGE ENCRYPTED FILE` label**, implemented as `age --armor`. Once the blob was PEM-wrapped, the upload worked first try and the flag came back encrypted to my key.

### What a real attacker learns
- When a service accepts ciphertext through a text-only channel, check the crypto format spec for a *standard text encoding* before resorting to hacks — for age that is PEM armor, not base64-in-form-fields.
- The error message split (`missing pubkey file` vs `Could not decrypt`) is a useful behavioral oracle: it tells you whether your data even reached the decrypt step.

---

## 7. Flag

| # | Flag | Method |
|---|------|--------|
| 1 | `FLAG{h3r3s_y0ur_s3curely_transferred_fl4g}` | age PEM key exchange via `/upload` |

---

## Key Takeaways

- **`age -a/--armor` exists for a reason** — always use PEM armor when an age file must traverse a text-only transport (form fields, JSON, email, paste bins).
- **Specs beat guessing**: the 13-variant brute force of encodings was fast, but the answer was a single sentence in the age format spec.
- **Server-side decoder behavior is the constraint**: no amount of client-side encoding fixes corruption introduced by the server's own UTF-8 decode; find the format the server's parser was built to receive.
