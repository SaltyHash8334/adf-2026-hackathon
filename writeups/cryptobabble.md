# CryptoBabble — ADF2026 Hackathon

**Category:** Cryptanalysis
**Flag:** `FLAG{STEGINSANE}`

---

## 0. Summary

### Access & Environment
- Single text file: `strings.txt` (119 bytes) in `CryptoBabble/`
- Challenge category: **Cryptanalysis** — "We're given a weird gibberish string. Could you try and decipher it?"

### Critical Findings
- The file contains **10 invented "babble" words** that are mostly real-English-shaped but meaningless as a sentence.
- The **first letter of each word**, taken in order, spells `GHSUWBGOBS`.
- A single **Caesar shift of +12 (ROT-12)** converts that to **`STEGINSANE`** — the only shift that yields readable text, and the flag message itself.
- The blank line after the 4th word splits the decode into **"STEG"** (positions 1–4) and **"INSANE"** (positions 5–10) — "STEG" being the author's nod to the steganographic nature of the trick.

### Security Implications
- The words are a **steganographic container**: they look like plausible English ("germinating hyperbolical squelching undulations…") while silently carrying the real payload in their initial letters. This is a classic covert-channel pattern — human-readable cover text with a hidden bit/letter channel — and the same trick works in phishing lures and obfuscated configs where "noise that looks normal" is exactly what defenders filter out.

---

## 1. Initial Inspection

**Code:**
```bash
file strings.txt
cat strings.txt
```

**Output:**
```
....germianting hyperbolical squelching undulations

wabbling bamboozle! germinating orbish blinkoggles solemnly..
```

**Description:**
- The string is framed by `....` (4 dots) at the start and `..` + 4 trailing spaces at the end — pure noise/decoration, not part of the message.
- 10 words, almost all of which are real or near-real English: `germianting` (a transposition of `germinating`, which also appears as word 7!), `hyperbolical`, `squelching`, `undulations`, `wabbling`, `bamboozle`, `germinating`, `orbish` (not a word), `blinkoggles` (not a word), `solemnly`.
- A "sentence" of random dictionary-sounding words with no grammar = classic **babble/gibberish generator** output — exactly what the challenge name advertises.

---

## 2. Extracting the First Letters

**Code:**
```bash
python3 -c "
import re
words = re.findall(r'[a-z]+', open('strings.txt').read())
print(len(words), words)
print(''.join(w[0] for w in words).upper())
"
```

**Output:**
```
10 ['germianting', 'hyperbolical', 'squelching', 'undulations', 'wabbling', 'bamboozle', 'germinating', 'orbish', 'blinkoggles', 'solemnly']
GHSUWBGOBS
```

**Description:**
- Since the words themselves are meaningless, the payload must be a derived channel. The natural first probe: the **first letter of each word** → `GHSUWBGOBS`.

---

## 3. Caesar Brute Force

**Code:**
```bash
python3 -c "
first = 'ghsuwbgobs'
for s in range(26):
    dec = ''.join(chr((ord(c)-97+s)%26+97) for c in first)
    print(f'ROT+{s:2d}: {dec.upper()}')
"
```

**Output (relevant rows):**
```
ROT+ 0: GHSUWBGOBS
ROT+11: RSDFHMRZMD
ROT+12: STEGINSANE   <- the only readable result
ROT+13: TUFHJOTBOF
...
```

**Description:**
- Classic Caesar brute force: of all 26 shifts, exactly **ROT-12** produces readable text: `STEGINSANE`.

---

## 4. Decoding

- First letters: `G H S U W B G O B S`
- ROT-12: `S T E G I N S A N E` → **`STEGINSANE`**
- The blank line in the original file sits after word 4, i.e. after the 4th letter — splitting the phrase as **`STEG` | `INSANE`**.

---

## 5. How We Solved It — Reasoning

### Initial Observations
The words are "babble" — most are real words but the sentence is nonsense, and two words (`orbish`, `blinkoggles`) plus one transposition (`germianting` for `germinating`) are clearly invented. A sentence whose words are individually plausible but collectively meaningless is the signature of a **word-level stego container**: the payload lives in a per-word channel, not in the words themselves.

### Key Discoveries
1. **First-letter channel**: `GHSUWBGOBS` — the first letters read cleanly as a 10-char ciphertext string.
2. **Unique Caesar hit**: Only ROT-12 decodes to readable text (`STEGINSANE`). Any cipher with a constant key (Caesar, affine with a=1, ROT-N) collapses to this; all 25 other shifts produce garbage, so the result is unambiguous.
3. **Blank-line framing**: the author inserted a blank line after the 4th word — i.e. after `S T E G` — marking the phrase as "**STEG** INSANE": the steg(anography) is *in the insane (babble) words*. `STEGINSANE` is the flag message.

### Rejected Hypotheses
- **Words as Morse (vowels=dot / consonants=dash)**: Exhaustively tried both mappings with a dictionary-constrained segmenter — the decoded streams (`TATEETTATOET…`, `EDTTINESTINT…`) are pure noise. Ruled out.
- **Baconian (real-vs-fake word split)**: 10 words = 2×5-bit groups; every classification tried (dictionary membership, vowel parity, length parity, contains-'g', 'ing'-suffix, double letters) yields non-ASCII garbage. Ruled out.
- **Length-based binary / A1Z26**: lengths `11 12 10 11 8 9 11 6 11 8` map to no readable sequence under any parity/threshold split (and 10 words ≠ a whole number of bytes). Ruled out.
- **Anagram unscrambling**: `germianting` is an anagram of `germinating`, but the other words are already real words and `orbish`/`blinkoggles` have no dictionary anagrams; no hidden channel there. Ruled out.
- **Whitespace/zero-width stego**: hexdump shows only `....`, `..`, 4 trailing spaces, and a blank line — 10-11 bits total, too few for a flag and non-ASCII under every bit assignment. Ruled out.

### Key Insight
The challenge name is the hint: "babble" words are just **cover text**. Once you treat the words as containers instead of ciphertext, the first-letter string appears immediately, and one Caesar brute-force pass finishes it — the same way `strings`-style scanning would miss a payload hidden in the *first characters* of dictionary-looking tokens.

---

## 6. Flag

```
FLAG{STEGINSANE}
```
