# Server Lookup — ADF2026 Hackathon Writeup

## Challenge Overview

- **Challenge**: Server Lookup
- **Category**: Network Forensics / Traffic Analysis
- **Files**: `capture.pcap`
- **Prompt**: *"Lately, our alarm system has been ringing more than usual... And also, our IDS has detected some suspicious traffic coming from a station. We think these two incidents may be related and someone is stealing our access codes. Given the captured traffic, can you pinpoint the exfiltration method and data?"*

---

## Summary

**Exfiltration Method**: DNS tunneling — data encoded as hex strings in A-record DNS queries, exfiltrated to a rogue DNS server at `192.168.1.180`.

**Exfiltrated Data**: An internal email (`it@corp.local → everyone@corp.local`) with subject "Access Codes", containing a ZIP attachment (`access_codes_2023.zip`) with a PDF file (`Building_Access_Codes_-_2023.pdf`).

**Flag**: `HTB{3xf1ltr4t1ng_w1th_DNS_1s_s0_fun!!}` (embedded in the PDF)

**Access Codes**:
- Main Entrance: `6819`
- Back Entrance: `1263`
- Employees Lounge: `HTB{3xf1ltr4t1ng_w1th_DNS_1s_s0_fun!!}`
- Workshop: `5710`

---

## How We Solved It — Reasoning

### Initial Triage

Opening the pcap immediately revealed a massive number of DNS queries — 4,740 DNS packets out of 5,301 total. The queries looked unusual:

```
192.168.1.163 → 192.168.1.180 : A? 46726f6d3a20697440636f72702e6c6f
```

The queried "domain names" were all 32-character hex strings. Classic DNS exfiltration — data is being smuggled out inside DNS query names. Every query receives the same response (`A 192.168.1.180`), confirming a rogue DNS server acting as C2.

### Hypothesis 1: Just Hex-Decode

**Tested**: Decoded each hex query name concatenated in time order.
**Result**: Produced a full SMTP email with MIME headers, a plain-text body, and a base64-encoded ZIP attachment.

### Hypothesis 2: Extract the ZIP

**Tested**: Extracted the base64 block between `Content-Transfer-Encoding: base64` and `--boundary_string--`.
**Pitfall encountered**: Base64 alignment issues after concatenating individual hex queries (each query = 32 hex chars = 16 bytes of base64). The `=` padding character was part of the stream and needed careful handling.
**Result**: Decoded to a valid ZIP containing `Building_Access_Codes_-_2023.pdf` (29,995 bytes uncompressed, 1 page, PDF 1.4).

### Hypothesis 3: PDF Text Extraction

**Tested**: `pdftotext` returned nothing — the PDF uses CID-encoded fonts with a ToUnicode CMap. Manual extraction of the PDF content stream revealed hex-encoded character IDs:

```
<00250058004C004F0047004C0051004A00030024004600460048005600560003002600520047004800560003001000030015001300150016> Tj
```

Decoding each 4-hex-digit CID with an offset of +29 mapped perfectly to ASCII:

| CID (hex) | CID (dec) | +29 | Char |
|-----------|-----------|-----|------|
| 0025 | 37 | 66 | B |
| 0058 | 88 | 117 | u |
| 004C | 76 | 105 | i |
| ... | ... | ... | ... |

This produced "Building Access Codes - 2023" for the title segment. The same offset decoded the flag from the "Employees Lounge:" field.

### Key Insight

The CID → ASCII offset of **+29** was discovered by aligning known text: the filename "Building_Access_Codes_-_2023.pdf" matches the document title, and `0x25 → 'B'` (66 - 37 = 29). This held for all characters including digits, punctuation, and braces.

---

## Technical Walkthrough

### Phase 1: Traffic Analysis

```bash
# Overview
capinfos capture.pcap
# 5,301 packets, 742 KB, ~1 hour capture

# Protocol breakdown
tshark -r capture.pcap -T fields -e frame.protocols | sed 's/:/\n/g' | sort | uniq -c | sort -rn
# 4,740 DNS packets (dominant)
# 256 SSDP, 178 TCP, 106 TLS — background noise

# DNS pattern
tcpdump -r capture.pcap -nn 'udp port 53' | head -20
# All queries: 192.168.1.163 → 192.168.1.180 with hex subdomains
# All responses: A 192.168.1.180
```

### Phase 2: Extracting DNS Exfiltrated Data

```bash
# Extract all DNS A-record queries in time order
tshark -r capture.pcap -Y 'dns.flags.response eq 0 and dns.qry.type eq 1' \
  -T fields -e frame.time_epoch -e dns.qry.name | sort -t$'\t' -k1 -n | cut -f2 \
  > all_queries.txt

# Decode hex concatenation
python3 -c "
data = b''
with open('all_queries.txt') as f:
    for line in f:
        data += bytes.fromhex(line.strip())
open('decoded.bin', 'wb').write(data)
"
```

### Phase 3: Reconstructing the Email

The decoded data revealed:

```
From: it@corp.local
To: everyone@corp.local
Subject: Access Codes
X-Priority: 1
Importance: high
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary_string"

--boundary_string
Content-Type: text/plain

Dear employees,

I hope this email finds you well.
I wanted to inform you all that we will be changing the building access
codes effective immediately. The new codes are found in the attached
document. Please make sure to memorize these codes and discard any old
access cards that you may have.

...

--boundary_string
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="access_codes_2023.zip"
Content-Transfer-Encoding: base64

<36,536 chars of base64>
```

### Phase 4: Extracting the ZIP

```python
import re, base64

text = open('decoded.bin', 'rb').read().decode('utf-8', errors='replace')
match = re.search(r'Content-Transfer-Encoding: base64\n\n(.+?)(?=\n--boundary_string--)', text, re.DOTALL)
b64_clean = re.sub(r'\s+', '', match.group(1))
padding = (4 - len(b64_clean) % 4) % 4
zip_data = base64.b64decode(b64_clean + '=' * padding)

with open('access_codes_2023.zip', 'wb') as f:
    f.write(zip_data)

# Result: 27,401 byte valid ZIP
```

### Phase 5: Decoding the PDF

The PDF uses CID-encoded text with font F4 and Adobe-Identity-UCS CMap. Content stream 0 contains hex-encoded text:

```python
import re, zlib

with open('Building_Access_Codes_-_2023.pdf', 'rb') as f:
    data = f.read()

# Parse FlateDecoded streams
streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', data, re.DOTALL)
for s in streams:
    try:
        decoded = zlib.decompress(s).decode('latin-1')
    except:
        decoded = s.decode('latin-1', errors='replace')
    
    # Extract CID hex text
    for match in re.finditer(r'<([0-9A-Fa-f]+)>\s*Tj', decoded):
        cids = [int(match.group(1)[i:i+4], 16) for i in range(0, len(match.group(1)), 4)]
        text = ''.join(chr(c + 29) for c in cids)  # offset +29
        print(text)
```

**Output**:
```
Building Access Codes - 2023
1
Dear all,
As per our last email, please find below the new access codes for the company building:
Main Entrance: 6819
Back Entrance: 1263
Employees Lounge: HTB{3xf1ltr4t1ng_w1th_DNS_1s_s0_fun!!}
Workshop: 5710
As always full confidentiality and discretion is advised!
```

---

## Indicators of Compromise (IOCs)

| Indicator | Value | Notes |
|-----------|-------|-------|
| Rogue DNS Server | `192.168.1.180` | MAC: `e0:4f:43:f7:13:5e` |
| Compromised Host | `192.168.1.163` | MAC: `08:00:27:75:8c:7f` (VirtualBox) |
| C2 Protocol | DNS A-record tunneling | 50-byte hex payload per query |
| Exfiltration Rate | ~1 query/1.6 sec | ~16 bytes/sec |
| Data Exfiltrated | Email + ZIP attachment | 37,896 bytes total |
| Capture Window | 2023-01-11 03:01:15 to 04:05:09 AEDT | ~64 minutes |

---

## Security Implications

1. **DNS tunneling bypasses most firewalls** — DNS is rarely blocked or inspected deeply. The exfiltration used standard A-record queries that look legitimate at a glance.

2. **The attachment was the real target** — The email body was just a decoy. The ZIP contained sensitive access codes for the building, which explains the "alarm system ringing more than usual."

3. **No encryption needed** — The attacker encoded data as hex, which stands out to anyone looking, but DNS over port 53 to an internal IP (`192.168.1.180`) wouldn't trigger default IDS rules.

4. **Mitigation**: Implement DNS query logging and anomaly detection (entropy analysis on query names, rate limiting per client, DNSSEC validation against known forwarders).