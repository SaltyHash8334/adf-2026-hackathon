# Silent Route — CTF Writeup

**Category:** Forensics / SIGINT / GSM  
**Challenge:** ADF 2026 Hackathon  
**Author:** SaltyHash8334  
**Flag:** `HTB{T3T2_SDS_c0v3rt_K3strel_c2_ch4nn3l}`

## Overview

Coalition SIGINT collected a decoded GSMTAP export from a temporary Kestrel Dawn 2G microcell near a forward relay site. Most of the traffic is routine SMS control-plane chatter, but one multipart short message thread carries the mission token.

**Provided file:** `silentroute_capture.pcap` — 36 packets, ~6.65s capture duration

**Tools used:** Wireshark, tshark, Python

## Enumeration

### Initial Triage

```bash
$ capinfos silentroute_capture.pcap
File name:           silentroute_capture.pcap
Number of packets:   36
File size:           3,347 bytes
Capture duration:    6.650000 seconds
```

### Protocol Breakdown

```bash
$ tshark -r silentroute_capture.pcap -T fields -e frame.protocols | sed 's/:/\n/g' | sort | uniq -c | sort -rn
     36 udp
     36 lapdm
     36 ip
     36 gsmtap
     36 gsm_a.dtap
     36 eth
     18 gsm_a.rp
      9 gsm_sms
```

Every frame carries the full GSM stack: `eth:ip:udp:gsmtap:lapdm:gsm_a.dtap`. Of the 36 packets, 18 carry RP (Radio Protocol) layer and 9 are actual SMS TPDU (gsm_sms) — the other 9 are CP-ACK and RP-ACK acknowledgements.

### SMS Message Extraction

Extracting all SMS-DELIVER messages:

```bash
$ tshark -r silentroute_capture.pcap -Y "gsm_sms" -T fields -e frame.number -e gsm_sms.sms_text -e gsm_sms.tp-udhi -e gsm_sms.tp-oa
1	CHECK FUEL SOUTH GATE	True	447700900742
5	4854427B543354	True	447700900911
9	LZ GREEN	True	447700900701
13	325F5344535F63	True	447700900911
17	LZ GREEN,STANDBY H30	True	447700900701
21	30763372745F4B	True	447700900911
25	33737472656C5F	True	447700900911
29	63325F6368346E	True	447700900911
33	4854427B543354,325F5344535F63,30763372745F4B,33737472656C5F,63325F6368346E,6E336C7D	True	447700900911
```

**Key observations:**
- Three distinct originating numbers communicate:
  - `447700900742` — sends "CHECK FUEL SOUTH GATE" (frame 1)
  - `447700900701` — sends "LZ GREEN" and "LZ GREEN,STANDBY H30" (frames 9, 17)
  - `447700900911` — sends hex-encoded segments (frames 5, 13, 21, 25, 29, 33)
- All messages have `TP-UDHI = True` (User Data Header present)
- The hex segments from `447700900911` are obviously the mission token

## Exploitation — SMS Reassembly

The hex segments from `447700900911` form a **concatenated SMS** (GSM 03.40 8-bit reference number concatenation). Wireshark automatically reassembles these in frame 33, showing the complete reassembled message:

```
4854427B543354,325F5344535F63,30763372745F4B,33737472656C5F,63325F6368346E,6E336C7D
```

The concatenation header (from frame 33's dissection):
- **Information Element Identifier:** 0x00 (Concatenated short messages, 8-bit reference)
- **Message identifier:** 122
- **Total parts:** 6
- **Part sequence:** 1 (frame 5), 2 (frame 13), 3 (frame 21), 4 (frame 25), 5 (frame 29), 6 (frame 33)

Wireshark confirms the reassembly:
```
[6 Short Message fragments (73 bytes): #5(13), #13(13), #21(13), #25(13), #29(13), #33(8)]
[Frame: 5, payload: 0-12 (13 bytes)]
[Frame: 13, payload: 13-25 (13 bytes)]
[Frame: 21, payload: 26-38 (13 bytes)]
[Frame: 25, payload: 39-51 (13 bytes)]
[Frame: 29, payload: 52-64 (13 bytes)]
[Frame: 33, payload: 65-72 (8 bytes)]
[Reassembled Short Message length: 73]
```

## Flag Decoding

The reassembled message contains comma-separated hex segments. Concatenating and decoding:

```python
>>> segments = ['4854427B543354', '325F5344535F63', '30763372745F4B',
...             '33737472656C5F', '63325F6368346E', '6E336C7D']
>>> flag = bytes.fromhex(''.join(segments)).decode()
>>> print(flag)
HTB{T3T2_SDS_c0v3rt_K3strel_c2_ch4nn3l}
```

**Flag interpretation:**
- `T3T2` → TETRA (TETRA = Terrestrial Trunked Radio, stylized as T3T2)
- `SDS` → Short Data Service (TETRA's SMS equivalent)
- `c0v3rt_K3strel_c2_ch4nn3l` → Covert Kestrel C2 channel (Kestrel Dawn microcell = C2 infrastructure)

## How We Solved It — Reasoning

1. **Protocol identification:** The GSMTAP encapsulation immediately tells us this is a GSM Um interface capture from a microcell/BTS. All traffic uses SDCCH/8 (Standalone Dedicated Control Channel), which is the standard signaling channel for SMS delivery in GSM.

2. **SMS filtering:** Of 36 total packets, exactly half (18) carry RP-layer data and half are acknowledgements. The 9 SMS TPDU frames are SMS-DELIVER messages (MTI = 0), meaning they're mobile-terminated (network → phone).

3. **Identifying the target thread:** Three senders appear. `447700900742` and `447700900701` send plaintext operational messages ("CHECK FUEL SOUTH GATE", "LZ GREEN", "LZ GREEN,STANDBY H30"). `447700900911` sends only hex strings — clearly the data channel.

4. **Concatenation recognition:** All messages have TP-UDHI set, meaning they carry User Data Headers. The hex messages use the standard GSM 8-bit concatenation IE (0x00) with reference number 122 spanning 6 parts. This is the standard mechanism for SMS messages exceeding 140 octets (160 7-bit characters).

5. **Reassembly approach:** Wireshark's GSM SMS dissector handles concatenation automatically when all fragments are present in a single capture. Frame 33 (the last fragment) shows the fully reassembled message with all 73 bytes. Alternatively, the segments could be manually concatenated from frames 5, 13, 21, 25, 29, and 33.

6. **Hex decode:** The reassembled text is clearly hex-encoded (uppercase hex characters, predictable length). A simple `bytes.fromhex()` reveals the ASCII flag.

## Flags

| Flag | Location | Method |
|------|----------|--------|
| `HTB{T3T2_SDS_c0v3rt_K3strel_c2_ch4nn3l}` | SMS-DELIVER reassembled from frames 5,13,21,25,29,33 | Hex decode of concatenated SMS body |

## Caveats

- The GSM 7-bit default alphabet (`TP-DCS: 0`) is standard for SMS text. The hex payload fits within GSM 7-bit character set so decoding works correctly.
- Wireshark reassembles concatenated SMS fragments only when all parts are captured in the same file and properly sequenced — this capture was complete.
- The operational plaintext messages ("LZ GREEN" etc.) are environmental noise/context, not part of the flag. The flag is exclusively in the hex segments from `447700900911`.
