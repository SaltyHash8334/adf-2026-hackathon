# Ghost Track

## Challenge Overview

**Scenario:** An attacker can write to the ASTERIX data concentrator feeding the Ramstein AOC Common Air Picture. The objective is a two-phase injection attack against the Cat 048 relay.

**Targets:**

- Dashboard: `154.57.164.70:31226`
- ASTERIX relay: `154.57.164.70:31534`

The relay exposed a live Cat 048 stream and accepted attacker-supplied frames on the same TCP connection.

## How We Solved It — Reasoning

The key was to treat the relay as a TCP byte stream rather than assuming the dashboard was the attack surface. The dashboard source disclosed a WebSocket endpoint, `/ws/radar`, which provided a convenient independent verification channel containing current tracks, injected-track state, and phase flags.

The relay initially returned repeated 35-byte messages. Parsing them using the normal ASTERIX header—one-byte category followed by a two-byte big-endian length—produced a clean stream of Category 048 frames:

```text
CAT = 0x30 (48)
LEN = 0x0023 (35)
```

Comparing frames across time showed that the changing fields were track update data. The live source was `SAC/SIC 01/01`; the challenge explicitly warned that this legitimate source was trusted and ignored by the ballistic detector. Therefore, merely modifying a legitimate frame's kinematics was insufficient: the source bytes also had to be foreign.

A first controlled modification confirmed the injection path. Changing the source from `01/01` to `02/99` caused the dashboard to show a new injected track, proving that the relay accepted foreign Cat 048 messages. This also exposed an important pitfall: the stream's message length and ASTERIX layout had to remain valid, while the modified fields had to preserve enough structure for the relay's decoder.

The dashboard's state showed the exact phase conditions indirectly. After Phase 1, the relay banner reported:

```text
>>> THREATCON ALPHA (ACTIVE) <<<
PHASE 2 IN PROGRESS: 1/50 SQUAWK CODES
INJECT >= 50 UNIQUE SQUAWK CODES (NON-LEGIT SOURCE)
```

That ruled out a hypothesis that Phase 2 required many tracks or high-rate flooding. It required at least 50 distinct Mode 3/A squawk values from a non-legitimate source.

## Phase 1 — PHANTOM LANCE

### Frame observations

The stable parts of a normal Cat 048 frame included:

```text
30 00 23             # category 48, length 35
fd d6                # live FSPEC bytes
01 01                # legitimate SAC/SIC
...
04 22 05 28          # ordinary track data / identity fields
30 00 01            # ICAO address in the observed frame
...
```

Rather than inventing a complete ASTERIX encoder, I used a valid live frame as a template and changed only the fields required by the scenario:

- foreign source address, `SAC/SIC = 02/99`;
- a foreign ICAO address, `DE AD B1`;
- Mode 3/A squawk `7777`;
- high altitude and high speed;
- a foreign-track position/range sequence moving toward Ramstein;
- a steep descending profile over successive injected frames.

The injected sequence used approximately:

| Sample | Range | Altitude | Speed | Heading | Squawk |
|---:|---:|---:|---:|---:|---:|
| 0 | 140.0 NM | 120,000 ft | 4,500 kt | 180° | 7777 |
| 8 | 72.0 NM | 64,000 ft | 4,500 kt | 180° | 7777 |
| 15 | 12.5 NM | 15,000 ft | 4,500 kt | 180° | 7777 |

The relay accepted the frames and returned the normal stream. The dashboard WebSocket independently showed the injected track as `INJ0777`, with the foreign address `DEADB1`, 4,500 kt, heading 180°, and the expected closing range. The legitimate `01/01` source was not used for the attack track.

### Phase 1 verification

The relay's state changed to:

```text
phase1_done = true
phase2_done = false
p1_squawk   = 0777
p2_count    = 1
```

The relay also exposed the active-threat banner, confirming that the detector—not merely the track renderer—had fired.

## Phase 2 — CORRELATOR BLACKOUT

Once Phase 1 was active, I sent 50 additional valid-length Cat 048 frames. Each used:

- a foreign SAC/SIC, with the SIC varied per frame;
- a unique squawk value;
- otherwise-valid template fields, so the relay would parse them as track reports.

The exact squawk-generation code used unique four-nibble values while keeping the data in the expected Mode 3/A field shape:

```python
words = []
for i in range(50):
    d1 = 1 + (i // 10)
    d2 = (i // 10) % 8
    d3 = (i // 3) % 8
    d4 = i % 8
    words.append((d1 << 12) | (d2 << 8) | (d3 << 4) | d4)
```

Each generated frame retained the Cat 048 category and 35-byte length. I drained the relay between sends to avoid confusing the live server-to-client stream with acknowledgements or causing a socket backlog.

### Phase 2 verification

The dashboard WebSocket reported:

```text
phase1_done = true
phase2_done = true
p1_squawk   = 0777
p2_count    = 50
```

A fresh connection to the relay returned the completion banner and token:

```text
>>> BLACKOUT ALREADY COMPLETE <<<

AUTHENTICATION TOKEN: HTB{4ST3R1X_ph4nt0m_l4nc3_bl4ck0ut}
```

## Flag

```text
HTB{4ST3R1X_ph4nt0m_l4nc3_bl4ck0ut}
```

## Key Lessons

1. Parse the TCP stream with the ASTERIX category/length header before mutating data.
2. The trusted source check is a decisive constraint: use a foreign SAC/SIC for injected frames.
3. Preserve a valid frame template while changing only the kinematic and identity values needed by the detector.
4. Use the dashboard WebSocket as an independent verification oracle, not as the injection mechanism.
5. Phase 2 is a uniqueness condition—50 distinct non-legitimate squawks—not simply a packet-volume condition.
6. Drain the relay output while injecting because it continues streaming legitimate Cat 048 traffic.

## Reproduction Summary

```text
1. Connect to 154.57.164.70:31534.
2. Capture a valid 35-byte Cat 048 frame.
3. Change SAC/SIC to a foreign source and inject a descending, high-speed, closing ballistic profile with squawk 7777.
4. Confirm `phase1_done` through `ws://154.57.164.70:31226/ws/radar`.
5. Send 50 valid Cat 048 frames with unique squawks and foreign source addresses.
6. Confirm `phase2_done` and read the completion banner from the relay.
```

## Evidence Collected

- Live relay stream parsed into 35-byte Cat 048 messages.
- Controlled foreign-source injection created an `injected: true` track in the dashboard state.
- Phase 1 state was independently observed through the dashboard WebSocket.
- Phase 2 state was independently observed as `p2_count = 50`.
- The final token was returned directly by the relay's completion banner.
