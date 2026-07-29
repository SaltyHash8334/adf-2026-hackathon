# Analog Lifeline — CTF Writeup

**CTF:** Cyber Apocalypse 2026 (ADF Hackathon)
**Category:** Hardware / Radio
**Challenge:** Analog Lifeline
**Flag:** `HTB{1709301337}`

---

## Scenario

> We've hacked an Eastern Union station, but they disabled the auto-tracking. Manually control the antenna to intercept their military orders from the Titan Link satellite before the connection is lost.

Target: `154.57.164.71:32259` (respawned at `154.57.164.82:32618`)

---

## How We Solved It — Reasoning

### Phase 1: Understanding the Challenge

The target hosted a satellite ground station web UI with:
- Manual antenna control (azimuth 0-360°, elevation 0-90°)
- Scheduled antenna control (JSON-based schedule upload)
- Time speed control (1x to 3600x)
- Real-time Socket.IO tracking updates for COSMOS 1371
- TLE data provided in the tracking stream

The web interface showed auto-tracking was disabled. We needed to manually point the dish at COSMOS 1371 to intercept communications from the "Titan Link" satellite.

### Phase 2: Reconnaissance & Failed Approaches

**Spent significant time on dead ends:**

1. **Schedule system**: Uploading schedules returned HTTP 200 but the antenna never moved according to schedule entries. The schedule executor was non-functional — a known pitfall on the challenge server.

2. **Manual tracking without `new_rec`**: We achieved near-perfect manual tracking (<0.3° error) through multiple complete satellite passes at 1x speed. The `new_rec` field never became `true`. The server state on the original instance was corrupted — `gs_conn` was permanently `true` and `new_rec` never fired.

3. **Guessing PIN candidates**: Tried dozens of numeric PINs derived from TLE data (NORAD ID 13241, inclination 740422, satellite number 1371, etc.) — all incorrect.

### Phase 3: Key Breakthrough — Time Reversal & Server Reset

We discovered that the `/api/time_control` endpoint accepted **negative speed values** (`"speed": -3600`), allowing us to reverse simulated time. Going back before the server start time (`ts=1748806550`) crashed the instance.

When the challenge respawned at a new address (`154.57.164.82:32618`), we connected immediately to a **fresh server state**:

| Field | Old (corrupted) | New (fresh) |
|---|---|---|
| `gs_conn` | Always `True` | Starts `False` |
| `new_rec` | Never triggered | Triggers on tracking |
| Logs | Spammed with "1x" messages | Only 3 clean log entries |

### Phase 4: Successful Interception

On the fresh server at 1x speed:
1. We located the first satellite pass using skyfield orbit propagation from the TLE
2. Fast-forwarded to just before the pass at 3600x, then switched to 1x
3. Manually tracked the satellite through the pass, updating antenna position on every Socket.IO `tracking_update` event
4. `gs_conn` changed from `False` → `True` when the antenna locked on
5. After 52 seconds of tracking, `new_rec` became `true`!

The `tracking_update` event contained a new log entry:
```
"52 seconds of recorded data stored in cosmos1371_2025-06-01_26a909a1-ef55-46a6-83d5-1dad4807e80b_wfm_250k.iq
<a href='/api/recordings/cosmos1371_2025-06-01_26a909a1-ef55-46a6-83d5-1dad4807e80b_wfm_250k.iq'>Download</a>"
```

### Phase 5: Signal Processing — The "Analog Lifeline"

We downloaded the 52 MB IQ (In-phase/Quadrature) recording. The filename indicated "wfm_250k" — Wideband FM at 250 kHz sample rate.

**Signal analysis:**
- 6,500,000 float32 I/Q sample pairs
- Actual sample rate: 125 kHz (matching the "52 seconds" in the log)
- FM demodulation: extracted instantaneous frequency via phase differentiation
- Decimated to 8 kHz for voice-quality audio

**Key insight**: The log message said "52 seconds" but at 250 kHz the file was only 26 seconds. Using 125 kHz sample rate produced exactly 52 seconds of audio — matching the log.

**FM demodulation:**
```python
phase = np.unwrap(np.arctan2(q, i))
freq = np.diff(phase) * 125000 / (2 * np.pi)
# Decimate to 8 kHz for voice
```

The demodulated audio (`voice_8k.wav`) contained clear voice transmission:

> **"UB31 calling DW96, confirmation code is given as 1709301337"**

### Phase 6: Flag Extraction

The confirmation code `1709301337` is the PIN.

**Flag: `HTB{1709301337}`**

## Key Tools Used

- **skyfield**: TLE orbit propagation for pass prediction
- **socket.io-client**: Real-time tracking data stream
- **numpy/scipy**: IQ signal processing, FM demodulation
- **Python urllib**: API interaction (antenna control, time manipulation)
- **Reversed time travel**: Negative speed values to control simulation time

## Lessons Learned

1. **Server state persistence matters**: The original instance had corrupted state from prior use. A fresh instance was essential.
2. **Negative speed is a feature**: The time control API accepted negative values, enabling time reversal — useful for navigating the simulation but dangerous (crashed the first instance).
3. **`gs_conn` is the real tracking indicator**: On a fresh server, `gs_conn` changes from `False` → `True` when the antenna locks onto the satellite.
4. **The "Analog" in "Analog Lifeline" refers to analog RF signal processing**: The challenge culminated in decoding a wideband FM IQ recording to extract spoken audio.
5. **Sample rate matters**: The WAV filename said "250k" but the actual sample rate was 125 kHz, determined by matching the file duration to the log message.