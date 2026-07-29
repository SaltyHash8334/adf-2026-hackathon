# Titan's View — ADF2026 Hackathon

**Category:** Signal Analysis / Forensics
**Flag:** `HTB{h1dd3n_l4nd1ng_s1t3_f0und}`

---

## 0. Summary

### Protocol
- **APT (Automatic Picture Transmission)** — analog image protocol used by weather satellites
- 2400 Hz AM subcarrier modulated with image brightness data
- Two channels (A/B) time-multiplexed per line, 0.5s per full line
- Telemetry/calibration strips on both edges of each channel

### Critical Findings
- The audio file is **stereo**: right channel carries the 2400 Hz AM signal, left channel is low-level noise
- **AM envelope detection** (Hilbert transform magnitude) of the right channel produces visible satellite imagery
- **FM demodulation** of the right channel reveals sync pulses at 0.25s intervals (sync A + sync B per line)
- The decoded image shows Mars-like terrain with calibration telemetry strips
- A **text flag** is overlaid in the telemetry region of Channel B (rows ~441–471)

### Security Implications
- Analog space telemetry protocols remain unencrypted and susceptible to interception
- Hidden data can be embedded in calibration/telemetry frames that are normally ignored by standard decoders

---

## 1. Signal Reconnaissance

### File Properties

```bash
file "challenge.wav"
# RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 11025 Hz
```

- **Duration:** 454.46 seconds (~7.5 minutes)
- **Channels:** 2 (stereo)
- **Sample Rate:** 11025 Hz
- **Bit Depth:** 16-bit PCM

### Channel Analysis

```python
import wave, numpy as np
w = wave.open("challenge.wav")
data = np.frombuffer(w.readframes(w.getnframes()), dtype=np.int16).reshape(-1, 2)
left, right = data[:, 0].astype(np.float64), data[:, 1].astype(np.float64)

# Right channel: full dynamic range (-32759 to 32767) — the signal
# Left channel: very low amplitude (-3498 to 3182) — likely demodulated or noise
# L/R correlation: ~0.001 (independent channels)
```

---

## 2. Protocol Identification

### Spectral Analysis

```python
from scipy import signal
f, Pxx = signal.welch(right[:int(fs*30)], fs, nperseg=4096)
# Dominant carrier: 2401 Hz (77.8 dB)
```

The right channel has a strong carrier at **2400 Hz** — this is the standard APT subcarrier frequency used by NOAA weather satellites.

### Sync Detection via FM Demodulation

```python
analytic = signal.hilbert(right)
inst_freq = np.diff(np.unwrap(np.angle(analytic))) * fs / (2 * np.pi)
# Median frequency: 2400 Hz, deviation: ±45 Hz (tight FM)
```

FM demodulation reveals sync pulses with tight frequency deviations at the sync boundaries. Peak detection finds **1819 sync pulses** at **0.250s intervals** — this matches the APT half-line timing (sync A + sync B = 0.5s full line).

### Protocol Confirmation

| Observation | APT Specification | Match |
|---|---|---|
| Carrier frequency | 2400 Hz | ✓ |
| Line sync interval | 0.25s (half-line) / 0.5s (full line) | ✓ |
| Modulation type | AM (amplitude modulation of subcarrier) | ✓ |
| Two image channels | Channel A / Channel B visible/infrared | ✓ |
| Telemetry strips | Calibration wedges + sync bars on edges | ✓ |

**Identified protocol: NOAA APT (Automatic Picture Transmission)**

---

## 3. Image Decoding

### Method 1: Custom AM Demodulation

```python
analytic = signal.hilbert(right)
envelope = np.abs(analytic)  # AM demodulation

# Sync from FM domain
inst_freq = np.diff(np.unwrap(np.angle(analytic))) * fs / (2*np.pi)
peaks, _ = find_peaks(np.abs(inst_freq - 2400), height=threshold, distance=int(fs*0.15))

# Extract lines between sync peaks, resample to fixed width
lines = [envelope[peaks[i]:peaks[i+1]] for i in range(len(peaks)-1)]
```

This produced a recognizable satellite image with terrain and telemetry strips, confirming the protocol.

### Method 2: apt-decoder (zacstewart/apt-decoder)

Used the Python APT decoder with modifications:
1. Resampled right channel to 20800 Hz (decoder requirement)
2. Fixed `PIL.Image` import and int16 overflow bugs
3. Produced optimal output: **2080×908 pixels** with clear channel separation

```bash
cd /tmp/apt-decoder
python3 apt.py resampled_20800.wav apt_output.png
# Output: 2080x908 grayscale PNG, Channel A (left) + Channel B (right)
```

### Decoded Image Structure

```
| Sync | Channel A Video | Telemetry A | Sync | Channel B Video | Telemetry B |
|<--------- 1040 px --------->|<--------- 1040 px --------->|
|<------------------------ 2080 px ------------------------>|
```

---

## 4. Flag Extraction

### Text Region Detection

High row-variance analysis on Channel B revealed an anomalous region at **rows 441–471** (31 rows of unusual pixel variance), far exceeding the background terrain variation.

```python
row_var = np.var(channel_b, axis=1)
# Channel B anomaly: rows 441-471 (variance > mean + 2σ)
# Channel A anomaly: rows 379-407 (weaker)
```

### Flag Reading

Multiple threshold levels (70–90th percentile) were used to binarize the text region. The overlaid text reads:

```
HTB{h1dd3n_l4nd1ng_s1t3_f0und}
```

**Translation (leetspeak):** "hidden landing site found"

### Character Verification

The text region contains ~30 character-like objects spanning columns 118–932, with consistent ~15–20px spacing. The HTB flag format was independently confirmed by the `Uncoding` challenge writeup in the same CTF.

---

## 5. How We Solved It — Reasoning

### Initial Hypotheses

1. **SSTV (Slow Scan Television):** Rejected — the tight 2400 Hz carrier and 45 Hz FM deviation don't match any SSTV mode (which uses 1500–2300 Hz for luminance). Standard SSTV modes produce much smaller images over ~2 minutes; this signal is 7.5 minutes.

2. **Digital FSK:** Rejected — the frequency between sync pulses varies continuously (analog), not in discrete levels. FSK decoding produced only garbage ASCII.

3. **APT (Automatic Picture Transmission):** **Confirmed** — 2400 Hz carrier, AM modulation, 0.25s half-line sync, two image channels with telemetry strips, and recognizable satellite terrain imagery.

### Key Evidence Correlation

| Evidence | Interpretation |
|---|---|
| Right channel envelope = satellite image | AM demodulation is correct |
| Right channel FM = sync structure | FM domain carries timing, AM domain carries data |
| Left channel = noise | Left channel is irrelevant (possibly demod residue) |
| 0.25s sync interval | Half-line APT timing (sync A → sync B) |
| Two visible image channels | Channel A and B multiplexed |
| Text in Channel B rows 441–471 | Flag embedded in telemetry overlay |

### Key Insight

The flag was hidden in the **telemetry overlay region** of the image — the portion that normally contains calibration wedges and instrument data. Standard APT decoders render this as graphical data, but the challenge authors overlaid text in this region. The full 2080-pixel width from the apt-decoder was essential — lower-resolution reconstructions (320–909 px) lost the character detail.

### Rejected Hypotheses

- **Left channel as second image:** Produced pure noise images
- **LSB steganography:** No readable ASCII in pixel LSBs
- **Sync pulse height encoding:** Peak height quantization produced garbage
- **IQ demodulation (left=I, right=Q):** Constellation showed no PSK structure

---

## 6. Tools Used

- **Python:** `numpy`, `scipy.signal` (Hilbert transform, filtering, peak detection)
- **apt-decoder:** `zacstewart/apt-decoder` (modified for PIL import and overflow fixes)
- **PIL/Pillow:** Image construction and enhancement
- **Signal analysis:** FM demodulation via Hilbert phase unwrapping, AM demodulation via Hilbert magnitude

---

## Appendix: Required Decoder Fixes

The `apt-decoder` had two bugs that required patching:

1. **Import:** `import PIL` → `from PIL import Image as PILImage`
2. **Integer overflow:** `x-128 for x in signal` → `int(x)-128 for x in signal` (int16 subtraction overflows)