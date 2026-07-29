# Raven Signal — Writeup

**Challenge:** Raven Signal  
**Category:** Signals Intelligence / Radio  
**Platform:** Hack The Box — ADF 2026 Hackathon  
**Flag:** `HTB{SSTV_R4v3n_S1gn4L_1nt3rc3pt}`

---

## Challenge Overview

Coalition signals intelligence detected an anomalous narrowband transmission on **137.500 MHz**, associated with the fictional "Kestrel Dawn" covert satellite downlinks. Two files provided:

| File | Description |
|------|-------------|
| `satellite_capture.iq` | Raw IQ data (85 MB, 115.2 seconds) |
| `satellite_capture.sigmf-meta` | SigMF metadata |

**SigMF Metadata:**
- Data type: `cf32_le` (complex float32, little-endian)
- Sample rate: 96,000 Hz
- Center frequency: 137.500 MHz
- Duration: 115.2 seconds (~11M samples)

---

## How We Solved It — Reasoning

### Phase 1: Initial Signal Reconnaissance

**Hypothesis 1: NOAA APT** — 137.500 MHz is near NOAA weather satellite frequencies. APT uses a 2400 Hz AM subcarrier.
→ **Rejected:** Zero energy at 2400 Hz. Dominant carrier at 1500 Hz.

**Hypothesis 2: SSTV** — The 137 MHz band carries amateur SSTV from satellites/ISS.
→ **Confirmed.**

### Phase 2: Key Signal Properties

IQ analysis revealed:
- **Constant envelope:** Magnitude = 1.0, std ≈ 0 → rules out AM, confirms FM/PM
- **FM demodulation:** Mean instant frequency ≈ 10 kHz (carrier offset), std ≈ 3.5 kHz deviation
- **Baseband spectral peaks after DC removal:**

| Frequency | Energy | Meaning |
|-----------|--------|---------|
| 1200.0 Hz | 4,069 | Sync tone |
| 1500.0 Hz | 172,804 | Black level (dominant) |
| 1898.4 Hz | 41,982 | VIS start tone |
| 1687.5 Hz | 77,441 | Modulation sideband |
| 1523.4 Hz | 50,807 | Modulation sideband |

Zero energy at 2400 Hz confirmed this was NOT NOAA APT.

### Phase 3: Protocol Identification — Martin M1 SSTV

Spectrogram analysis showed classic SSTV structure:
- **VIS header** at t ≈ 0.7–0.9s: 1900 Hz leaders, 1200 Hz breaks, 8-bit digital code
- **Sync pulses** at 1200 Hz: 4.862ms duration, ~150ms intervals (between color scans)
- **Three color channels per line:** Green → Blue → Red sequential (Martin mode characteristic)

VIS code decoded to **44 decimal = Martin 1** (confirmed by `sstv` package VIS_MAP).

**Martin M1 timing match:**
- Resolution: 320 × 256 pixels
- Per-line: 3 × (4.862ms sync + 146.432ms scan) = 453.9ms
- Total: 256 × 453.9ms ≈ 116.2s → matches our 115.2s capture

### Phase 4: SSTV Decoding

Used `colaclanth/sstv` Python package with two bug fixes:
1. `get_terminal_size()` fails in non-TTY → fallback to 80 columns
2. `SSTVDecoder.close()` expects file object → handle string paths

**Pipeline:**
```
IQ data → FM demod (d(phase)/dt) → HPF (remove 10 kHz carrier)
→ LPF (3 kHz anti-alias) → sstv.decode() → 320×256 PNG
```

---

## Decoded Image

The decoded Martin M1 image shows a military HUD overlay:

```
RAVEN-6 // ISR FEED // KESTREL DAWN
LAT: 51.4700 N / LON: 00.4543 W
ALT: 090 M    TIME: 0317Z

┌──────────────────────────────────────┐
│  HTB{SSTV_R4v3n_S1gn4L_1nt3rc3pt}  │
└──────────────────────────────────────┘

MODE: MARTIN M1
FREQ: 137.500 MHz
INTERCEPT REF: SV-SIGINT-0042
SIGNAL VEIL // COALITION SIGINT
```

Coordinates (51.4700 N, 0.4543 W) → London Heathrow Airport.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Python + NumPy/SciPy | IQ loading, FM demodulation, filtering |
| `sstv` (colaclanth/sstv) | VIS detection + Martin M1 decoding |
| PIL/Pillow | Image output |
| Matplotlib | Spectrogram visualization |

---

## Key Insights

1. **Constant envelope → FM/PM** — zero-variance magnitude ruled out AM protocols
2. **1500 Hz dominant → SSTV black level** — APT would peak at 2400 Hz
3. **1200 Hz → universal SSTV sync tone**
4. **116s duration + 256 lines → Martin M1** — timing matched perfectly

---

## Flag

```
HTB{SSTV_R4v3n_S1gn4L_1nt3rc3pt}
```
