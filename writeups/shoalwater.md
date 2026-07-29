# ShoalWater — Coding / Simulation

**CTF:** Cyber Apocalypse 2026
**Category:** Coding / Simulation
**Challenge:** ShoalWater
**Flag:** `HTB{...}` (pending)

---

## Scenario

A Kestrel Dawn VSAT compromise exposes the NMEA bus of OPFOR patrol vessel OPV-14606, the read-only NMEA feed of BLUE vessel RS-10 AURORA, and an ECDIS dashboard for a fictional South Pacific exercise sector. AURORA must depart a BLUE staging area, reach Beacon Cay, dwell long enough to deploy a package, and return to a BLUE home port without OPFOR patrols plotting her ECDIS track inside their detection window. The goal is to spoof the AURORA AIS position on OPFOR ECDIS.

**Targets:**
- `154.57.164.83:31414` — OPFOR NMEA bus (AIS injection point)
- `154.57.164.83:30159` — AURORA read-only NMEA feed
- `154.57.164.83:32015` — ECDIS tactical dashboard (WebSocket)
- `154.57.164.83:32018` — Crownspire Signetry Model Registry (bonus discovery)

---

## Analysis

### Architecture

The challenge simulates maritime operations across four services:

| Port | Service | Protocol | Role |
|------|---------|----------|------|
| 31414 | OPFOR NMEA Bus | Raw TCP (NMEA 0183) | OPFOR sensor data + AIS targets. Accepts injection. |
| 30159 | AURORA NMEA Feed | Raw TCP (NMEA 0183) | AURORA's real-time navigation data |
| 32015 | ECDIS Dashboard | HTTP + WebSocket | Flask/Werkzeug tactical display with Leaflet map |
| 32018 | Signetry Registry | HTTP (Apache/React) | Model registry for AIS trajectory models |

### NMEA Data Stream (Port 31414)

The OPFOR NMEA bus streams real-time navigation data:
- `$GPRMC` — Recommended Minimum Navigation (position, SOG, COG)
- `$GPGGA` — GPS Fix Data
- `$GPVTG` — Track Made Good and Ground Speed
- `$HEHDT` — Heading True
- `$SDDBT` / `$SDDBS` — Depth Below Transducer/Surface
- `$WIMWV` — Wind Speed and Angle
- `$AIVDM` — AIS VHF Data-link Message (other vessel reports)
- `$PSEC` — Proprietary security/detection sentences

**Detection Alert:**
```
$PSEC,DETECT,ALARM 2026-07-29 00:27:48 UTC
SRC: OPFOR SENSOR FUSION
REASON: OPV-14606
TGT MMSI 990189432 INTERCEPTED
TGT POS 24.9896S 140.2802W
```

This shows OPFOR detected AURORA (MMSI 990189432) at Beacon Cay because the ECDIS track matched her real position.

### ECDIS Dashboard (Port 32015)

The dashboard provides a real-time tactical view via WebSocket (`/ws/ecdis`):
- **OPFOR OPV-14606**: Position, heading, speed, detection/radar rings
- **RS-10 AURORA** (real): Actual vessel position from port 30159
- **TGT-001 (ECDIS Lock)**: What OPFOR's ECDIS displays as AURORA position
- **Mission state**: Current phase, chaser status, destruction state
- **NMEA log**: 1000-entry ring buffer with OPFOR, SYS, and INJECT channels

Key WebSocket fields:
```json
{
  "mission": "FAILED",
  "friendly_destroyed": true,
  "destroy_tick": 92,
  "reassert_n": 4,
  "ecdis_friendly": {"spoofed": false, "lat": -24.98964, "lon": -140.28022},
  "chaser_mmsi": null,
  "detection_radius_deg": 0.04,
  "radar_range_deg": 0.025
}
```

### Signetry Model Registry (Port 32018)

A dark-fantasy-themed React app for managing ML model lifecycles:
- **Authentication**: Session-based (cookie `cs_session`), registration assigns `viewer` role
- **Roles**: anonymous → viewer → maintainer → curator → service
- **Model lifecycle**: STAGE (zip upload) → SEAL → FINALIZE/PROMOTE → DEPLOYED
- **Endpoints**: `/api/register`, `/api/login`, `/api/models`, `/api/versions/`, `/stage`, `/seal`, `/finalize`, `/withdraw`, `/api/appeals`

Existing models: `fraud-detector` (v7 deployed), `churn-propensity` (v3 deployed), `vision-defect-net` (v12 approved). Target handles `ais-spoof` and `trajectory` exist but have no versions (`exists: false`).

---

## Solution / Exploitation

### Phase 1: AIS Injection (Successful)

AIS position reports can be injected onto the OPFOR NMEA bus via port 31414. Using `pyais` to encode position reports for AURORA (MMSI 990189432):

```python
from pyais.encode import encode_msg
from pyais.messages import MessageType1

msg = MessageType1.create(
    mmsi=990189432,
    lat=-26.5, lon=-142.5,  # Spoofed position
    sog=28.0, cog=275.0, hdg=275,
    nav_status=0, repeat_indicator=0,
)
sentences = encode_msg(msg, talker_id="AI", sentence_type="VDM", radio_channel="A")
spoofed_nmea = "$" + sentences[0][1:] + "\r\n"

# Inject via port 31414
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("154.57.164.83", 31414))
s.send(spoofed_nmea.encode())
```

**Result:** Injected AIS messages appear in the ECDIS NMEA log under the `INJECT` channel:
```json
{"ts": "00:48:06", "raw": "$AIVDM,1,1,,A,1>hDGN?P00Ekcu1hmR`00001P000,0*0C",
 "channel": "INJECT", "injected": true, "type": "AIVDM"}
```

Valid talker IDs are restricted: only `AI` prefix is accepted; others like `AB`, `AD`, `GP`, `VD` return `$PSEC,NACK,BAD_PREFIX`.

### Phase 2: Signetry Maintainer Access (Blocked)

To deploy a spoofed trajectory model that the ECDIS simulation will use, maintainer-level access to the Signetry registry is required. Attempted bypass vectors:

| Approach | Result |
|----------|--------|
| Registration mass assignment (`role: "maintainer"`) | Ignored; always assigns `viewer` |
| Username impersonation (`admin`, `dms`, `curator`) | New viewer account created |
| Password reset for `dms@htb.com` | 503 "temporarily under maintenance" |
| NoSQL injection on login | 401 Unauthorized |
| HTTP method override (PUT/PATCH /stage) | 404 Not Found |
| Race condition (10× concurrent /stage) | All 403 |
| Custom headers (`X-Role`, `X-Model-Name`) | Ignored |
| Path traversal in ZIP | Rejected |
| Session prediction/forgery | SHA256 tokens, unpredictable |

The `/stage` endpoint consistently returns `403 {"error": "maintainer access required"}` for viewer sessions.

### Phase 3: Simulation State

The simulation completed all 4 reassertion attempts (`reassert_n: 4`) and ended with AURORA destroyed at tick 92. The mission status is stuck at `FAILED`. Port 30159 (AURORA feed) is silent. The ECDIS `ecdis_friendly.spoofed` remains `False` throughout.

---

## How We Solved It — Reasoning

**Initial hypothesis:** The Signetry Model Registry is the control interface for AIS spoofing. Deploying a trajectory model would feed spoofed positions to the OPFOR ECDIS.

**Evidence for:** 
- Handles `ais-spoof` and `trajectory` exist in the registry
- Model lifecycle (STAGE → SEAL → DEPLOY) matches operational deployment
- The dashboard NMEA log has an INJECT channel suggesting injected data can affect the display

**Evidence against / alternative:**
- Direct AIS injection on port 31414 works (messages appear in log) but doesn't change ECDIS position
- The simulation is single-run; once FAILED, no mechanism to restart was discovered
- The challenge target list does NOT include port 32018 (Signetry), suggesting it may be separate

**Key insight:** The NMEA bus on port 31414 is bi-directional — it accepts injected AIS messages that appear in the INJECT channel. However, during a FAILED simulation, the ECDIS position is frozen at the destruction point. Successful spoofing likely requires injection DURING an active simulation run, or through the Signetry model deployment mechanism.

**Rejected hypotheses:**
- WebSocket command injection — no effect on server state
- Password reset token brute force — token validation is robust
- Port 30159 as injection point — no response, port is output-only

---

## Key Takeaways / Caveats

1. **NMEA 0183 protocol**: AIS position reports use 6-bit ASCII armoring. Python's `pyais` library handles encoding/decoding.
2. **Talker ID filtering**: The OPFOR bus only accepts `AI`-prefixed sentences; other talker IDs are rejected with `BAD_PREFIX`.
3. **Simulation lifecycle**: The challenge appears to run a fixed number of simulation attempts. A fresh instance or timer-based restart may be needed.
4. **Checksums**: NMEA checksums are XOR of all characters between `$` and `*`. Invalid checksums produce `BAD_CHECKSUM` NACKs.
5. **Signetry auth**: Session cookies (`cs_session`) are 64-char hex (SHA256), unpredictable. The app enforces role-based access with no discovered bypass.
