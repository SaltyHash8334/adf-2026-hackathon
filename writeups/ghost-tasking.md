# Ghost Tasking — Salty Hash443

**Target:** `154.57.164.71`
**Services:** GCS `32342`, MAVLink TCP `31426`
**Flag:** `HTB{Gh0st_T4sk1ng_0v3rr1d3}`

## Challenge Overview

The task was to access the Signal Veil GCS, use its unauthenticated MAVLink-over-TCP bridge, redirect Raven-6 from its patrol, and land it at the displayed Arthur Junction Nature Reserve recovery base.

## How We Solved It — Reasoning

### 1. Reconnaissance

The two supplied ports exposed different protocols:

- `32342/tcp`: Flask/Werkzeug web application, redirecting unauthenticated users to `/login`.
- `31426/tcp`: MAVLink v2 telemetry stream. The initial bytes included a MAVLink heartbeat, confirming the service immediately.

The GCS HTML identified the asset as `RAVEN-6`, exposed the telemetry endpoint `/api/drone_data`, and showed the recovery marker at `51.4728, -0.5288`.

### 2. Web authentication and telemetry

The supplied credentials authenticated successfully:

```text
gcs_admin / Kd@LHR_0ps!r4v3n6
```

After login, `/api/drone_data` returned live state including latitude, longitude, altitude, flight mode, arm state, and a `flag` field. Initially the flag field was empty.

### 3. MAVLink validation

A virtual environment was used for `pymavlink` because the host Python installation is externally managed:

```bash
python3 -m venv /tmp/ghost-venv
/tmp/ghost-venv/bin/pip install pymavlink
```

A heartbeat identified ArduPilot (`autopilot=3`) and system 1/component 1. Telemetry confirmed the active patrol and a moving position target.

### 4. Rejected approaches

- **Direct global position targets:** MAVLink accepted the messages, but the autopilot continued following its existing target loop.
- **`MAV_CMD_DO_REPOSITION`:** returned an unsuccessful command result and did not replace the active target.
- **Mission upload/AUTO mode:** mission requests were not serviced and AUTO reported `init failed`.
- **Direct landing before reaching the base:** the aircraft landed at its current position, proving the LAND command worked but not satisfying the scenario condition.

The key insight was to use the local-NED position interface and first set the recovery coordinates as the vehicle's home position. The `MAV_CMD_DO_SET_HOME` command was acknowledged, and `HOME_POSITION` then reported exactly `51.4728000, -0.5288000`.

### 5. Successful control sequence

The verified sequence was:

1. Set home to the recovery coordinates with `MAV_CMD_DO_SET_HOME`.
2. Confirm the resulting `HOME_POSITION` coordinates.
3. Issue `MAV_CMD_NAV_RETURN_TO_LAUNCH`.
4. Observe the vehicle enter RTL and travel to the recovery base.
5. Verify GCS telemetry reached approximately:

```text
lat: 51.4728
lon: -0.5288
alt: ~0 m
armed: false
system_status: STANDBY
```

The GCS then exposed the non-empty flag through `/api/drone_data`.

## Evidence

Final verified response:

```json
{"airspeed":0.02253096178174019,"alt":0.062,"armed":false,"battery":-1,"flag":"HTB{Gh0st_T4sk1ng_0v3rr1d3}","groundspeed":0.02245245687663555,"heading":203.58,"lat":51.4727996,"lon":-0.5287998,"mode":"LAND","system_status":"STANDBY"}
```

The flag was independently confirmed from the authenticated GCS API after the vehicle was at the recovery coordinates and disarmed.

## Flag

```text
HTB{Gh0st_T4sk1ng_0v3rr1d3}
```
