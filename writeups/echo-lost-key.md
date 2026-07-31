# Echo Lost Key — CTF Writeup

**CTF:** ADF CSA 2026 Season 3
**Category:** Digital Forensics
**Challenge:** EchoLostKey
**Flag:** `FLAG{ctrl_v}`

---

## Scenario

> I encrypted one of my hard drives but I forgot the password!
> I copied and pasted the password I used to encrypt the hard drive but I don't know how to get the password back again.
> I managed to recover my %AppData%/Local directory - I once read this is helpful!

**Files provided:** `%AppData%/Local` directory from a Windows 10 VM (`vboxuser` account, VirtualBox guest additions, shared folder `\\VBOXSVR\VMShared\b.txt`).

---

## How We Solved It — Reasoning

### Phase 1: Evidence Triage — What Matters in `%AppData%\Local`

The recovered directory contained the classic Windows 10 local-application artifacts:

| Artifact | Role |
|---|---|
| `ConnectedDevicesPlatform\L.vboxuser\ActivitiesCache.db` (+ `.db-wal`, `.db-shm`) | **Windows Activity / Clipboard History database** |
| `Comms\UnistoreDB\USS.jcp` + `.jrs` | Windows 11-era cloud clipboard (Unistore) — **empty scaffolding here** |
| `Temp\18e19041….db`, `Temp\offline` | VirtualBox telemetry events — **decoy** |
| `Temp\msedge_installer.log`, `wmsetup.log` | Edge / WM setup logs — confirm OS is Windows 10 19045 |

**Key insight (rejected hypothesis #1):** The presence of a WAL (`.db-wal`, 498 KB) next to the main `ActivitiesCache.db` meant the main file was **not** the latest state. A forensic analyst must always account for the WAL — it holds committed pages the main DB hasn't absorbed yet, and (critically) it can survive even when rows are deleted from the logical table.

### Phase 2: Inside ActivitiesCache.db — The Clipboard Trail

The `Activity` table has a `ClipboardPayload` column and `ActivityType=16` rows that log clipboard events:

```sql
SELECT Id, Payload FROM Activity WHERE ActivityType=16;
-- {"gdprType":"ProductAndServiceUsage","clipboardDataId":"{E6C066F7-84AE-4640-B393-DCF4F9466A08}"}
-- {"gdprType":"ProductAndServiceUsage","clipboardDataId":"{D4369E87-1E1D-4823-8A8A-AFBA0905228B}"}
```

Timeline reconstruction (Unix epochs in DB):
- `1682846743` — File Explorer opens
- `1682847206` — `cmd.exe` used
- `1682849076` — Notepad opens `\\VBOXSVR\VMShared\b.txt`
- `1682849092` / `1682849160` — **clipboard events (`Copy`)** — the user copied the password

But `ClipboardPayload` was NULL on every visible row and the DB threw `database disk image is malformed` when stepping the index. SQLite's own `PRAGMA integrity_check` reported *"wrong # of entries in index"* across all Activity indexes — a signature that the logical table had fewer rows than its indexes, i.e. **rows were deleted / the WAL held the real state**.

**Rejected hypothesis #2:** The `Comms\UnistoreDB` files (cloud clipboard on Win11) — `strings` showed only path names, all data was zeroed. Dead end; the clipboard history here is the Win10 `ActivitiesCache.db` mechanism.

### Phase 3: WAL Carve — Recovering What SQLite Wouldn't Show

SQLite refused to cleanly apply the WAL (`malformed` on index traversal), so I parsed the WAL **by hand**:

- WAL header is **big-endian** (unlike the main DB): magic `0x377f0682`, page size 4096
- 121 frames × (24-byte header + 4096-byte page), **no commit record** — the file was truncated mid-stream, which is why SQLite choked
- Overlaid every frame onto a copy of the main DB pages in frame order → `reconstructed.db`

Then `.recover` (which ignores b-tree/index corruption and dumps whatever records exist) surfaced the smoking gun — a row in the **`ActivityOperation`** table (the clipboard operation log):

```sql
SELECT OperationOrder, AppId, Group, ClipboardPayload FROM ActivityOperation;
-- 1 | com.microsoft.clipboard | Microsoft | [{content: "RkxBR3tjdHJsX3Z9Cg=="}]
```

### Phase 4: The Payload — One Base64 Decode

```
RkxBR3tjdHJsX3Z9Cg==  →  base64 -d  →  FLAG{ctrl_v}
```

### Phase 5: Verification

1. Decoded: `FLAG{ctrl_v}\n` (trailing newline is part of the payload).
2. Re-verified against the **pristine original** challenge files (read-only connection, WAL intact): the `ActivityOperation` row is present with the same payload.
3. Flag-format sanity check: the challenge declares `FLAG{cmd_k}` — "cmd" + "k" maps to **ctrl + v**, i.e. the user "gets the password back" with the **paste** keystroke. The recovered clipboard content confirms the paste command itself is the flag.

---

## Flags

| Flag | Location | Method |
|---|---|---|
| `FLAG{ctrl_v}` | `ActivitiesCache.db` → `ActivityOperation` (AppId `com.microsoft.clipboard`, ClipboardPayload base64) | WAL carve + `.recover` + base64 decode |

---

## Caveats / Gotchas

1. **WAL is part of the evidence.** Copying only `ActivitiesCache.db` gives a stale view — you must copy the `.db-wal` and `.db-shm` alongside it, and never let a read-write sqlite3 session checkpoint the WAL on your only copy (it truncates the WAL).
2. **SQLite WAL headers are big-endian**, while the database file itself is little-endian — a naive parser gets nonsense page sizes.
3. **`PRAGMA integrity_check` index errors are a hint, not a brick wall.** "wrong # of entries in index" means deleted rows or truncated WAL — exactly where forensics gold hides.
4. **`.recover`** is the right tool for a corrupted/truncated SQLite artifact: it walks pages directly and dumps records even when the b-tree indexes are unusable.
5. **Decoys everywhere:** `Comms/UnistoreDB` (zeroed), VirtualBox `Temp/*.db` telemetry, `.cdp` configs — triage by identifying the artifact family (clipboard history) first, then drill down.
