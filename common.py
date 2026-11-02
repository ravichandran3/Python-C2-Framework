"""Shared helpers for server, operator, stager. Pure stdlib."""
import hashlib
import json
import socket
import ssl
import struct

PROTOCOL_VERSION = "1"

DEFAULT_PROFILE = {
    "name": "default",
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "register_uri": "/api/v1/auth/login",
    "beacon_uri": "/api/v1/auth/refresh",
    "result_uri": "/api/v1/auth/verify",
    "headers": {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
    },
}


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_msg(sock):
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    length = struct.unpack(">I", hdr)[0]
    if length == 0 or length > 64 * 1024 * 1024:
        return None
    return recv_exact(sock, length)


def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def cert_fingerprint(sock):
    """SHA-256 hex of peer DER cert."""
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("no peer certificate")
    return hashlib.sha256(der).hexdigest()


def normalize_fp(fp):
    if not fp:
        return ""
    return fp.lower().replace(":", "").replace("sha256:", "").strip()


def make_client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def make_server_ctx(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def json_dumps(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


def json_loads(data):
    return json.loads(data.decode() if isinstance(data, bytes) else data)
