"""Shared crypto, framing, and default malleable profile."""
import os, struct
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_PROFILE = {
    "name": "default",
    "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "register_uri": "/api/v1/auth/login",
    "beacon_uri":   "/api/v1/auth/refresh",
    "result_uri":   "/api/v1/auth/verify",
    "headers": {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "X-Requested-With": "XMLHttpRequest",
    },
}


def aes_encrypt(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], None)


def rsa_encrypt(pub, data: bytes) -> bytes:
    return pub.encrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))


def rsa_decrypt(priv, data: bytes) -> bytes:
    return priv.decrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def recv_msg(sock):
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    n = struct.unpack(">I", hdr)[0]
    return recv_exact(sock, n)


def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)
