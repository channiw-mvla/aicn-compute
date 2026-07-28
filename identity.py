"""Identity & key material for Phase 3 (identity + auth).

Each participant (node or requester) has an Ed25519 keypair. The public key is
its identity; the private key stays on the participant's machine. Authentication
is a challenge-response: the gateway sends a random nonce, the participant signs
it, and the gateway verifies the signature against the public key it has on file.
This proves the participant actually holds the private key — knowing someone's
public key is not enough to impersonate them.

The gateway keeps an **authorized-keys** store (a JSON file) mapping each public
key to a role, label and status (approved / pending / revoked). Unknown keys are
recorded as `pending` so an admin can approve them with `authctl.py`.

Requires the `cryptography` package.
"""

import base64
import hashlib
import json
import os
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


class Identity:
    """A loaded keypair. Holds the private key; exposes the public identity."""

    def __init__(self, private: Ed25519PrivateKey):
        self._private = private
        self.public_raw = private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)

    @property
    def public_b64(self) -> str:
        return b64(self.public_raw)

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.public_b64)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)


def load_or_create(path: str) -> Identity:
    """Load the private key at `path`, generating + saving one if absent."""
    if os.path.exists(path):
        seed = unb64(open(path, encoding="ascii").read().strip())
        private = Ed25519PrivateKey.from_private_bytes(seed)
    else:
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="ascii") as f:
            f.write(b64(seed))
        try:
            os.chmod(path, 0o600)  # private key — owner-only
        except OSError:
            pass
    return Identity(private)


def verify(public_b64: str, data: bytes, signature: bytes) -> bool:
    """True if `signature` is a valid Ed25519 signature of `data` by `public_b64`."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(unb64(public_b64))
        pub.verify(signature, data)   # raises InvalidSignature on mismatch
        return True
    except Exception:
        return False


def fingerprint_of(public_b64: str) -> str:
    """Short, human-comparable id for a public key (16 hex chars of SHA-256)."""
    try:
        raw = unb64(public_b64)
    except Exception:
        return "??"
    return hashlib.sha256(raw).hexdigest()[:16]


# -- authorized-keys store (used by the gateway and authctl) ------------------

def load_keystore(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_keystore(path: str, data: dict) -> None:
    """Atomic write so a concurrent reader never sees a half-written file."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".keys-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


async def client_handshake(ws, identity: "Identity", role: str):
    """Run the client side of the challenge-response over an open websocket.

    Returns (True, None) on success, or (False, reason) if the gateway rejected
    us. On success the caller should proceed to send its REGISTER message.
    """
    import protocol as P
    await P.send(ws, {"type": P.HELLO, "role": role, "pubkey": identity.public_b64})
    msg = P.decode(await ws.recv())
    if msg.get("type") == P.UNAUTHORIZED:
        return False, msg.get("reason", "rejected")
    if msg.get("type") != P.CHALLENGE:
        return False, f"expected CHALLENGE, got {msg.get('type')}"
    signature = identity.sign(str(msg.get("nonce", "")).encode("utf-8"))
    await P.send(ws, {"type": P.AUTH, "signature": b64(signature)})
    reply = P.decode(await ws.recv())
    if reply.get("type") == P.AUTH_OK:
        return True, None
    return False, reply.get("reason", "authentication failed")


if __name__ == "__main__":
    # `python identity.py [path]` — print this machine's public identity to hand
    # to the gateway admin for approval.
    import sys
    key_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.expanduser("~"), ".aicn", "identity.key")
    ident = load_or_create(key_path)
    print(f"identity key file : {key_path}")
    print(f"public key        : {ident.public_b64}")
    print(f"fingerprint       : {ident.fingerprint}")
