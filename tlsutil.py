"""TLS helpers for wss:// (Phase 3 — the encryption half of identity+encryption).

The gateway serves wss:// (and https for the dashboard) when given a cert+key.
Clients verify that cert. Over a private overlay (Tailscale) TLS is optional
belt-and-suspenders; for a public gateway it's what encrypts workloads/results
in transit and prevents an on-path attacker from reading or hijacking them.
"""

import ssl


def server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx


def client_context(cafile: str = None, insecure: bool = False) -> ssl.SSLContext:
    """Context for connecting to a wss:// gateway.

    * cafile   — trust this CA/self-signed cert (verifies identity + hostname).
    * insecure — skip verification entirely (TESTING ONLY; encrypted but
                 vulnerable to man-in-the-middle).
    * neither  — use the system trust store (right for a real CA / Let's Encrypt).
    """
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
