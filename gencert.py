"""Generate a self-signed TLS cert+key for the gateway (no openssl needed).

    python gencert.py --host 100.101.102.10 --host mybox.local
    # always includes localhost + 127.0.0.1

Produces cert.pem and key.pem. Point the gateway at them with
--tls-cert/--tls-key, and give clients the cert as their --tls-ca (so they can
verify it). For a public, stranger-facing gateway, prefer a real CA-signed cert
(e.g. Let's Encrypt / a reverse proxy) so clients need no special CA file.
"""

import argparse
import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate(hosts, cert_path, key_path, days=825):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    san = []
    for h in hosts:
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            san.append(x509.DNSName(h))

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # Key identifiers so OpenSSL 3 can build the (self-signed) chain.
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                       critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"wrote {cert_path} and {key_path}")
    print("SANs:", ", ".join(hosts))


def main():
    ap = argparse.ArgumentParser(description="Generate a self-signed gateway TLS cert")
    ap.add_argument("--host", action="append", default=[],
                    help="hostname or IP to include (repeatable); localhost + 127.0.0.1 always added")
    ap.add_argument("--out-cert", default="cert.pem")
    ap.add_argument("--out-key", default="key.pem")
    ap.add_argument("--days", type=int, default=825)
    args = ap.parse_args()

    hosts = []
    for h in args.host + ["localhost", "127.0.0.1"]:
        if h not in hosts:
            hosts.append(h)
    generate(hosts, args.out_cert, args.out_key, args.days)


if __name__ == "__main__":
    main()
