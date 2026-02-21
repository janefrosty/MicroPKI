import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID


def parse_dn(dn_str: str) -> x509.Name:
    attributes = []
    if dn_str.startswith("/"):
        parts = dn_str[1:].split("/")
    else:
        parts = [p.strip() for p in dn_str.split(",")]

    for part in parts:
        if "=" not in part:
            continue
        key, value = [x.strip() for x in part.split("=", 1)]
        key = key.upper()
        if key == "CN":
            attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, value))
        elif key == "O":
            attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, value))
        elif key == "C":
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, value))
    if not attributes:
        raise ValueError("Invalid or empty subject DN")
    return x509.Name(attributes)


def generate_key(key_type: str, key_size: int):
    if key_type == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    elif key_type == "ecc":
        return ec.generate_private_key(ec.SECP384R1())
    raise ValueError("Unsupported key-type")


def create_self_signed_cert(private_key, subject_str: str, validity_days: int):
    subject = parse_dn(subject_str)
    serial = secrets.randbits(128) 
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=validity_days)

    if isinstance(private_key, rsa.RSAPrivateKey):
        hash_alg = hashes.SHA256()
    else:
        hash_alg = hashes.SHA384()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hash_alg)
    )
    return cert


def save_encrypted_key(private_key, passphrase: bytes, path: str):
    encryption = serialization.BestAvailableEncryption(passphrase)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_cert(cert, path: str):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(path, "wb") as f:
        f.write(pem)


def ensure_pki_dirs(out_dir: str, logger):
    private_dir = os.path.join(out_dir, "private")
    certs_dir = os.path.join(out_dir, "certs")
    os.makedirs(private_dir, exist_ok=True)
    os.makedirs(certs_dir, exist_ok=True)
    try:
        os.chmod(private_dir, 0o700)
    except OSError:
        logger.warning("Cannot set 0o700 on private/ (Windows OK)")
    return private_dir, certs_dir