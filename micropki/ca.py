# micropki/ca.py
import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .crypto_utils import (
    create_self_signed_cert,
    ensure_pki_dirs,
    generate_key,
    parse_dn,
    save_encrypted_key,
    save_cert,
    load_encrypted_private_key,
    load_certificate,
    sign_cert,
)

from .database import get_db_path, save_cert_to_db


def init_ca(args, logger):
    logger.info("=== Starting Root CA initialization ===")

    with open(args.passphrase_file, "rb") as f:
        passphrase = f.read().strip()

    private_dir, certs_dir = ensure_pki_dirs(args.out_dir, logger)

    key_path = os.path.join(private_dir, "ca.key.pem")
    cert_path = os.path.join(certs_dir, "ca.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        logger.error("Files already exist. Use --force to overwrite.")
        return

    logger.info(f"Generating {args.key_type.upper()} key")
    private_key = generate_key(args.key_type, args.key_size or 4096)

    logger.info("Creating self-signed X.509v3 certificate")
    cert = create_self_signed_cert(private_key, args.subject, args.validity_days)

    logger.info("Saving encrypted private key")
    save_encrypted_key(private_key, passphrase, key_path)

    logger.info("Saving certificate")
    save_cert(cert, cert_path)

    db_path = get_db_path(args.out_dir)
    save_cert_to_db(db_path, cert, str(cert.subject), logger)

    logger.info(f"SUCCESS: Root CA created in {args.out_dir}")


def issue_end_entity_cert(args, ca_passphrase_bytes: bytes, logger):
    logger.info(f"Выдача конечного сертификата по шаблону: {args.template}")

    ca_key = load_encrypted_private_key(args.ca_key, ca_passphrase_bytes)
    ca_cert = load_certificate(args.ca_cert)

    key_size = args.key_size or (2048 if args.key_type == "rsa" else 256)
    subject_key = generate_key(args.key_type, key_size)

    san_names = []
    if args.san:
        for entry in args.san:
            entry = entry.strip()
            if entry.startswith("dns:"):
                san_names.append(x509.DNSName(entry[4:]))
            elif entry.startswith("ip:"):
                from ipaddress import ip_address
                san_names.append(x509.IPAddress(ip_address(entry[3:])))
            elif entry.startswith("email:"):
                san_names.append(x509.RFC822Name(entry[6:]))

    from .templates import get_extensions_for_template
    extensions = get_extensions_for_template(args.template, args.key_type, san_names)

    subject = parse_dn(args.subject)
    serial = secrets.randbits(128)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.validity_days))
    )

    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    )

    signing_hash = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    cert = sign_cert(builder, ca_key, signing_hash)

    private_dir = os.path.join(args.out_dir, "private")
    certs_dir = os.path.join(args.out_dir, "certs")
    os.makedirs(private_dir, exist_ok=True)
    os.makedirs(certs_dir, exist_ok=True)

    cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn_safe = cn[0].value.replace(" ", "_").replace(".", "_") if cn else "end-entity"

    key_path = os.path.join(private_dir, f"{cn_safe}.key.pem")
    cert_path = os.path.join(certs_dir, f"{cn_safe}.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        logger.error("Files already exist. Use --force")
        return

    with open(key_path, "wb") as f:
        f.write(subject_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    save_cert(cert, cert_path)

    db_path = get_db_path(args.out_dir)
    save_cert_to_db(db_path, cert, str(ca_cert.subject), logger)

    logger.info("Конечный сертификат успешно выдан")
    logger.info(f"Приватный ключ: {key_path}")
    logger.info(f"Сертификат:     {cert_path}")


def issue_cert_from_csr(args, ca_key, ca_cert, logger):
    with open(args.csr, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    serial = secrets.randbits(128)
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.validity_days))
    )

    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, critical=ext.critical)

    signing_hash = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    cert = builder.sign(ca_key, signing_hash)

    cert_path = args.out_cert
    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)

    save_cert(cert, cert_path)

    db_path = get_db_path(os.path.dirname(cert_path) or "./pki")
    save_cert_to_db(db_path, cert, str(ca_cert.subject), logger)

    logger.info(f"Certificate issued from CSR: {cert_path}")