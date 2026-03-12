import os
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timedelta, timezone
import secrets
import os
import ipaddress

from .crypto_utils import (
    generate_key,
    parse_dn,
    create_self_signed_cert,
    save_encrypted_key,
    save_cert,
    ensure_pki_dirs,
    load_encrypted_private_key,
    load_certificate,
    sign_cert
)


def init_ca(args, logger):
    logger.info("=== Starting Root CA initialization ===")

    with open(args.passphrase_file, "rb") as f:
        passphrase = f.read().strip()
    if not passphrase:
        raise ValueError("Passphrase file is empty")

    private_dir, certs_dir = ensure_pki_dirs(args.out_dir, logger)

    key_path = os.path.join(private_dir, "ca.key.pem")
    cert_path = os.path.join(certs_dir, "ca.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        logger.error("Files already exist. Use --force to overwrite.")
        sys.exit(1)

    logger.info(f"Generating {args.key_type.upper()} key ({args.key_size} bits)")
    private_key = generate_key(args.key_type, args.key_size)

    logger.info("Creating self-signed X.509v3 certificate")
    cert = create_self_signed_cert(private_key, args.subject, args.validity_days)

    logger.info("Saving encrypted private key (PKCS#8)")
    save_encrypted_key(private_key, passphrase, key_path)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        logger.warning("Cannot set 0o600 on ca.key.pem (Windows OK)")

    logger.info("Saving certificate (PEM)")
    save_cert(cert, cert_path)

    logger.info(f"SUCCESS: Root CA successfully created in {args.out_dir}")
    logger.info(f"   Private key: {key_path}")
    logger.info(f"   Certificate: {cert_path}")

def issue_end_entity_cert(args, logger):
    logger.info(f"Issuing end-entity certificate using template: {args.template}")

    ca_key = load_encrypted_private_key(args.ca_key, open(args.ca_passphrase_file, "rb").read().strip())
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
                try:
                    san_names.append(x509.IPAddress(ipaddress.ip_address(entry[3:])))
                except Exception:
                    logger.warning(f"Invalid IP in SAN: {entry}")
            elif entry.startswith("email:"):
                san_names.append(x509.RFC822Name(entry[6:]))
            else:
                logger.warning(f"Unsupported SAN type: {entry}")

    from .templates import get_extensions_for_template
    extensions = get_extensions_for_template(args.template, args.key_type, san_names)

    # Строим сертификат
    subject = parse_dn(args.subject)
    serial = secrets.randbits(120)
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

    for ext_val, critical in extensions:
        builder = builder.add_extension(ext_val, critical=critical)

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

    out_private = os.path.join(args.out_dir, "private")
    out_certs = os.path.join(args.out_dir, "certs")
    os.makedirs(out_private, exist_ok=True)
    os.makedirs(out_certs, exist_ok=True)

    cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn_safe = cn[0].value.replace(" ", "_").replace(".", "_") if cn else "end-entity"

    key_path = os.path.join(out_private, f"{cn_safe}.key.pem")
    cert_path = os.path.join(out_certs, f"{cn_safe}.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        raise FileExistsError("Use --force to overwrite")

    with open(key_path, "wb") as f:
        f.write(subject_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    save_cert(cert, cert_path)

    logger.info("Issued successfully:")
    logger.info(f"  Certificate → {cert_path}")
    logger.info(f"  Private key  → {key_path}")

def issue_end_entity_cert(args, ca_passphrase_bytes: bytes, logger):
    logger.info(f"Выдача конечного сертификата по шаблону: {args.template}")

    # Загрузка CA
    ca_key = load_encrypted_private_key(args.ca_key, ca_passphrase_bytes)
    ca_cert = load_certificate(args.ca_cert)

    # Генерация ключа конечного субъекта
    key_size = args.key_size or (2048 if args.key_type == "rsa" else 256)
    subject_key = generate_key(args.key_type, key_size)

    # Парсинг SAN
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
            else:
                logger.warning(f"Неподдерживаемый тип SAN: {entry}")

    # Получаем расширения по шаблону
    from .templates import get_extensions_for_template
    extensions = get_extensions_for_template(args.template, args.key_type, san_names)

    # Строим сертификат
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
        raise FileExistsError("Файлы уже существуют. Используйте --force")

    with open(key_path, "wb") as f:
        f.write(subject_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    save_cert(cert, cert_path)

    logger.info("Конечный сертификат успешно выдан")
    logger.info(f"Приватный ключ: {key_path}")
    logger.info(f"Сертификат:     {cert_path}")