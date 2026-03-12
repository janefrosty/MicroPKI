# micropki/intermediate.py

import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from .crypto_utils import (
    generate_key,
    parse_dn,
    save_encrypted_key,
    save_cert,
    ensure_pki_dirs,
    load_encrypted_private_key,
    load_certificate,
    create_csr,
    sign_cert
)


def issue_intermediate_ca(args, root_passphrase: bytes, inter_passphrase: bytes, logger):
    """Выдача промежуточного CA-сертификата, подписанного Root CA"""

    logger.info("=== Выдача Intermediate CA ===")

    # Загрузка Root CA
    root_key = load_encrypted_private_key(args.root_key, root_passphrase)
    root_cert = load_certificate(args.root_cert)

    # Генерация ключа Intermediate
    key_size = args.key_size or (4096 if args.key_type == "rsa" else 384)
    inter_key = generate_key(args.key_type, key_size)

    # Subject Intermediate
    subject = parse_dn(args.subject)

    # CSR (с расширением BasicConstraints, если pathlen указан)
    extensions = []
    if args.pathlen is not None:
        bc = x509.BasicConstraints(ca=True, path_length=args.pathlen)
        extensions.append((bc, True))

    csr = create_csr(subject, inter_key, extensions)

    # Строим сертификат Intermediate
    serial = secrets.randbits(128)
    not_before = datetime.now(timezone.utc)
    not_after = not_before + timedelta(days=args.validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(inter_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=args.pathlen),
            critical=True
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
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False
        )
    )

    # Подпись сертификата ключом Root
    signing_hash = hashes.SHA256() if isinstance(root_key, rsa.RSAPrivateKey) else hashes.SHA384()
    inter_cert = sign_cert(builder, root_key, signing_hash)

    # Сохранение файлов
    private_dir, certs_dir = ensure_pki_dirs(args.out_dir, logger)
    key_path = os.path.join(private_dir, "intermediate.key.pem")
    cert_path = os.path.join(certs_dir, "intermediate.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        raise FileExistsError("Файлы Intermediate уже существуют. Используйте --force")

    save_encrypted_key(inter_key, inter_passphrase, key_path)
    save_cert(inter_cert, cert_path)

    logger.info("Intermediate CA успешно создан")
    logger.info(f"Приватный ключ: {key_path}")
    logger.info(f"Сертификат:     {cert_path}")