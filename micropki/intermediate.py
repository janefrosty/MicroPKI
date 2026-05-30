# micropki/intermediate.py
import os
import secrets
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .crypto_utils import (
    generate_key, parse_dn, save_encrypted_key, save_cert,
    sign_cert, load_encrypted_private_key, load_certificate, ensure_pki_dirs
)
from .database import get_db_path, save_cert_to_db

def issue_intermediate_ca(args, root_passphrase: bytes, inter_passphrase: bytes, logger):
    """
    Выпуск промежуточного CA, подписанного корневым CA.
    Ожидает, что args содержит:
        root_key (str) - путь к закрытому ключу корневого CA
        root_cert (str) - путь к сертификату корневого CA
        subject (str) - DN для промежуточного CA
        key_type (str) - 'rsa' или 'ecc'
        key_size (int) - размер ключа
        validity_days (int) - срок действия
        pathlen (int) - ограничение глубины BasicConstraints
        out_dir (str) - выходная директория
        force (bool) - перезаписывать ли файлы
    """
    logger.info("=== Выдача Intermediate CA ===")
    
    # Загружаем корневой ключ и сертификат
    root_key = load_encrypted_private_key(args.root_key, root_passphrase)
    root_cert = load_certificate(args.root_cert)
    
    # Генерируем ключ для промежуточного CA
    key_size = args.key_size or (3072 if args.key_type == "rsa" else 384)
    inter_key = generate_key(args.key_type, key_size)
    
    # Определяем пути
    private_dir, certs_dir = ensure_pki_dirs(args.out_dir, logger)
    inter_key_path = os.path.join(private_dir, "intermediate.key.pem")
    inter_cert_path = os.path.join(certs_dir, "intermediate.cert.pem")
    
    if (os.path.exists(inter_key_path) or os.path.exists(inter_cert_path)) and not args.force:
        logger.error("Файлы промежуточного CA уже существуют. Используйте --force.")
        return
    
    # Создаём сертификат
    subject = parse_dn(args.subject)
    serial = secrets.randbits(128)
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(inter_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=args.pathlen), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False)
    )
    
    signing_hash = hashes.SHA256() if isinstance(root_key, rsa.RSAPrivateKey) else hashes.SHA384()
    inter_cert = sign_cert(builder, root_key, signing_hash)
    
    # Сохраняем ключ и сертификат
    save_encrypted_key(inter_key, inter_passphrase, inter_key_path)
    save_cert(inter_cert, inter_cert_path)
    
    # Сохраняем в БД (исправленный порядок аргументов: db_path, cert, issuer_name, logger)
    db_path = get_db_path(args.out_dir)
    save_cert_to_db(db_path, inter_cert, str(root_cert.subject), logger)
    
    logger.info(f"Intermediate CA создан: {inter_cert_path}")