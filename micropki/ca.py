import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .crypto_utils import (
    create_self_signed_cert, ensure_pki_dirs, generate_key, parse_dn,
    save_encrypted_key, save_cert, load_encrypted_private_key, load_certificate, sign_cert
)
from .database import get_db_path, save_cert_to_db, is_key_compromised
from .templates import get_extensions_for_template
from .policy import enforce_key_size, enforce_validity, enforce_san
from .transparency import log_certificate
from .audit import AuditLogger

def init_ca(args, logger, audit_logger: AuditLogger):
    logger.info("=== Инициализация корневого CA ===")
    audit_logger.log('AUDIT', 'init_ca', 'start', 'Инициализация корневого CA', {})
    
    with open(args.passphrase_file, "rb") as f:
        passphrase = f.read().strip()

    private_dir, certs_dir = ensure_pki_dirs(args.out_dir, logger)
    key_path = os.path.join(private_dir, "ca.key.pem")
    cert_path = os.path.join(certs_dir, "ca.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        logger.error("Файлы уже существуют. Используйте --force для перезаписи.")
        audit_logger.log('AUDIT', 'init_ca', 'failure', 'Файлы CA уже существуют', {'force': False})
        return

    logger.info(f"Генерация {args.key_type.upper()} ключа")
    private_key = generate_key(args.key_type, args.key_size or 4096)
    
    # Проверка политик для корневого CA
    enforce_key_size(private_key.public_key(), 'root', is_ca=True)
    enforce_validity('root', args.validity_days)

    logger.info("Создание самоподписанного сертификата")
    cert = create_self_signed_cert(private_key, args.subject, args.validity_days)

    logger.info("Сохранение зашифрованного закрытого ключа")
    save_encrypted_key(private_key, passphrase, key_path)
    logger.info("Сохранение сертификата")
    save_cert(cert, cert_path)

    db_path = get_db_path(args.out_dir)
    save_cert_to_db(db_path, cert, str(cert.subject), logger)

    logger.info(f"УСПЕХ: Корневой CA создан в {args.out_dir}")
    audit_logger.log('AUDIT', 'init_ca', 'success', 'Корневой CA инициализирован', {
        'subject': args.subject, 'key_type': args.key_type, 'out_dir': args.out_dir
    })

def issue_end_entity_cert(args, ca_passphrase_bytes: bytes, logger, audit_logger: AuditLogger, ct_log_path: str = None):
    logger.info(f"Выпуск сертификата по шаблону: {args.template}")
    audit_logger.log('AUDIT', 'issue_cert', 'start', f'Запрос на выпуск сертификата {args.template}', {})

    ca_key = load_encrypted_private_key(args.ca_key, ca_passphrase_bytes)
    ca_cert = load_certificate(args.ca_cert)

    key_size = args.key_size or (2048 if args.key_type == "rsa" else 256)
    subject_key = generate_key(args.key_type, key_size)

    # --- Применение политик ---
    try:
        enforce_key_size(subject_key.public_key(), args.template, is_ca=False)
        enforce_validity(args.template, args.validity_days)
        
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
        enforce_san(san_names, args.template)

        # Проверка, не скомпрометирован ли ключ
        db_path = get_db_path(args.out_dir)
        if is_key_compromised(db_path, subject_key.public_key()):
            raise ValueError("Публичный ключ числится в списке скомпрометированных. Выпуск невозможен.")
            
    except ValueError as e:
        logger.error(f"Ошибка политики: {e}")
        audit_logger.log('AUDIT', 'issue_cert', 'failure', f'Нарушение политики: {e}', {'template': args.template})
        return

    extensions = get_extensions_for_template(args.template, args.key_type, san_names)
    subject = parse_dn(args.subject)
    serial = secrets.randbits(128)
    now = datetime.now(timezone.utc)

    builder = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.validity_days))
    )
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), False)

    signing_hash = hashes.SHA256() if isinstance(ca_key, rsa.RSAPrivateKey) else hashes.SHA384()
    cert = sign_cert(builder, ca_key, signing_hash)

    # --- Сохранение файлов ---
    private_dir = os.path.join(args.out_dir, "private")
    certs_dir = os.path.join(args.out_dir, "certs")
    os.makedirs(private_dir, exist_ok=True)
    os.makedirs(certs_dir, exist_ok=True)

    cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn_safe = cn[0].value.replace(" ", "_").replace(".", "_") if cn else "end-entity"

    key_path = os.path.join(private_dir, f"{cn_safe}.key.pem")
    cert_path = os.path.join(certs_dir, f"{cn_safe}.cert.pem")

    if (os.path.exists(key_path) or os.path.exists(cert_path)) and not args.force:
        logger.error("Файлы уже существуют. Используйте --force.")
        audit_logger.log('AUDIT', 'issue_cert', 'failure', 'Файлы сертификата уже существуют', {'cert_path': cert_path})
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

    # --- CT логгирование ---
    if ct_log_path:
        log_certificate(cert_path, ct_log_path)

    logger.info("Сертификат успешно выпущен")
    audit_logger.log('AUDIT', 'issue_cert', 'success', 'Сертификат выпущен', {
        'serial': format(serial, 'x'), 'subject': str(subject), 'template': args.template
    })

# Функция issue_cert_from_csr аналогичным образом дополняется проверками политик, аудитом и CT-логом.
def issue_cert_from_csr(args, ca_key, ca_cert, logger, audit_logger: AuditLogger, ct_log_path: str = None):
    audit_logger.log('AUDIT', 'issue_from_csr', 'start', 'Выпуск сертификата из CSR', {'csr_path': args.csr})
    with open(args.csr, "rb") as f:
        csr = x509.load_pem_x509_csr(f.read())

    try:
        enforce_key_size(csr.public_key(), 'end', is_ca=False)
        enforce_validity('end', args.validity_days)
        db_path = get_db_path(args.out_dir)
        if is_key_compromised(db_path, csr.public_key()):
            raise ValueError("Публичный ключ из CSR скомпрометирован.")
    except ValueError as e:
        logger.error(f"Ошибка политики: {e}")
        audit_logger.log('AUDIT', 'issue_from_csr', 'failure', f'Нарушение политики: {e}', {})
        return

    serial = secrets.randbits(128)
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder()
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

    if ct_log_path:
        log_certificate(cert_path, ct_log_path)

    logger.info(f"Сертификат из CSR выпущен: {cert_path}")
    audit_logger.log('AUDIT', 'issue_from_csr', 'success', 'Сертификат выпущен', {'serial': format(serial, 'x')})