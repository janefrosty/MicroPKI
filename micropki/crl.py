import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .database import get_db_connection, get_db_path
from .crypto_utils import load_encrypted_private_key, load_certificate
from .audit import AuditLogger

def generate_crl(args, ca_key, ca_cert, logger, audit_logger: AuditLogger):
    audit_logger.log('AUDIT', 'generate_crl', 'start', 'Генерация CRL', {})
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.now(timezone.utc))
    builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=args.validity_days))

    conn = get_db_connection(get_db_path(args.out_dir))
    cursor = conn.cursor()
    cursor.execute("SELECT serial_hex, revoked_at, revocation_reason FROM certificates WHERE status = 'revoked'")

    reason_map = {
        0: x509.ReasonFlags.unspecified,
        1: x509.ReasonFlags.key_compromise,
        2: x509.ReasonFlags.ca_compromise,
        3: x509.ReasonFlags.affiliation_changed,
        4: x509.ReasonFlags.superseded,
        5: x509.ReasonFlags.cessation_of_operation,
        6: x509.ReasonFlags.certificate_hold,
        8: x509.ReasonFlags.remove_from_crl,
        9: x509.ReasonFlags.privilege_withdrawn,
        10: x509.ReasonFlags.aa_compromise,
    }

    revoked_count = 0
    for row in cursor.fetchall():
        serial = int(row['serial_hex'], 16)
        revoked_date = datetime.fromisoformat(row['revoked_at'])
        reason_code = int(row['revocation_reason']) if row['revocation_reason'] else 0

        revoked_builder = x509.RevokedCertificateBuilder()
        revoked_builder = revoked_builder.serial_number(serial)
        revoked_builder = revoked_builder.revocation_date(revoked_date)

        if reason_code in reason_map:
            revoked_builder = revoked_builder.add_extension(
                x509.CRLReason(reason_map[reason_code]), critical=False)

        builder = builder.add_revoked_certificate(revoked_builder.build())
        revoked_count += 1

    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    crl_dir = os.path.join(args.out_dir, "crl")
    os.makedirs(crl_dir, exist_ok=True)
    crl_path = os.path.join(crl_dir, "root.crl.pem")

    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    logger.info(f"CRL сгенерирован: {crl_path} (отозванных сертификатов: {revoked_count})")
    audit_logger.log('AUDIT', 'generate_crl', 'success', 'CRL сгенерирован', {
        'path': crl_path, 'revoked_count': revoked_count
    })
    return crl_path