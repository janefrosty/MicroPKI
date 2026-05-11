import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from .crypto_utils import generate_key, parse_dn, save_cert


def issue_ocsp_cert(args, ca_key, ca_cert, logger):
    subject = parse_dn(args.subject)
    key = generate_key(args.key_type, args.key_size or 2048)

    serial = int.from_bytes(os.urandom(16), "big")
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=args.validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=True
        )
    )

    if hasattr(args, 'san') and args.san:
        san_list = [x509.DNSName(s[4:]) for s in args.san if s.startswith("dns:")]
        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    cert_path = os.path.join(args.out_dir, "certs", "ocsp.cert.pem")
    key_path = os.path.join(args.out_dir, "private", "ocsp.key.pem")

    save_cert(cert, cert_path)

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    logger.info(f"OCSP responder certificate issued: {cert_path}")
    logger.info(f"OCSP responder key: {key_path}")
    return cert_path, key_path