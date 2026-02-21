import os
import sys

from .crypto_utils import (
    generate_key,
    create_self_signed_cert,
    save_encrypted_key,
    save_cert,
    ensure_pki_dirs,
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