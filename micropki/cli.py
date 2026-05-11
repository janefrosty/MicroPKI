import argparse
import os
import sys

from .logger import setup_logger
from .ca import init_ca, issue_end_entity_cert
from .intermediate import issue_intermediate_ca
from .database import init_db, get_db_path
from .crypto_utils import load_encrypted_private_key, load_certificate


def main():
    parser = argparse.ArgumentParser(description="MicroPKI CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ==================== CA COMMANDS ====================
    ca_parser = subparsers.add_parser("ca", help="Certificate Authority commands")
    ca_sub = ca_parser.add_subparsers(dest="ca_action", required=True)

    # ca init
    init_p = ca_sub.add_parser("init", help="Initialize self-signed Root CA")
    init_p.add_argument("--subject", required=True)
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int, default=None)
    init_p.add_argument("--passphrase-file", required=True)
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)
    init_p.add_argument("--log-file", default=None)
    init_p.add_argument("--force", action="store_true")

    # ca issue-intermediate
    inter_p = ca_sub.add_parser("issue-intermediate", help="Issue Intermediate CA")
    inter_p.add_argument("--root-key", default="./pki/private/ca.key.pem")
    inter_p.add_argument("--root-cert", default="./pki/certs/ca.cert.pem")
    inter_p.add_argument("--root-passphrase-file", required=True)
    inter_p.add_argument("--subject", required=True)
    inter_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    inter_p.add_argument("--key-size", type=int, default=None)
    inter_p.add_argument("--validity-days", type=int, default=1825)
    inter_p.add_argument("--pathlen", type=int, default=0)
    inter_p.add_argument("--inter-passphrase-file", required=True)
    inter_p.add_argument("--out-dir", default="./pki")
    inter_p.add_argument("--force", action="store_true")
    inter_p.add_argument("--log-file", default=None)

    # ca issue-cert
    issue_p = ca_sub.add_parser("issue-cert", help="Issue end-entity certificate")
    issue_p.add_argument("--ca-key", default="./pki/private/ca.key.pem")
    issue_p.add_argument("--ca-cert", default="./pki/certs/ca.cert.pem")
    issue_p.add_argument("--ca-passphrase-file", required=True)
    issue_p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    issue_p.add_argument("--subject", required=True)
    issue_p.add_argument("--san", action="append", default=[])
    issue_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    issue_p.add_argument("--key-size", type=int, default=None)
    issue_p.add_argument("--validity-days", type=int, default=398)
    issue_p.add_argument("--out-dir", default="./issued")
    issue_p.add_argument("--force", action="store_true")
    issue_p.add_argument("--log-file", default=None)

    # ca issue-cert-from-csr
    csr_issue_p = ca_sub.add_parser("issue-cert-from-csr", help="Issue certificate from CSR")
    csr_issue_p.add_argument("--csr", required=True)
    csr_issue_p.add_argument("--ca-key", default="./pki/private/ca.key.pem")
    csr_issue_p.add_argument("--ca-cert", default="./pki/certs/ca.cert.pem")
    csr_issue_p.add_argument("--ca-passphrase-file", required=True)
    csr_issue_p.add_argument("--validity-days", type=int, default=365)
    csr_issue_p.add_argument("--out-cert", default="./pki/certs/client.cert.pem")
    csr_issue_p.add_argument("--out-dir", default="./issued")
    csr_issue_p.add_argument("--log-file", default=None)

    # ca revoke
    revoke_p = ca_sub.add_parser("revoke", help="Revoke a certificate")
    revoke_p.add_argument("--serial", required=True)
    revoke_p.add_argument("--reason", type=int, default=0)
    revoke_p.add_argument("--out-dir", default="./pki")
    revoke_p.add_argument("--log-file", default=None)

    # ca generate-crl
    crl_p = ca_sub.add_parser("generate-crl", help="Generate CRL")
    crl_p.add_argument("--ca-key", default="./pki/private/ca.key.pem")
    crl_p.add_argument("--ca-cert", default="./pki/certs/ca.cert.pem")
    crl_p.add_argument("--ca-passphrase-file", required=True)
    crl_p.add_argument("--validity-days", type=int, default=30)
    crl_p.add_argument("--out-dir", default="./pki")
    crl_p.add_argument("--log-file", default=None)

    # ca issue-ocsp-cert
    ocsp_p = ca_sub.add_parser("issue-ocsp-cert", help="Issue OCSP Responder certificate")
    ocsp_p.add_argument("--subject", required=True)
    ocsp_p.add_argument("--san", action="append", default=[])
    ocsp_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    ocsp_p.add_argument("--key-size", type=int, default=None)
    ocsp_p.add_argument("--validity-days", type=int, default=30)
    ocsp_p.add_argument("--ca-key", default="./pki/private/ca.key.pem")
    ocsp_p.add_argument("--ca-cert", default="./pki/certs/ca.cert.pem")
    ocsp_p.add_argument("--ca-passphrase-file", required=True)
    ocsp_p.add_argument("--out-dir", default="./pki")
    ocsp_p.add_argument("--force", action="store_true")
    ocsp_p.add_argument("--log-file", default=None)

    # ca serve-ocsp
    serve_p = ca_sub.add_parser("serve-ocsp", help="Start OCSP responder server")
    serve_p.add_argument("--responder-cert", default="./pki/certs/ocsp.cert.pem")
    serve_p.add_argument("--responder-key", default="./pki/private/ocsp.key.pem")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8080)
    serve_p.add_argument("--log-file", default=None)

    # db
    db_p = subparsers.add_parser("db", help="Database operations")
    db_sub = db_p.add_subparsers(dest="db_action", required=True)
    init_db_p = db_sub.add_parser("init", help="Initialize certificate database")
    init_db_p.add_argument("--out-dir", default="./pki")
    init_db_p.add_argument("--log-file", default=None)

    list_p = ca_sub.add_parser("list-certs", help="List certificates from database")
    list_p.add_argument("--status", choices=["valid", "revoked", "expired"], default="valid")
    list_p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    list_p.add_argument("--out-dir", default="./pki")
    list_p.add_argument("--log-file", default=None)

    show_p = ca_sub.add_parser("show-cert", help="Show certificate by serial")
    show_p.add_argument("serial", help="Serial number in hex")
    show_p.add_argument("--out-dir", default="./pki")
    show_p.add_argument("--log-file", default=None)

    # ==================== CLIENT COMMANDS ====================
    client_parser = subparsers.add_parser("client", help="Client-side operations")
    client_sub = client_parser.add_subparsers(dest="client_action", required=True)

    gen_csr_p = client_sub.add_parser("gen-csr", help="Generate private key and CSR")
    gen_csr_p.add_argument("--subject", required=True)
    gen_csr_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    gen_csr_p.add_argument("--key-size", type=int, default=None)
    gen_csr_p.add_argument("--san", action="append", default=[])
    gen_csr_p.add_argument("--out-key", default="./pki/private/client.key.pem")
    gen_csr_p.add_argument("--out-csr", default="./pki/certs/client.csr.pem")

    request_p = client_sub.add_parser("request-cert", help="Send CSR to CA and get signed certificate")
    request_p.add_argument("--csr", required=True)
    request_p.add_argument("--ca-passphrase-file", required=True)
    request_p.add_argument("--out-cert", default="./pki/certs/client.cert.pem")
    request_p.add_argument("--validity-days", type=int, default=365)
    request_p.add_argument("--log-file", default=None)

    args = parser.parse_args()
    logger = setup_logger(args.log_file if hasattr(args, "log_file") else None)

    try:
        if args.command == "db" and args.db_action == "init":
            db_path = get_db_path(args.out_dir)
            init_db(db_path, logger)

        elif args.command == "ca":
            if args.ca_action == "init":
                if args.key_type == "rsa":
                    args.key_size = args.key_size or 4096
                else:
                    args.key_size = args.key_size or 384
                init_ca(args, logger)

            elif args.ca_action == "issue-intermediate":
                with open(args.root_passphrase_file, "rb") as f:
                    root_pass = f.read().strip()
                with open(args.inter_passphrase_file, "rb") as f:
                    inter_pass = f.read().strip()
                issue_intermediate_ca(args, root_pass, inter_pass, logger)

            elif args.ca_action == "issue-cert":
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                issue_end_entity_cert(args, ca_pass, logger)

            elif args.ca_action == "issue-cert-from-csr":
                from .ca import issue_cert_from_csr
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key(args.ca_key, ca_pass)
                ca_cert = load_certificate(args.ca_cert)
                issue_cert_from_csr(args, ca_key, ca_cert, logger)

            elif args.ca_action == "revoke":
                from .repository import revoke_cert
                db_path = get_db_path(args.out_dir)
                revoke_cert(db_path, args.serial, args.reason, logger)

            elif args.ca_action == "generate-crl":
                from .crl import generate_crl
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key(args.ca_key, ca_pass)
                ca_cert = load_certificate(args.ca_cert)
                generate_crl(args, ca_key, ca_cert, logger)

            elif args.ca_action == "issue-ocsp-cert":
                from .ocsp import issue_ocsp_cert
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key(args.ca_key, ca_pass)
                ca_cert = load_certificate(args.ca_cert)
                issue_ocsp_cert(args, ca_key, ca_cert, logger)

            elif args.ca_action == "serve-ocsp":
                from .ocsp_responder import serve_ocsp
                serve_ocsp(args, logger)

            elif args.ca_action == "list-certs":
                from .repository import list_certs
                list_certs(get_db_path(args.out_dir), args.status, args.format, logger)

            elif args.ca_action == "show-cert":
                from .repository import show_cert
                show_cert(get_db_path(args.out_dir), args.serial, logger)

            else:
                logger.error(f"Unknown ca subcommand: {args.ca_action}")

        elif args.command == "client":
            if args.client_action == "gen-csr":
                from .client import gen_csr
                gen_csr(args)
            elif args.client_action == "request-cert":
                from .ca import issue_cert_from_csr
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key("./pki/private/ca.key.pem", ca_pass)
                ca_cert = load_certificate("./pki/certs/ca.cert.pem")
                issue_cert_from_csr(args, ca_key, ca_cert, logger)
            else:
                logger.error(f"Unknown client subcommand: {args.client_action}")

        else:
            logger.error(f"Unknown command: {args.command}")

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()