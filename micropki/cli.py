import argparse
import os
import sys
from .logger import setup_logger
from .ca import init_ca, issue_end_entity_cert, issue_cert_from_csr
from .intermediate import issue_intermediate_ca
from .database import init_db, get_db_path, get_certificate_by_serial, add_compromised_key, revoke_certificate
from .crypto_utils import load_encrypted_private_key, load_certificate, load_pem_x509_certificate
from .audit import AuditLogger
from .repository import revoke_cert, list_certs, show_cert
from .crl import generate_crl
from .ocsp import issue_ocsp_cert
from .ocsp_responder import serve_ocsp

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

    # ca serve-ocsp (with rate limiting)
    serve_p = ca_sub.add_parser("serve-ocsp", help="Start OCSP responder server")
    serve_p.add_argument("--responder-cert", default="./pki/certs/ocsp.cert.pem")
    serve_p.add_argument("--responder-key", default="./pki/private/ocsp.key.pem")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8080)
    serve_p.add_argument("--rate-limit", type=int, default=5, help="Requests per second")
    serve_p.add_argument("--rate-burst", type=int, default=10, help="Burst size")
    serve_p.add_argument("--log-file", default=None)

    # ca compromise (new for sprint 7)
    comp_p = ca_sub.add_parser("compromise", help="Mark a certificate's key as compromised")
    comp_p.add_argument("--cert", required=True, help="Path to the certificate PEM file")
    comp_p.add_argument("--reason", default="keyCompromise")
    comp_p.add_argument("--ca-key", default="./pki/private/ca.key.pem")
    comp_p.add_argument("--ca-cert", default="./pki/certs/ca.cert.pem")
    comp_p.add_argument("--ca-passphrase-file", required=True)
    comp_p.add_argument("--out-dir", default="./pki")
    comp_p.add_argument("--force", action="store_true")
    comp_p.add_argument("--log-file", default=None)

    # ca list-certs
    list_p = ca_sub.add_parser("list-certs", help="List certificates from database")
    list_p.add_argument("--status", choices=["valid", "revoked", "expired"], default="valid")
    list_p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    list_p.add_argument("--out-dir", default="./pki")
    list_p.add_argument("--log-file", default=None)

    # ca show-cert
    show_p = ca_sub.add_parser("show-cert", help="Show certificate by serial")
    show_p.add_argument("serial", help="Serial number in hex")
    show_p.add_argument("--out-dir", default="./pki")
    show_p.add_argument("--log-file", default=None)

    # ==================== DB COMMANDS ====================
    db_p = subparsers.add_parser("db", help="Database operations")
    db_sub = db_p.add_subparsers(dest="db_action", required=True)
    init_db_p = db_sub.add_parser("init", help="Initialize certificate database")
    init_db_p.add_argument("--out-dir", default="./pki")
    init_db_p.add_argument("--log-file", default=None)

    # ==================== AUDIT COMMANDS (sprint 7) ====================
    audit_parser = subparsers.add_parser("audit", help="Audit log operations")
    audit_sub = audit_parser.add_subparsers(dest="audit_action", required=True)

    query_p = audit_sub.add_parser("query", help="Query audit log")
    query_p.add_argument("--from", dest="from_ts", help="Start timestamp (ISO 8601 or ns)")
    query_p.add_argument("--to", help="End timestamp (ISO 8601 or ns)")
    query_p.add_argument("--level", choices=["INFO", "WARNING", "ERROR", "AUDIT"])
    query_p.add_argument("--operation")
    query_p.add_argument("--serial")
    query_p.add_argument("--format", default="table", choices=["table", "json", "csv"])
    query_p.add_argument("--out-dir", default="./pki")
    query_p.add_argument("--log-file", default=None)

    verify_p = audit_sub.add_parser("verify", help="Verify audit log integrity")
    verify_p.add_argument("--log-file", default="./pki/audit/audit.log")
    verify_p.add_argument("--chain-file", default="./pki/audit/chain.dat")
    verify_p.add_argument("--log-file-cli", dest="log_file", default=None)  # for logger

    # ==================== REPOSITORY SERVER (sprint 7) ====================
    repo_parser = subparsers.add_parser("repo", help="Certificate repository server")
    repo_sub = repo_parser.add_subparsers(dest="repo_action", required=True)
    serve_repo_p = repo_sub.add_parser("serve", help="Start HTTP repository server")
    serve_repo_p.add_argument("--host", default="127.0.0.1")
    serve_repo_p.add_argument("--port", type=int, default=8081)
    serve_repo_p.add_argument("--rate-limit", type=int, default=5, help="Requests per second")
    serve_repo_p.add_argument("--rate-burst", type=int, default=10)
    serve_repo_p.add_argument("--repo-dir", default="./pki")
    serve_repo_p.add_argument("--log-file", default=None)

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

    # ========== Parsing and execution ==========
    args = parser.parse_args()
    logger = setup_logger(getattr(args, 'log_file', None))

    # Create audit logger (use out_dir if present, else current dir)
    base_dir = getattr(args, 'out_dir', '.')
    audit_log = AuditLogger(
        log_path=os.path.join(base_dir, 'audit', 'audit.log'),
        chain_path=os.path.join(base_dir, 'audit', 'chain.dat')
    )
    ct_log_path = os.path.join(base_dir, 'audit', 'ct.log')

    try:
        # ---------- DB ----------
        if args.command == "db" and args.db_action == "init":
            db_path = get_db_path(args.out_dir)
            init_db(db_path, logger)

        # ---------- CA ----------
        elif args.command == "ca":
            if args.ca_action == "init":
                if args.key_type == "rsa":
                    args.key_size = args.key_size or 4096
                else:
                    args.key_size = args.key_size or 384
                init_ca(args, logger, audit_log)

            elif args.ca_action == "issue-intermediate":
                with open(args.root_passphrase_file, "rb") as f:
                    root_pass = f.read().strip()
                with open(args.inter_passphrase_file, "rb") as f:
                    inter_pass = f.read().strip()
                # TODO: update issue_intermediate_ca to accept audit_log and ct_log_path
                issue_intermediate_ca(args, root_pass, inter_pass, logger)

            elif args.ca_action == "issue-cert":
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                issue_end_entity_cert(args, ca_pass, logger, audit_log, ct_log_path)

            elif args.ca_action == "issue-cert-from-csr":
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key(args.ca_key, ca_pass)
                ca_cert = load_certificate(args.ca_cert)
                issue_cert_from_csr(args, ca_key, ca_cert, logger, audit_log, ct_log_path)

            elif args.ca_action == "revoke":
                db_path = get_db_path(args.out_dir)
                revoke_cert(db_path, args.serial, args.reason, logger, audit_log)

            elif args.ca_action == "generate-crl":
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key(args.ca_key, ca_pass)
                ca_cert = load_certificate(args.ca_cert)
                generate_crl(args, ca_key, ca_cert, logger, audit_log)

            elif args.ca_action == "issue-ocsp-cert":
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key(args.ca_key, ca_pass)
                ca_cert = load_certificate(args.ca_cert)
                issue_ocsp_cert(args, ca_key, ca_cert, logger)

            elif args.ca_action == "serve-ocsp":
                serve_ocsp(args, logger, audit_log)

            elif args.ca_action == "compromise":
                # Simulate key compromise
                try:
                    cert = load_pem_x509_certificate(args.cert)
                    serial_hex = format(cert.serial_number, 'x').upper()
                    db_path = get_db_path(args.out_dir)
                    cert_row = get_certificate_by_serial(db_path, serial_hex)
                    if not cert_row:
                        logger.error(f"Certificate {serial_hex} not found in database")
                        audit_log.log('AUDIT', 'compromise', 'failure', 'Certificate not found in DB', {'cert': args.cert})
                        return
                    # Revoke if not already revoked (reason 1 = keyCompromise)
                    if cert_row['status'] != 'revoked':
                        revoke_certificate(db_path, serial_hex, 1, logger)
                    # Add public key hash to compromised_keys
                    from .database import get_public_key_hash
                    pub_key_hash = get_public_key_hash(cert.public_key())
                    add_compromised_key(db_path, pub_key_hash, serial_hex, args.reason, logger)
                    # Regenerate CRL immediately
                    logger.info("Generating emergency CRL...")
                    with open(args.ca_passphrase_file, "rb") as f:
                        ca_pass = f.read().strip()
                    ca_key = load_encrypted_private_key(args.ca_key, ca_pass)
                    ca_cert = load_certificate(args.ca_cert)
                    generate_crl(args, ca_key, ca_cert, logger, audit_log)
                    logger.info(f"Key for certificate {serial_hex} marked as compromised and revoked.")
                    audit_log.log('AUDIT', 'compromise', 'success', 'Key compromise simulated', {'serial': serial_hex, 'cert': args.cert})
                except Exception as e:
                    logger.error(f"Compromise simulation failed: {e}")
                    audit_log.log('AUDIT', 'compromise', 'failure', f'Error: {e}', {})

            elif args.ca_action == "list-certs":
                list_certs(get_db_path(args.out_dir), args.status, args.format, logger)

            elif args.ca_action == "show-cert":
                show_cert(get_db_path(args.out_dir), args.serial, logger)

            else:
                logger.error(f"Unknown ca subcommand: {args.ca_action}")

        # ---------- AUDIT ----------
        elif args.command == "audit":
            if args.audit_action == "verify":
                success = audit_log.verify_chain()
                sys.exit(0 if success else 1)
            elif args.audit_action == "query":
                # For simplicity, a basic implementation:
                log_file = os.path.join(args.out_dir, 'audit', 'audit.log')
                if not os.path.exists(log_file):
                    logger.error(f"Audit log not found: {log_file}")
                    return
                import json
                from tabulate import tabulate
                entries = []
                with open(log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        # filtering
                        if args.from_ts and entry['timestamp'] < int(args.from_ts):
                            continue
                        if args.to and entry['timestamp'] > int(args.to):
                            continue
                        if args.level and entry['level'] != args.level:
                            continue
                        if args.operation and entry['operation'] != args.operation:
                            continue
                        if args.serial:
                            serial_meta = entry.get('metadata', {}).get('serial')
                            if serial_meta != args.serial:
                                continue
                        entries.append(entry)
                if args.format == 'table':
                    table = []
                    for e in entries:
                        table.append([
                            e['timestamp'], e['level'], e['operation'],
                            e['status'], e['message'][:60]
                        ])
                    print(tabulate(table, headers=['Timestamp', 'Level', 'Operation', 'Status', 'Message'], tablefmt='grid'))
                elif args.format == 'json':
                    print(json.dumps(entries, indent=2))
                else:
                    import csv
                    writer = csv.writer(sys.stdout)
                    writer.writerow(['timestamp', 'level', 'operation', 'status', 'message', 'metadata'])
                    for e in entries:
                        writer.writerow([e['timestamp'], e['level'], e['operation'], e['status'], e['message'], json.dumps(e['metadata'])])
            else:
                logger.error(f"Unknown audit subcommand: {args.audit_action}")

        # ---------- REPOSITORY SERVER ----------
        elif args.command == "repo" and args.repo_action == "serve":
            from .repository_server import serve_repository
            serve_repository(args, logger, audit_log)

        # ---------- CLIENT ----------
        elif args.command == "client":
            if args.client_action == "gen-csr":
                from .client import gen_csr
                gen_csr(args)
            elif args.client_action == "request-cert":
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_pass = f.read().strip()
                ca_key = load_encrypted_private_key("./pki/private/ca.key.pem", ca_pass)
                ca_cert = load_certificate("./pki/certs/ca.cert.pem")
                # Create a dummy args object for issue_cert_from_csr
                class DummyArgs:
                    pass
                dummy = DummyArgs()
                dummy.csr = args.csr
                dummy.out_cert = args.out_cert
                dummy.validity_days = args.validity_days
                dummy.out_dir = "./pki"
                issue_cert_from_csr(dummy, ca_key, ca_cert, logger, audit_log, ct_log_path)
            else:
                logger.error(f"Unknown client subcommand: {args.client_action}")

        else:
            logger.error(f"Unknown command: {args.command}")

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()