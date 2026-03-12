import argparse
import os
import sys

from .logger import setup_logger
from .ca import init_ca, issue_end_entity_cert
from .intermediate import issue_intermediate_ca


def main():
    parser = argparse.ArgumentParser(description="MicroPKI CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ca_parser = subparsers.add_parser("ca", help="Certificate Authority commands")
    ca_sub = ca_parser.add_subparsers(dest="ca_action", required=True)

    init_p = ca_sub.add_parser("init", help="Initialize self-signed Root CA")
    init_p.add_argument("--subject", required=True,
                        help="DN string, e.g. /CN=MyCA or CN=MyCA,O=Demo")
    init_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    init_p.add_argument("--key-size", type=int, default=None)
    init_p.add_argument("--passphrase-file", required=True,
                        help="Path to passphrase file")
    init_p.add_argument("--out-dir", default="./pki")
    init_p.add_argument("--validity-days", type=int, default=3650)
    init_p.add_argument("--log-file", default=None)
    init_p.add_argument("--force", action="store_true", help="Overwrite existing files")

    inter_p = ca_sub.add_parser("issue-intermediate",
                                help="Issue an Intermediate CA signed by Root")
    inter_p.add_argument("--root-key", default="./pki/private/ca.key.pem", help="Path to Root private key")
    inter_p.add_argument("--root-cert", default="./pki/certs/ca.cert.pem", help="Path to Root certificate")
    inter_p.add_argument("--root-passphrase-file", required=True, help="File with Root passphrase")
    inter_p.add_argument("--subject", required=True, help="Subject DN for Intermediate CA")
    inter_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    inter_p.add_argument("--key-size", type=int, default=None)
    inter_p.add_argument("--validity-days", type=int, default=1825, help="Validity period in days")
    inter_p.add_argument("--pathlen", type=int, default=0, help="pathLenConstraint (0 = no further sub-CAs)")
    inter_p.add_argument("--inter-passphrase-file", required=True, help="File with new Intermediate passphrase")
    inter_p.add_argument("--out-dir", default="./pki")
    inter_p.add_argument("--force", action="store_true")
    inter_p.add_argument("--log-file", default=None)

    issue_p = ca_sub.add_parser("issue-cert",
                                help="Issue end-entity certificate using template")
    issue_p.add_argument("--ca-key", default="./pki/private/ca.key.pem", help="CA private key (Root or Intermediate)")
    issue_p.add_argument("--ca-cert", default="./pki/certs/ca.cert.pem", help="CA certificate (Root or Intermediate)")
    issue_p.add_argument("--ca-passphrase-file", required=True, help="File with CA passphrase")
    issue_p.add_argument("--template", required=True, choices=["server", "client", "code_signing"])
    issue_p.add_argument("--subject", required=True, help="Subject DN")
    issue_p.add_argument("--san", action="append", default=[], help="Repeatable: dns:example.com ip:1.2.3.4 email:user@domain")
    issue_p.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    issue_p.add_argument("--key-size", type=int, default=None)
    issue_p.add_argument("--validity-days", type=int, default=398)
    issue_p.add_argument("--out-dir", default="./issued")
    issue_p.add_argument("--force", action="store_true")
    issue_p.add_argument("--log-file", default=None)

    args = parser.parse_args()

    logger = setup_logger(args.log_file if hasattr(args, "log_file") else None)

    try:
        if args.command == "ca":
            if args.ca_action == "init":
                if args.key_type == "rsa":
                    args.key_size = args.key_size or 4096
                    if args.key_size != 4096:
                        raise ValueError("--key-size must be 4096 for RSA")
                else:  # ecc
                    args.key_size = args.key_size or 384
                    if args.key_size != 384:
                        raise ValueError("--key-size must be 384 for ECC")

                if not os.path.isfile(args.passphrase_file):
                    raise FileNotFoundError(f"Passphrase file not found: {args.passphrase_file}")

                init_ca(args, logger)

            elif args.ca_action == "issue-intermediate":
                with open(args.root_passphrase_file, "rb") as f:
                    root_passphrase = f.read().strip()
                with open(args.inter_passphrase_file, "rb") as f:
                    inter_passphrase = f.read().strip()

                issue_intermediate_ca(args, root_passphrase, inter_passphrase, logger)

            elif args.ca_action == "issue-cert":
                with open(args.ca_passphrase_file, "rb") as f:
                    ca_passphrase = f.read().strip()

                issue_end_entity_cert(args, ca_passphrase, logger)

            else:
                logger.error(f"Unknown subcommand: ca {args.ca_action}")
                sys.exit(1)

        else:
            logger.error(f"Unknown command: {args.command}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()