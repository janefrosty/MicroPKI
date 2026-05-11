import os
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from .crypto_utils import generate_key, parse_dn


def gen_csr(args):
    subject = parse_dn(args.subject)

    key_size = args.key_size if args.key_size is not None else (2048 if args.key_type == "rsa" else 256)
    private_key = generate_key(args.key_type, key_size)

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    if args.san:
        san_list = [x509.DNSName(s[4:]) for s in args.san if s.startswith("dns:")]
        if san_list:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    csr = builder.sign(private_key, hashes.SHA256())

    os.makedirs(os.path.dirname(args.out_key), exist_ok=True)
    os.makedirs(os.path.dirname(args.out_csr), exist_ok=True)

    with open(args.out_key, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(args.out_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"Private key saved: {args.out_key}")
    print(f"CSR saved:         {args.out_csr}")