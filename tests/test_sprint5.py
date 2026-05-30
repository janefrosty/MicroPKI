import os
import subprocess
import sys
import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from micropki.ocsp import issue_ocsp_cert
from micropki.crypto_utils import load_encrypted_private_key, load_certificate
from unittest.mock import MagicMock
from micropki.audit import AuditLogger

def setup_ca(temp_pki_dir, passphrase_file):
    subprocess.run([
        sys.executable, "-m", "micropki.cli", "ca", "init",
        "--subject", "/CN=TestCA", "--passphrase-file", passphrase_file,
        "--out-dir", temp_pki_dir, "--force"
    ], check=True, capture_output=True, text=True)
    with open(passphrase_file, "rb") as f:
        ca_pass = f.read().strip()
    ca_key = load_encrypted_private_key(os.path.join(temp_pki_dir, "private", "ca.key.pem"), ca_pass)
    ca_cert = load_certificate(os.path.join(temp_pki_dir, "certs", "ca.cert.pem"))
    return ca_key, ca_cert, ca_pass

def test_sprint5_issue_ocsp_cert_valid(temp_pki_dir, passphrase_file):
    ca_key, ca_cert, _ = setup_ca(temp_pki_dir, passphrase_file)
    args = type('Args', (), {
        'subject': '/CN=OCSP Responder',
        'san': [],
        'key_type': 'rsa',
        'key_size': 2048,
        'validity_days': 30,
        'out_dir': temp_pki_dir,
        'force': True
    })()
    issue_ocsp_cert(args, ca_key, ca_cert, MagicMock())
    cert_path = os.path.join(temp_pki_dir, "certs", "ocsp.cert.pem")
    assert os.path.exists(cert_path)
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.OCSP_SIGNING in eku.value

def test_sprint5_ocsp_cert_short_validity(temp_pki_dir, passphrase_file):
    ca_key, ca_cert, _ = setup_ca(temp_pki_dir, passphrase_file)
    args = type('Args', (), {
        'subject': '/CN=OCSP',
        'san': [],
        'key_type': 'rsa',
        'key_size': 2048,
        'validity_days': 30,
        'out_dir': temp_pki_dir,
        'force': True
    })()
    issue_ocsp_cert(args, ca_key, ca_cert, MagicMock())
    cert_path = os.path.join(temp_pki_dir, "certs", "ocsp.cert.pem")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    days = (cert.not_valid_after - cert.not_valid_before).days
    assert days <= 30

def test_sprint5_ocsp_responder_basic(temp_pki_dir, passphrase_file):
    from micropki.ocsp_responder import serve_ocsp
    assert callable(serve_ocsp)
