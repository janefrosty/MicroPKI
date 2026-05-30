import os
import subprocess
import sys
import gc
from cryptography import x509
from micropki.ca import issue_end_entity_cert
from micropki.repository import revoke_cert
from micropki.crl import generate_crl
from micropki.crypto_utils import load_encrypted_private_key, load_certificate
from unittest.mock import MagicMock
from micropki.audit import AuditLogger

def setup_ca_and_issue_cert(temp_pki_dir, passphrase_file, cn="revokeme"):
    subprocess.run([
        sys.executable, "-m", "micropki.cli", "ca", "init",
        "--subject", "/CN=TestCA", "--passphrase-file", passphrase_file,
        "--out-dir", temp_pki_dir, "--force"
    ], check=True, capture_output=True, text=True)
    with open(passphrase_file, "rb") as f:
        ca_pass = f.read().strip()
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    args = type('Args', (), {
        'ca_key': os.path.join(temp_pki_dir, "private", "ca.key.pem"),
        'ca_cert': os.path.join(temp_pki_dir, "certs", "ca.cert.pem"),
        'template': 'client',
        'subject': f"/CN={cn}",
        'san': [],
        'key_type': 'rsa',
        'key_size': 2048,
        'validity_days': 365,
        'force': True,
        'out_dir': temp_pki_dir
    })()
    issue_end_entity_cert(args, ca_pass, MagicMock(), audit, None)
    cert_path = os.path.join(temp_pki_dir, "certs", f"{cn}.cert.pem")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    del audit
    gc.collect()
    return format(cert.serial_number, 'x').upper()

def test_sprint4_revoke_certificate(temp_pki_dir, passphrase_file):
    serial = setup_ca_and_issue_cert(temp_pki_dir, passphrase_file, "revoke1")
    db_path = os.path.join(temp_pki_dir, "micropki.db")
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    success = revoke_cert(db_path, serial, 1, MagicMock(), audit)
    assert success is True
    del audit
    gc.collect()

def test_sprint4_revoke_nonexistent_cert_fails(temp_pki_dir, passphrase_file):
    setup_ca_and_issue_cert(temp_pki_dir, passphrase_file, "dummy")
    db_path = os.path.join(temp_pki_dir, "micropki.db")
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    success = revoke_cert(db_path, "DEADBEEF", 1, MagicMock(), audit)
    assert success is False
    del audit
    gc.collect()

def test_sprint4_revoke_already_revoked_cert_fails(temp_pki_dir, passphrase_file):
    serial = setup_ca_and_issue_cert(temp_pki_dir, passphrase_file, "revoke2")
    db_path = os.path.join(temp_pki_dir, "micropki.db")
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    revoke_cert(db_path, serial, 1, MagicMock(), audit)
    success2 = revoke_cert(db_path, serial, 1, MagicMock(), audit)
    assert success2 is False
    del audit
    gc.collect()

def test_sprint4_generate_crl_contains_revoked_cert(temp_pki_dir, passphrase_file):
    serial = setup_ca_and_issue_cert(temp_pki_dir, passphrase_file, "crl_test")
    db_path = os.path.join(temp_pki_dir, "micropki.db")
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    revoke_cert(db_path, serial, 1, MagicMock(), audit)
    with open(passphrase_file, "rb") as f:
        ca_pass = f.read().strip()
    ca_key = load_encrypted_private_key(os.path.join(temp_pki_dir, "private", "ca.key.pem"), ca_pass)
    ca_cert = load_certificate(os.path.join(temp_pki_dir, "certs", "ca.cert.pem"))
    args = type('Args', (), {
        'out_dir': temp_pki_dir,
        'validity_days': 30
    })()
    crl_path = generate_crl(args, ca_key, ca_cert, MagicMock(), audit)
    assert os.path.exists(crl_path)
    with open(crl_path, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())
    revoked_serials = [rcert.serial_number for rcert in crl]
    assert int(serial, 16) in revoked_serials
    del audit
    gc.collect()

def test_sprint4_crl_multiple_revoked_certs(temp_pki_dir, passphrase_file):
    serial1 = setup_ca_and_issue_cert(temp_pki_dir, passphrase_file, "multi1")
    serial2 = setup_ca_and_issue_cert(temp_pki_dir, passphrase_file, "multi2")
    db_path = os.path.join(temp_pki_dir, "micropki.db")
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    revoke_cert(db_path, serial1, 1, MagicMock(), audit)
    revoke_cert(db_path, serial2, 1, MagicMock(), audit)
    with open(passphrase_file, "rb") as f:
        ca_pass = f.read().strip()
    ca_key = load_encrypted_private_key(os.path.join(temp_pki_dir, "private", "ca.key.pem"), ca_pass)
    ca_cert = load_certificate(os.path.join(temp_pki_dir, "certs", "ca.cert.pem"))
    args = type('Args', (), {
        'out_dir': temp_pki_dir,
        'validity_days': 30
    })()
    crl_path = generate_crl(args, ca_key, ca_cert, MagicMock(), audit)
    with open(crl_path, "rb") as f:
        crl = x509.load_pem_x509_crl(f.read())
    revoked_serials = [rcert.serial_number for rcert in crl]
    assert int(serial1, 16) in revoked_serials
    assert int(serial2, 16) in revoked_serials
    del audit
    gc.collect()