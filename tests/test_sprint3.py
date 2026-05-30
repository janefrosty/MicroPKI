import os
import sys
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from micropki.ca import issue_cert_from_csr
from micropki.crypto_utils import load_encrypted_private_key, load_certificate
from unittest.mock import MagicMock
from micropki.audit import AuditLogger

def test_sprint3_gen_csr_rsa_valid(temp_pki_dir):
    cmd = [
        sys.executable, "-m", "micropki.cli", "client", "gen-csr",
        "--subject", "/CN=rsaclient", "--key-type", "rsa",
        "--out-key", os.path.join(temp_pki_dir, "key.pem"),
        "--out-csr", os.path.join(temp_pki_dir, "csr.pem")
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    assert os.path.exists(os.path.join(temp_pki_dir, "csr.pem"))

def test_sprint3_gen_csr_ecc_valid(temp_pki_dir):
    cmd = [
        sys.executable, "-m", "micropki.cli", "client", "gen-csr",
        "--subject", "/CN=eccclient", "--key-type", "ecc",
        "--out-key", os.path.join(temp_pki_dir, "key.pem"),
        "--out-csr", os.path.join(temp_pki_dir, "csr.pem")
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    assert os.path.exists(os.path.join(temp_pki_dir, "csr.pem"))

def test_sprint3_issue_from_csr_valid(temp_pki_dir, passphrase_file):
    subprocess.run([
        sys.executable, "-m", "micropki.cli", "ca", "init",
        "--subject", "/CN=TestCA", "--passphrase-file", passphrase_file,
        "--out-dir", temp_pki_dir, "--force"
    ], check=True, capture_output=True, text=True)

    csr_file = os.path.join(temp_pki_dir, "client.csr.pem")
    key_file = os.path.join(temp_pki_dir, "client.key.pem")
    subprocess.run([
        sys.executable, "-m", "micropki.cli", "client", "gen-csr",
        "--subject", "/CN=csrclient", "--key-type", "rsa",
        "--out-key", key_file, "--out-csr", csr_file
    ], check=True, capture_output=True, text=True)

    with open(passphrase_file, "rb") as f:
        ca_pass = f.read().strip()
    ca_key = load_encrypted_private_key(os.path.join(temp_pki_dir, "private", "ca.key.pem"), ca_pass)
    ca_cert = load_certificate(os.path.join(temp_pki_dir, "certs", "ca.cert.pem"))
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    args = type('Args', (), {
        'csr': csr_file,
        'out_cert': os.path.join(temp_pki_dir, "certs", "issued.cert.pem"),
        'validity_days': 365,
        'out_dir': temp_pki_dir
    })()
    issue_cert_from_csr(args, ca_key, ca_cert, MagicMock(), audit, None)
    assert os.path.exists(args.out_cert)

def test_sprint3_issue_from_csr_invalid_csr_fails(temp_pki_dir, passphrase_file):
    subprocess.run([
        sys.executable, "-m", "micropki.cli", "ca", "init",
        "--subject", "/CN=TestCA", "--passphrase-file", passphrase_file,
        "--out-dir", temp_pki_dir, "--force"
    ], check=True, capture_output=True, text=True)
    cmd = [
        sys.executable, "-m", "micropki.cli", "ca", "issue-cert-from-csr",
        "--csr", os.path.join(temp_pki_dir, "nonexistent.csr"),
        "--ca-passphrase-file", passphrase_file,
        "--out-cert", os.path.join(temp_pki_dir, "cert.pem")
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0

def test_sprint3_issue_from_csr_without_ca_init_fails(temp_pki_dir, passphrase_file):
    csr_file = os.path.join(temp_pki_dir, "csr.pem")
    subprocess.run([
        sys.executable, "-m", "micropki.cli", "client", "gen-csr",
        "--subject", "/CN=test", "--out-csr", csr_file
    ], check=True, capture_output=True, text=True)
    cmd = [
        sys.executable, "-m", "micropki.cli", "ca", "issue-cert-from-csr",
        "--csr", csr_file, "--ca-passphrase-file", passphrase_file,
        "--out-cert", os.path.join(temp_pki_dir, "cert.pem")
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0