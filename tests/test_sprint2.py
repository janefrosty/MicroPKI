import os
import subprocess
import sys
import time
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from micropki.ca import issue_end_entity_cert
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
    ca_key_path = os.path.join(temp_pki_dir, "private", "ca.key.pem")
    ca_cert_path = os.path.join(temp_pki_dir, "certs", "ca.cert.pem")
    return ca_pass, ca_key_path, ca_cert_path

def test_sprint2_issue_server_cert_valid(temp_pki_dir, passphrase_file):
    ca_pass, ca_key, ca_cert = setup_ca(temp_pki_dir, passphrase_file)
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    args = type('Args', (), {
        'ca_key': ca_key,
        'ca_cert': ca_cert,
        'template': 'server',
        'subject': '/CN=test.example.com',
        'san': ['dns:test.example.com'],
        'key_type': 'rsa',
        'key_size': 2048,
        'validity_days': 365,
        'force': True,
        'out_dir': temp_pki_dir
    })()
    issue_end_entity_cert(args, ca_pass, MagicMock(), audit, None)
    # Имя файла: CN с точками заменяется на подчёркивания
    cert_path = os.path.join(temp_pki_dir, "certs", "test_example_com.cert.pem")
    time.sleep(0.2)
    assert os.path.exists(cert_path), f"File not found: {cert_path}. Directory contents: {os.listdir(os.path.join(temp_pki_dir, 'certs'))}"
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku.value

def test_sprint2_issue_client_cert_valid(temp_pki_dir, passphrase_file):
    ca_pass, ca_key, ca_cert = setup_ca(temp_pki_dir, passphrase_file)
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    args = type('Args', (), {
        'ca_key': ca_key,
        'ca_cert': ca_cert,
        'template': 'client',
        'subject': '/CN=client.local',
        'san': [],
        'key_type': 'rsa',
        'key_size': 2048,
        'validity_days': 365,
        'force': True,
        'out_dir': temp_pki_dir
    })()
    issue_end_entity_cert(args, ca_pass, MagicMock(), audit, None)
    cert_path = os.path.join(temp_pki_dir, "certs", "client_local.cert.pem")
    time.sleep(0.2)
    assert os.path.exists(cert_path), f"File not found: {cert_path}. Directory contents: {os.listdir(os.path.join(temp_pki_dir, 'certs'))}"
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

def test_sprint2_issue_code_signing_cert_valid(temp_pki_dir, passphrase_file):
    ca_pass, ca_key, ca_cert = setup_ca(temp_pki_dir, passphrase_file)
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    args = type('Args', (), {
        'ca_key': ca_key,
        'ca_cert': ca_cert,
        'template': 'code_signing',
        'subject': '/CN=codesign',
        'san': [],
        'key_type': 'rsa',
        'key_size': 2048,
        'validity_days': 365,
        'force': True,
        'out_dir': temp_pki_dir
    })()
    issue_end_entity_cert(args, ca_pass, MagicMock(), audit, None)
    cert_path = os.path.join(temp_pki_dir, "certs", "codesign.cert.pem")  # здесь без точек, имя не меняется
    time.sleep(0.2)
    assert os.path.exists(cert_path), f"File not found: {cert_path}. Directory contents: {os.listdir(os.path.join(temp_pki_dir, 'certs'))}"
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert ExtendedKeyUsageOID.CODE_SIGNING in eku.value

def test_sprint2_issue_cert_invalid_template_rejected(temp_pki_dir, passphrase_file):
    setup_ca(temp_pki_dir, passphrase_file)
    cmd = [
        sys.executable, "-m", "micropki.cli", "ca", "issue-cert",
        "--template", "invalid", "--subject", "/CN=bad",
        "--ca-passphrase-file", passphrase_file, "--out-dir", temp_pki_dir
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0
    assert "invalid choice" in result.stderr.lower()

def test_sprint2_issue_cert_missing_subject_rejected(temp_pki_dir, passphrase_file):
    setup_ca(temp_pki_dir, passphrase_file)
    cmd = [
        sys.executable, "-m", "micropki.cli", "ca", "issue-cert",
        "--template", "server", "--ca-passphrase-file", passphrase_file,
        "--out-dir", temp_pki_dir
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0
    assert "required" in result.stderr.lower()

def test_sprint2_issue_cert_without_san_should_still_work(temp_pki_dir, passphrase_file):
    ca_pass, ca_key, ca_cert = setup_ca(temp_pki_dir, passphrase_file)
    audit = AuditLogger(
        os.path.join(temp_pki_dir, "audit", "audit.log"),
        os.path.join(temp_pki_dir, "audit", "chain.dat")
    )
    args = type('Args', (), {
        'ca_key': ca_key,
        'ca_cert': ca_cert,
        'template': 'server',
        'subject': '/CN=no-san.local',
        'san': [],
        'key_type': 'rsa',
        'key_size': 2048,
        'validity_days': 365,
        'force': True,
        'out_dir': temp_pki_dir
    })()
    issue_end_entity_cert(args, ca_pass, MagicMock(), audit, None)
    cert_path = os.path.join(temp_pki_dir, "certs", "no-san_local.cert.pem")
    time.sleep(0.2)
    assert os.path.exists(cert_path), f"File not found: {cert_path}. Directory contents: {os.listdir(os.path.join(temp_pki_dir, 'certs'))}"