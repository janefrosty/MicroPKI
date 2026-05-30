import os
import sys
import subprocess
from cryptography import x509

def test_sprint1_init_root_ca_rsa_valid(temp_pki_dir, passphrase_file):
    cmd = [
        sys.executable, "-m", "micropki.cli", "ca", "init",
        "--subject", "/CN=RSARoot", "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", passphrase_file, "--out-dir", temp_pki_dir,
        "--validity-days", "3650", "--force"
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    cert_path = os.path.join(temp_pki_dir, "certs", "ca.cert.pem")
    assert os.path.exists(cert_path)
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    assert cert.subject == cert.issuer
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True

def test_sprint1_init_root_ca_ecc_valid(temp_pki_dir, passphrase_file):
    cmd = [
        sys.executable, "-m", "micropki.cli", "ca", "init",
        "--subject", "/CN=ECCRoot", "--key-type", "ecc", "--key-size", "384",
        "--passphrase-file", passphrase_file, "--out-dir", temp_pki_dir, "--force"
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    cert_path = os.path.join(temp_pki_dir, "certs", "ca.cert.pem")
    assert os.path.exists(cert_path)

def test_sprint1_init_root_ca_force_overwrite(temp_pki_dir, passphrase_file):
    cmd1 = [sys.executable, "-m", "micropki.cli", "ca", "init",
            "--subject", "/CN=First", "--passphrase-file", passphrase_file,
            "--out-dir", temp_pki_dir, "--force"]
    subprocess.run(cmd1, check=True, capture_output=True, text=True)
    cmd2 = [sys.executable, "-m", "micropki.cli", "ca", "init",
            "--subject", "/CN=Second", "--passphrase-file", passphrase_file,
            "--out-dir", temp_pki_dir, "--force"]
    subprocess.run(cmd2, check=True, capture_output=True, text=True)
    cert_path = os.path.join(temp_pki_dir, "certs", "ca.cert.pem")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "Second"

def test_sprint1_init_root_ca_no_force_fails_if_exists(temp_pki_dir, passphrase_file):
    cmd1 = [sys.executable, "-m", "micropki.cli", "ca", "init",
            "--subject", "/CN=Root", "--passphrase-file", passphrase_file,
            "--out-dir", temp_pki_dir, "--force"]
    subprocess.run(cmd1, check=True, capture_output=True, text=True)
    cmd2 = [sys.executable, "-m", "micropki.cli", "ca", "init",
            "--subject", "/CN=Root2", "--passphrase-file", passphrase_file,
            "--out-dir", temp_pki_dir]
    result = subprocess.run(cmd2, capture_output=True, text=True)
    assert "already exist" in result.stderr.lower() or "существуют" in result.stderr.lower()

def test_sprint1_init_root_ca_key_usage(temp_pki_dir, passphrase_file):
    cmd = [sys.executable, "-m", "micropki.cli", "ca", "init",
           "--subject", "/CN=KU", "--passphrase-file", passphrase_file,
           "--out-dir", temp_pki_dir, "--force"]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    cert_path = os.path.join(temp_pki_dir, "certs", "ca.cert.pem")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True