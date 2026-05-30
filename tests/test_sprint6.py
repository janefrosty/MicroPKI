import os
import subprocess
import sys
from cryptography import x509
from micropki.intermediate import issue_intermediate_ca
from unittest.mock import MagicMock

def setup_root_ca(temp_pki_dir, passphrase_file):
    subprocess.run([
        sys.executable, "-m", "micropki.cli", "ca", "init",
        "--subject", "/CN=RootCA", "--passphrase-file", passphrase_file,
        "--out-dir", temp_pki_dir, "--force"
    ], check=True, capture_output=True, text=True)
    
    class Args:
        root_key = os.path.join(temp_pki_dir, "private", "ca.key.pem")
        root_cert = os.path.join(temp_pki_dir, "certs", "ca.cert.pem")
        out_dir = temp_pki_dir
        force = True
        subject = "/CN=Intermediate CA"
        key_type = "rsa"
        key_size = 3072
        validity_days = 1825
        pathlen = 0
    return Args()

def test_sprint6_issue_intermediate_ca_valid(temp_pki_dir, passphrase_file):
    args = setup_root_ca(temp_pki_dir, passphrase_file)
    inter_pass_file = os.path.join(temp_pki_dir, "inter.pass")
    with open(inter_pass_file, "wb") as f:
        f.write(b"interpass")
    with open(passphrase_file, "rb") as f:
        root_pass = f.read().strip()
    with open(inter_pass_file, "rb") as f:
        inter_pass = f.read().strip()
    
    issue_intermediate_ca(args, root_pass, inter_pass, MagicMock())
    
    inter_cert = os.path.join(temp_pki_dir, "certs", "intermediate.cert.pem")
    assert os.path.exists(inter_cert)
    with open(inter_cert, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    assert bc.value.path_length == 0

def test_sprint6_intermediate_ca_pathlen_positive(temp_pki_dir, passphrase_file):
    args = setup_root_ca(temp_pki_dir, passphrase_file)
    args.pathlen = 2
    inter_pass_file = os.path.join(temp_pki_dir, "inter.pass")
    with open(inter_pass_file, "wb") as f:
        f.write(b"interpass")
    with open(passphrase_file, "rb") as f:
        root_pass = f.read().strip()
    with open(inter_pass_file, "rb") as f:
        inter_pass = f.read().strip()
    
    issue_intermediate_ca(args, root_pass, inter_pass, MagicMock())
    
    inter_cert = os.path.join(temp_pki_dir, "certs", "intermediate.cert.pem")
    with open(inter_cert, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.path_length == 2

def test_sprint6_intermediate_ca_rsa_key_size(temp_pki_dir, passphrase_file):
    args = setup_root_ca(temp_pki_dir, passphrase_file)
    args.key_size = 3072
    inter_pass_file = os.path.join(temp_pki_dir, "inter.pass")
    with open(inter_pass_file, "wb") as f:
        f.write(b"interpass")
    with open(passphrase_file, "rb") as f:
        root_pass = f.read().strip()
    with open(inter_pass_file, "rb") as f:
        inter_pass = f.read().strip()
    
    issue_intermediate_ca(args, root_pass, inter_pass, MagicMock())
    
    inter_cert = os.path.join(temp_pki_dir, "certs", "intermediate.cert.pem")
    with open(inter_cert, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    assert cert.public_key().key_size >= 3072

def test_sprint6_intermediate_ca_ecc(temp_pki_dir, passphrase_file):
    args = setup_root_ca(temp_pki_dir, passphrase_file)
    args.key_type = "ecc"
    args.key_size = 384
    inter_pass_file = os.path.join(temp_pki_dir, "inter.pass")
    with open(inter_pass_file, "wb") as f:
        f.write(b"interpass")
    with open(passphrase_file, "rb") as f:
        root_pass = f.read().strip()
    with open(inter_pass_file, "rb") as f:
        inter_pass = f.read().strip()
    
    issue_intermediate_ca(args, root_pass, inter_pass, MagicMock())
    
    inter_cert = os.path.join(temp_pki_dir, "certs", "intermediate.cert.pem")
    assert os.path.exists(inter_cert)