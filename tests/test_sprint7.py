# tests/test_sprint7.py
import os
import sys
import json
import pytest
import subprocess
import tempfile
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from micropki.database import get_db_path, init_db, is_key_compromised, get_public_key_hash
from micropki.audit import AuditLogger
from micropki.policy import enforce_key_size, enforce_validity, enforce_san
from micropki.ratelimit import RateLimit
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture
def temp_pki_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "audit"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "private"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "certs"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "crl"), exist_ok=True)
        yield tmpdir


class TestPolicyEnforcement:
    def test_weak_rsa_key_for_end_entity(self):
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with pytest.raises(ValueError, match="2048 бит"):
            enforce_key_size(weak_key.public_key(), "server", is_ca=False)

    def test_too_long_validity_for_leaf(self):
        with pytest.raises(ValueError, match="365 дней"):
            enforce_validity("server", 400)

    def test_wildcard_san_disallowed(self):
        san_ext = [x509.DNSName("*.example.com")]
        with pytest.raises(ValueError, match="Wildcard"):
            enforce_san(san_ext, "server")

    def test_email_san_for_code_signing_disallowed(self):
        san_ext = [x509.RFC822Name("user@example.com")]
        with pytest.raises(ValueError, match="не разрешен"):
            enforce_san(san_ext, "code_signing")

    def test_valid_dns_san_for_server_allowed(self):
        san_ext = [x509.DNSName("example.com")]
        enforce_san(san_ext, "server")


class TestAuditIntegrity:
    def test_audit_log_chain_verification(self, temp_pki_dir):
        log_path = os.path.join(temp_pki_dir, "audit", "audit.log")
        chain_path = os.path.join(temp_pki_dir, "audit", "chain.dat")
        logger = AuditLogger(log_path, chain_path)
        logger.log("AUDIT", "issue", "start", "Test issuance", {})
        logger.log("INFO", "revoke", "success", "Cert revoked", {"serial": "1234"})
        assert logger.verify_chain() is True

    def test_audit_tamper_detection(self, temp_pki_dir):
        log_path = os.path.join(temp_pki_dir, "audit", "audit.log")
        chain_path = os.path.join(temp_pki_dir, "audit", "chain.dat")
        logger = AuditLogger(log_path, chain_path)
        logger.log("AUDIT", "issue", "start", "Test issuance", {})
        with open(log_path, "rb+") as f:
            f.seek(100)
            f.write(b"\x00")
        assert logger.verify_chain() is False

    def test_audit_missing_entry(self, temp_pki_dir):
        log_path = os.path.join(temp_pki_dir, "audit", "audit.log")
        chain_path = os.path.join(temp_pki_dir, "audit", "chain.dat")
        logger = AuditLogger(log_path, chain_path)
        for i in range(3):
            logger.log("INFO", f"op{i}", "success", f"msg{i}", {})
        with open(log_path, "r") as f:
            lines = f.readlines()
        with open(log_path, "w") as f:
            f.writelines(lines[0::2])
        assert logger.verify_chain() is False


class TestRateLimit:
    def test_rate_limit_blocking(self):
        limiter = RateLimit(rate=2, burst=3)
        ip = "192.168.1.1"
        for _ in range(3):
            assert limiter.check(ip) is True
        assert limiter.check(ip) is False
        assert limiter.check(ip) is False

    def test_rate_limit_refill(self):
        limiter = RateLimit(rate=2, burst=3)
        ip = "192.168.1.1"
        for _ in range(3):
            limiter.check(ip)
        assert limiter.check(ip) is False
        import time
        time.sleep(1.2)
        assert limiter.check(ip) is True


class TestKeyCompromise:
    def test_compromised_key_reuse_blocked(self, temp_pki_dir):
        db_path = get_db_path(temp_pki_dir)
        init_db(db_path, MagicMock())
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        from micropki.database import add_compromised_key
        pub_hash = get_public_key_hash(key.public_key())
        add_compromised_key(db_path, pub_hash, "SERIAL123", "keyCompromise", MagicMock())
        assert is_key_compromised(db_path, key.public_key()) is True


class TestCTLog:
    def test_ct_log_contains_certificate_entry(self, temp_pki_dir):
        db_path = get_db_path(temp_pki_dir)
        init_db(db_path, MagicMock())
        from micropki.ca import issue_end_entity_cert
        from micropki.crypto_utils import generate_key, create_self_signed_cert, save_cert, save_encrypted_key
        ca_key = generate_key("rsa", 2048)
        ca_cert = create_self_signed_cert(ca_key, "/CN=TestCA", 365)
        save_cert(ca_cert, os.path.join(temp_pki_dir, "certs", "ca.cert.pem"))
        save_encrypted_key(ca_key, b"pass", os.path.join(temp_pki_dir, "private", "ca.key.pem"))
        
        class Args:
            template = "server"
            subject = "/CN=test.local"
            san = ["dns:test.local"]
            key_type = "rsa"
            key_size = 2048
            validity_days = 365
            force = True
            ca_key = os.path.join(temp_pki_dir, "private", "ca.key.pem")
            ca_cert = os.path.join(temp_pki_dir, "certs", "ca.cert.pem")
            out_dir = temp_pki_dir
        args = Args()
        ct_log_path = os.path.join(temp_pki_dir, "audit", "ct.log")
        audit_logger = AuditLogger(os.path.join(temp_pki_dir, "audit", "audit.log"),
                                   os.path.join(temp_pki_dir, "audit", "chain.dat"))
        issue_end_entity_cert(args, b"pass", MagicMock(), audit_logger, ct_log_path)
        assert os.path.exists(ct_log_path)
        with open(ct_log_path, "r") as f:
            content = f.read()
            assert "test.local" in content
