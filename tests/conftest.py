import os
import tempfile
import pytest

@pytest.fixture
def temp_pki_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "private"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "certs"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "crl"), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, "audit"), exist_ok=True)
        yield tmpdir

@pytest.fixture
def passphrase_file(temp_pki_dir):
    path = os.path.join(temp_pki_dir, "ca.pass")
    with open(path, "wb") as f:
        f.write(b"testpass")
    return path