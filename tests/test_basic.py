import pytest
from micropki.crypto_utils import parse_dn
from cryptography.x509.oid import NameOID

def test_parse_dn():
    name1 = parse_dn("/CN=Test Root CA")
    assert name1.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test Root CA"

    name2 = parse_dn("CN=ECC CA,O=MicroPKI")
    attrs = {a.oid: a.value for a in name2}
    assert attrs[NameOID.COMMON_NAME] == "ECC CA"
    assert attrs[NameOID.ORGANIZATION_NAME] == "MicroPKI"