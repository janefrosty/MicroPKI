# micropki/templates.py
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa

def get_extensions_for_template(template: str, key_type: str, san_list: list) -> list:

    extensions = []

    if template == "server":
        extensions.extend([
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.KeyUsage(
                digital_signature=True,
                key_encipherment=(key_type == "rsa"),
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), True),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        ])
        if san_list:
            extensions.append((x509.SubjectAlternativeName(san_list), False))

    elif template == "client":
        extensions.extend([
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), True),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        ])
        if san_list:
            extensions.append((x509.SubjectAlternativeName(san_list), False))

    elif template == "code_signing":
        extensions.extend([
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=True,  # non-repudiation
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), True),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False),
        ])
        if san_list:
            extensions.append((x509.SubjectAlternativeName(san_list), False))

    else:
        raise ValueError(f"Неизвестный шаблон: {template}")

    return extensions