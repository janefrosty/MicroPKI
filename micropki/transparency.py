import json
import hashlib
import os
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def log_certificate(cert_path: str, ct_log_path: str):
    """Записывает информацию о выпущенном сертификате в CT-лог."""
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())
    
    # Вычисляем SHA-256 fingerprint сертификата
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(cert_der).hexdigest()

    entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'serial': format(cert.serial_number, 'x'),
        'subject': cert.subject.rfc4514_string(),
        'fingerprint': fingerprint
    }

    os.makedirs(os.path.dirname(ct_log_path), exist_ok=True)
    with open(ct_log_path, 'a') as f:
        f.write(json.dumps(entry) + '\n')