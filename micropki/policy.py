from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# --- Конфигурация политик по умолчанию (согласно спецификации) ---
POLICIES = {
    'rsa_min': {'root': 4096, 'intermediate': 3072, 'end': 2048},
    'ecc_min': {'root': 384, 'intermediate': 384, 'end': 256},
    'max_validity_days': {'root': 3650, 'intermediate': 1825, 'end': 365},
    'allowed_san': {
        'server': ['dns', 'ip'],
        'client': ['email', 'dns'],
        'code_signing': ['dns', 'uri']
    }
}

def enforce_key_size(pub_key, template: str, is_ca: bool):
    """Проверяет, соответствует ли размер ключа минимальным требованиям."""
    min_size = None
    if isinstance(pub_key, rsa.RSAPublicKey):
        size = pub_key.key_size
        if is_ca:
            required = POLICIES['rsa_min'].get(template, POLICIES['rsa_min']['intermediate'])
            if size < required:
                raise ValueError(f'RSA-ключ для {template} CA должен быть не менее {required} бит (текущий: {size})')
        else:
            if size < POLICIES['rsa_min']['end']:
                raise ValueError(f'RSA-ключ для конечного сертификата должен быть не менее {POLICIES["rsa_min"]["end"]} бит (текущий: {size})')
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        size = pub_key.curve.key_size
        if is_ca:
            if size < POLICIES['ecc_min']['root']:
                raise ValueError(f'ECC-ключ для CA должен быть не менее {POLICIES["ecc_min"]["root"]} бит (текущий: {size})')
        else:
            if size < POLICIES['ecc_min']['end']:
                raise ValueError(f'ECC-ключ для конечного сертификата должен быть не менее {POLICIES["ecc_min"]["end"]} бит (текущий: {size})')
    else:
        raise ValueError('Неподдерживаемый тип ключа')

def enforce_validity(template: str, days: int):
    """Проверяет, не превышает ли запрошенный срок действия максимально допустимый."""
    max_days = POLICIES['max_validity_days'].get(template, 365)
    if days > max_days:
        raise ValueError(f'Срок действия в {days} дней превышает максимум в {max_days} дней для {template}')

def enforce_san(san_extensions, template: str):
    """Проверяет, что типы SAN соответствуют разрешенным для данного шаблона."""
    allowed_types = POLICIES['allowed_san'].get(template, [])
    for san in san_extensions:
        if isinstance(san, x509.DNSName):
            if 'dns' not in allowed_types:
                raise ValueError(f'DNS-имя не разрешено для сертификата типа "{template}"')
            # Проверка на wildcard (требование POL-5)
            if san.value.startswith('*.'):
                raise ValueError(f'Wildcard DNS-имена (например, {san.value}) не разрешены.')
        elif isinstance(san, x509.IPAddress):
            if 'ip' not in allowed_types:
                raise ValueError(f'IP-адрес не разрешен для сертификата типа "{template}"')
        elif isinstance(san, x509.RFC822Name):
            if 'email' not in allowed_types:
                raise ValueError(f'Email не разрешен для сертификата типа "{template}"')