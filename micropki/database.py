import sqlite3
import os
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import serialization

def get_db_path(out_dir: str = "./pki") -> str:
    return os.path.join(out_dir, "micropki.db")

def get_db_connection(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str, logger):
    os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_hex TEXT UNIQUE NOT NULL,
            subject TEXT NOT NULL,
            issuer TEXT NOT NULL,
            not_before TEXT NOT NULL,
            not_after TEXT NOT NULL,
            pem TEXT NOT NULL,
            status TEXT DEFAULT 'valid' CHECK(status IN ('valid', 'revoked', 'expired')),
            revoked_at TEXT,
            revocation_reason TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS compromised_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key_hash TEXT UNIQUE NOT NULL,
            certificate_serial TEXT NOT NULL,
            compromise_date TEXT NOT NULL,
            compromise_reason TEXT NOT NULL,
            FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_compromised_keys_hash ON compromised_keys(public_key_hash)")
    
    conn.commit()
    conn.close()
    logger.info(f"База данных инициализирована: {db_path}")

def save_cert_to_db(db_path: str, cert, issuer_name: str, logger):
    init_db(db_path, logger)

    serial_hex = format(cert.serial_number, 'x').upper()
    subject_str = str(cert.subject)
    not_before = cert.not_valid_before_utc.isoformat()
    not_after = cert.not_valid_after_utc.isoformat()
    pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO certificates 
            (serial_hex, subject, issuer, not_before, not_after, pem, status)
            VALUES (?, ?, ?, ?, ?, ?, 'valid')
        """, (serial_hex, subject_str, issuer_name, not_before, not_after, pem))
        conn.commit()
        logger.info(f"Сертификат сохранён в БД. Serial: {serial_hex}")
    except sqlite3.IntegrityError:
        logger.warning(f"Сертификат с serial {serial_hex} уже существует.")
    except Exception as e:
        logger.error(f"Ошибка при сохранении в БД: {e}")
    finally:
        conn.close()

def get_public_key_hash(public_key) -> str:
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(pub_der).hexdigest()

def is_key_compromised(db_path: str, public_key) -> bool:
    key_hash = get_public_key_hash(public_key)
    conn = get_db_connection(db_path)
    cursor = conn.execute("SELECT 1 FROM compromised_keys WHERE public_key_hash = ?", (key_hash,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def add_compromised_key(db_path: str, public_key_hash: str, cert_serial: str, reason: str, logger):
    conn = get_db_connection(db_path)
    now = datetime.utcnow().isoformat()
    try:
        conn.execute(
            "INSERT INTO compromised_keys (public_key_hash, certificate_serial, compromise_date, compromise_reason) VALUES (?, ?, ?, ?)",
            (public_key_hash, cert_serial, now, reason)
        )
        conn.commit()
        logger.info(f"Скомпрометированный ключ добавлен для сертификата {cert_serial}")
    except sqlite3.IntegrityError:
        logger.warning(f"Ключ для сертификата {cert_serial} уже был в compromised_keys.")
    finally:
        conn.close()

def get_certificate_by_serial(db_path: str, serial_hex: str):
    conn = get_db_connection(db_path)
    cursor = conn.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
    row = cursor.fetchone()
    conn.close()
    return row

def revoke_certificate(db_path: str, serial_hex: str, reason: int, logger):
    conn = get_db_connection(db_path)
    now = datetime.utcnow().isoformat()
    conn.execute(
        "UPDATE certificates SET status = 'revoked', revoked_at = ?, revocation_reason = ? WHERE serial_hex = ? AND status = 'valid'",
        (now, reason, serial_hex.upper())
    )
    conn.commit()
    conn.close()
    logger.info(f"Сертификат {serial_hex} отозван.")