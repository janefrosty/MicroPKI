import sqlite3
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization

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

    conn.commit()
    conn.close()
    logger.info(f"База данных успешно инициализирована: {db_path}")

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
        logger.info(f"Сертификат успешно сохранён в БД. Serial: {serial_hex}")
    except sqlite3.IntegrityError:
        logger.warning(f"Сертификат с serial {serial_hex} уже существует в БД")
    except Exception as e:
        logger.error(f"Ошибка при сохранении в БД: {e}")
    finally:
        conn.close()