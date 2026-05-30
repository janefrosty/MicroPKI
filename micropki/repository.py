from datetime import datetime, timezone
import sqlite3
from tabulate import tabulate

from .database import get_db_connection
from .audit import AuditLogger

def list_certs(db_path: str, status: str = "valid", output_format: str = "table", logger=None):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT serial_hex, subject, issuer, not_before, not_after, status 
        FROM certificates 
        WHERE status = ?
        ORDER BY id DESC
    """, (status,))

    rows = cursor.fetchall()
    conn.close()

    if not rows:
        if logger:
            logger.info(f"Сертификатов со статусом '{status}' не найдено.")
        else:
            print(f"Сертификатов со статусом '{status}' не найдено.")
        return

    headers = ["Serial (Hex)", "Subject", "Issuer", "Not Before", "Not After", "Status"]

    if output_format == "table":
        table_data = []
        for row in rows:
            table_data.append([
                row["serial_hex"],
                (row["subject"][:55] + "...") if len(row["subject"]) > 55 else row["subject"],
                (row["issuer"][:40] + "...") if len(row["issuer"]) > 40 else row["issuer"],
                row["not_before"][:10],
                row["not_after"][:10],
                row["status"]
            ])
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

    elif output_format == "json":
        import json
        data = [dict(row) for row in rows]
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        # csv
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([row["serial_hex"], row["subject"], row["issuer"], 
                            row["not_before"], row["not_after"], row["status"]])
        print(output.getvalue())


def show_cert(db_path: str, serial_hex: str, logger):
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
    row = cursor.fetchone()
    conn.close()

    if not row:
        logger.error(f"Сертификат с serial {serial_hex} не найден.")
        return

    print(f"Serial (Hex) : {row['serial_hex']}")
    print(f"Subject      : {row['subject']}")
    print(f"Issuer       : {row['issuer']}")
    print(f"Not Before   : {row['not_before']}")
    print(f"Not After    : {row['not_after']}")
    print(f"Status       : {row['status']}")
    print(f"Created At   : {row['created_at']}")
    print("\n--- PEM Certificate ---")
    print(row['pem'])

def revoke_cert(db_path: str, serial_hex: str, reason: int, logger, audit_logger: AuditLogger) -> bool:
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    # Для аудита: получаем информацию о сертификате до отзыва
    cursor.execute("SELECT subject FROM certificates WHERE serial_hex = ?", (serial_hex.upper(),))
    row = cursor.fetchone()
    if not row:
        logger.error(f"Сертификат {serial_hex} не найден")
        audit_logger.log('AUDIT', 'revoke', 'failure', 'Сертификат не найден', {'serial': serial_hex})
        return False

    cursor.execute("""
        UPDATE certificates 
        SET status = 'revoked', 
            revoked_at = ?, 
            revocation_reason = ? 
        WHERE serial_hex = ? AND status = 'valid'
    """, (now, reason, serial_hex.upper()))

    if cursor.rowcount == 0:
        logger.error(f"Сертификат {serial_hex} не найден или уже отозван")
        audit_logger.log('AUDIT', 'revoke', 'failure', 'Сертификат уже отозван или не найден', {'serial': serial_hex})
        conn.close()
        return False

    conn.commit()
    conn.close()
    logger.info(f"Сертификат {serial_hex} успешно отозван")
    audit_logger.log('AUDIT', 'revoke', 'success', 'Сертификат отозван', {
        'serial': serial_hex, 'reason': reason, 'subject': row['subject']
    })
    return True