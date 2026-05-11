import secrets
import time

def generate_serial() -> int:

    timestamp = int(time.time()) & 0xFFFFFFFF          
    random_part = secrets.randbits(32)                
    serial = (timestamp << 32) | random_part
    return serial


def serial_to_hex(serial: int) -> str:
    return format(serial, 'x').upper()