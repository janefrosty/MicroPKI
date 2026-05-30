import json
import hashlib
import os
import time
from threading import Lock

class AuditLogger:
    def __init__(self, log_path: str, chain_path: str):
        self.log_path = log_path
        self.chain_path = chain_path
        self.lock = Lock()
        self._init_chain()

    def _init_chain(self):
        """Инициализирует директории и файлы для аудита."""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        if not os.path.exists(self.chain_path):
            with open(self.chain_path, 'w') as f:
                f.write('0'*64)  # Начальный хеш для первой записи
        if not os.path.exists(self.log_path):
            open(self.log_path, 'a').close()

    def log(self, level: str, operation: str, status: str, msg: str, metadata: dict):
        """Создает новую запись в аудит-логе с хеш-ссылкой на предыдущую."""
        with self.lock:
            with open(self.chain_path, 'r') as f:
                prev_hash = f.read().strip()

            entry = {
                "timestamp": time.time_ns(),
                "level": level.upper(),
                "operation": operation,
                "status": status,
                "message": msg,
                "metadata": metadata,
                "integrity": {"prev_hash": prev_hash, "hash": ""}
            }

            # Вычисляем хеш текущей записи (без поля integrity.hash)
            entry_copy_for_hash = entry.copy()
            entry_copy_for_hash['integrity']['hash'] = ''
            json_str = json.dumps(entry_copy_for_hash, separators=(',', ':'), sort_keys=True)
            entry['integrity']['hash'] = hashlib.sha256(json_str.encode()).hexdigest()

            # Записываем JSON в лог-файл
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
            
            # Обновляем последний хеш в chain.dat
            with open(self.chain_path, 'w') as f:
                f.write(entry['integrity']['hash'])

    def verify_chain(self) -> bool:
        """Проверяет целостность всей цепочки аудит-лога."""
        if not os.path.exists(self.log_path):
            return True
        prev_hash = '0' * 64
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                # Проверка ссылки на предыдущий хеш
                if entry['integrity']['prev_hash'] != prev_hash:
                    print(f"Ошибка цепочки: несоответствие prev_hash в записи {entry['timestamp']}")
                    return False
                
                # Проверка хеша текущей записи
                entry_copy = entry.copy()
                entry_copy['integrity']['hash'] = ''
                json_str = json.dumps(entry_copy, separators=(',', ':'), sort_keys=True)
                computed_hash = hashlib.sha256(json_str.encode()).hexdigest()
                if computed_hash != entry['integrity']['hash']:
                    print(f"Ошибка целостности: хеш записи {entry['timestamp']} не совпадает.")
                    return False
                prev_hash = entry['integrity']['hash']
        
        # Проверка последнего хеша с chain.dat
        with open(self.chain_path, 'r') as f:
            stored_last = f.read().strip()
        if stored_last != prev_hash:
            print("Ошибка целостности: последний хеш в chain.dat не совпадает.")
            return False
        
        print("Цепочка аудит-лога проверена и не содержит ошибок.")
        return True