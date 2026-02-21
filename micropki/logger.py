import logging
import os
import sys

def setup_logger(log_file=None):
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(formatter)
    logger.addHandler(sh)

    if log_file:
        os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
        fh = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        try:
            os.chmod(log_file, 0o640)
        except OSError:
            logger.warning("Cannot set log-file permissions (Windows OK)")

    return logger