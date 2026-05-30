import sys
import pytest

if __name__ == "__main__":
    sys.exit(pytest.main(["tests/", "-v", "-p", "no:warnings", "--tb=short"]))