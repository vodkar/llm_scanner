import sys

from .consts import SRC_DIR

# Ensure src/ is importable
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
