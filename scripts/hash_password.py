#!/usr/bin/env python3
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from scripts.hash_password import main  # noqa: E402


if __name__ == "__main__":
    main()
