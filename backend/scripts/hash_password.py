import sys
from getpass import getpass
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.security import hash_password


def main() -> None:
    if "--stdin" in sys.argv:
        password = sys.stdin.readline().rstrip("\n")
        confirmation = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass("Admin password: ")
        confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters")
    print(hash_password(password))


if __name__ == "__main__":
    main()
