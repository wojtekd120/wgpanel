from getpass import getpass

from app.security import hash_password


def main() -> None:
    password = getpass("Admin password: ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    print(hash_password(password))


if __name__ == "__main__":
    main()
