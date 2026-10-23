"""Trusted CLI for creating instructor accounts."""

import argparse
import getpass
from app.infrastructure.database.base import Base
from app.infrastructure.database.session import engine, SessionLocal
from app.infrastructure.database import models  # register table metadata
from app.application.services import PlatformService


def create_instructor() -> None:
    """Create an instructor interactively without exposing password in shell history."""
    name = input("Full name: ").strip()
    email = input("Email: ").strip()
    password = getpass.getpass("Password (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        try:
            user = PlatformService().create_instructor(db, name, email, password)
        except ValueError as exc:
            raise SystemExit(str(exc))
        print(f"Instructor created: id={user.id}, email={user.email}")


def main() -> None:
    """Dispatch supported maintenance commands."""
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["create-instructor"])
    if parser.parse_args().command == "create-instructor":
        create_instructor()


if __name__ == "__main__":
    main()
