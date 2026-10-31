"""Test environment: throw-away SQLite database and keys. Must run before any `app` import."""

import os
import pathlib
import tempfile

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_tmp = pathlib.Path(tempfile.mkdtemp(prefix="sep-tests-"))
_key = Ed25519PrivateKey.generate()
(_tmp / "priv.pem").write_bytes(_key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
(_tmp / "pub.pem").write_bytes(_key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
os.environ.update(
    DATABASE_URL=f"sqlite:///{_tmp / 'test.db'}", JWT_SECRET_KEY="test-secret-" * 4,
    FERNET_KEY=Fernet.generate_key().decode(),
    CERTIFICATE_PRIVATE_KEY_PATH=str(_tmp / "priv.pem"), CERTIFICATE_PUBLIC_KEY_PATH=str(_tmp / "pub.pem"))
