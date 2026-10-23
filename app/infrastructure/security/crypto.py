"""Concrete cryptographic services for passwords, JWTs, PII, and certificate signatures."""

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jose import jwt
from passlib.context import CryptContext
from app.core.config import get_settings

_passwords = CryptContext(schemes=["argon2"], deprecated="auto")


class PasswordService:
    """One-way Argon2 password hashing and verification."""

    @staticmethod
    def hash(password: str) -> str:
        """Hash a password for storage; never store the original password."""
        return _passwords.hash(password)

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        """Verify a candidate password against the stored Argon2 hash."""
        return _passwords.verify(password, stored_hash)


class JWTService:
    """Create and validate short-lived JWT access tokens."""

    @staticmethod
    def create(user_id: int, role: str) -> str:
        """Issue a signed access token containing minimal identity claims."""
        settings = get_settings()
        expiry = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
        return jwt.encode({"sub": str(user_id), "role": role, "exp": expiry},
                          settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

    @staticmethod
    def decode(token: str) -> dict:
        """Validate token signature and expiry; invalid tokens raise an exception."""
        settings = get_settings()
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])


class PIIEncryptionService:
    """Fernet authenticated encryption for structured PII."""

    def __init__(self) -> None:
        """Load the Fernet key from environment-backed settings."""
        self._cipher = Fernet(get_settings().fernet_key.encode())

    def encrypt(self, payload: dict) -> str:
        """Serialize and encrypt PII before database persistence."""
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return self._cipher.encrypt(data).decode()

    def decrypt(self, ciphertext: str) -> dict:
        """Authenticate and decrypt a previously stored PII payload."""
        return json.loads(self._cipher.decrypt(ciphertext.encode()).decode())


class CertificateCryptoService:
    """Canonicalize, hash, sign, and verify certificate payloads using Ed25519."""

    def __init__(self) -> None:
        """Load the signing private key and verification public key."""
        settings = get_settings()
        private_path = Path(settings.certificate_private_key_path)
        public_path = Path(settings.certificate_public_key_path)
        self._private = serialization.load_pem_private_key(private_path.read_bytes(), password=None) if private_path.exists() else None
        self._public = serialization.load_pem_public_key(public_path.read_bytes()) if public_path.exists() else None

    @staticmethod
    def canonical_json(payload: dict) -> str:
        """Produce deterministic JSON so the exact bytes can be signed and verified."""
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def sign(self, payload: dict) -> tuple[str, str, str]:
        """Return canonical payload, SHA-256 digest, and base64 Ed25519 signature."""
        if not isinstance(self._private, Ed25519PrivateKey):
            raise RuntimeError("Signing private key missing; run scripts/generate_signing_keys.py")
        canonical = self.canonical_json(payload)
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        signature = self._private.sign(canonical.encode())
        return canonical, digest, base64.b64encode(signature).decode()

    def verify(self, canonical: str, digest: str, signature_b64: str) -> bool:
        """Return False if the digest or digital signature does not validate."""
        if not isinstance(self._public, Ed25519PublicKey):
            raise RuntimeError("Verification public key missing; run scripts/generate_signing_keys.py")
        if not hmac.compare_digest(hashlib.sha256(canonical.encode()).hexdigest(), digest):
            return False
        try:
            self._public.verify(base64.b64decode(signature_b64), canonical.encode())
            return True
        except Exception:
            return False
