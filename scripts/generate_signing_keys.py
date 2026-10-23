"""Generate an Ed25519 certificate signing key pair."""

from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
KEYS = ROOT / "keys"


def main() -> None:
    """Write PEM keys; never commit the private key."""
    KEYS.mkdir(exist_ok=True)
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = KEYS / "certificate_private_key.pem"
    private_path.write_bytes(private_pem)
    (KEYS / "certificate_public_key.pem").write_bytes(public_pem)
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    print("Generated Ed25519 keys. Keep the private key secret.")


if __name__ == "__main__":
    main()
