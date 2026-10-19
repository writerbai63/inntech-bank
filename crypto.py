"""Butun kriptoqrafiya burada. Acarlar secrets/ qovluqunda saxlanilir.
Real bankda bu acarlar buludda KMS / Secrets Manager-de olardi."""
import os, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

D = "secrets"
os.makedirs(D, exist_ok=True)


def _key(name, n=32):
    p = os.path.join(D, name)
    if not os.path.exists(p):
        open(p, "wb").write(os.urandom(n))
    return open(p, "rb").read()


AES_KEY, HMAC_KEY = _key("aes.key"), _key("hmac.key")
_pem = os.path.join(D, "sign_private.pem")
if not os.path.exists(_pem):
    k = ec.generate_private_key(ec.SECP256R1())
    open(_pem, "wb").write(k.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
PRIV = serialization.load_pem_private_key(open(_pem, "rb").read(), None)


def encrypt(text: str) -> str:            # AES-256-GCM
    nonce = os.urandom(12)
    return (nonce + AESGCM(AES_KEY).encrypt(nonce, text.encode(), None)).hex()


def decrypt(token: str) -> str:
    raw = bytes.fromhex(token)
    return AESGCM(AES_KEY).decrypt(raw[:12], raw[12:], None).decode()


def blind_index(text: str) -> str:        # sifrelenmis datani axtarmaq ucun
    return hmac.new(HMAC_KEY, text.encode(), hashlib.sha256).hexdigest()


def sign(payload: str) -> str:            # ECDSA P-256 + SHA-256
    return PRIV.sign(payload.encode(), ec.ECDSA(hashes.SHA256())).hex()


def verify(payload: str, sig_hex: str) -> bool:
    try:
        PRIV.public_key().verify(bytes.fromhex(sig_hex), payload.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
