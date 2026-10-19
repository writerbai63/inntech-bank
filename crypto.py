"""Butun kriptoqrafiya burada. Acarlar secrets/ qovluqunda saxlanilir.
Real bankda bu acarlar buludda KMS / Secrets Manager-de olardi."""
import os, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

D = "secrets"
os.makedirs(D, exist_ok=True)


def _key(name, env_name, n=32):
    # Əvvəlcə environment variable-dan yoxlayır (buludda sabit qalır)
    env_val = os.environ.get(env_name)
    if env_val:
        return bytes.fromhex(env_val)
    # Yoxdursa, yerli fayldan oxuyur/yaradır (yalnız öz kompüterin üçün)
    p = os.path.join(D, name)
    if not os.path.exists(p):
        open(p, "wb").write(os.urandom(n))
    return open(p, "rb").read()


AES_KEY = _key("aes.key", "AES_KEY_HEX")
HMAC_KEY = _key("hmac.key", "HMAC_KEY_HEX")

_pem_env = os.environ.get("SIGN_PRIVATE_PEM")
if _pem_env:
    PRIV = serialization.load_pem_private_key(_pem_env.encode(), None)
else:
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
