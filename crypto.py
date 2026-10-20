"""Butun kriptoqrafiya burada. Acarlar secrets/ qovluqunda saxlanilir.
Real bankda bu acarlar buludda KMS / Secrets Manager-de olardi."""

# =====================================================================
# crypto.py — KRİPTOQRAFİYA MÖVZUSUNUN ƏSAS FAYLIDIR.
# Burada 4 fərqli kriptoqrafik texnika var:
#   1) AES-256-GCM — şifrələmə (IBAN kimi datanı qorumaq üçün)
#   2) HMAC         — "blind index" (şifrəli datanı açmadan axtarmaq üçün)
#   3) ECDSA        — rəqəmsal imza (əməliyyatın dəyişdirilmədiyini sübut edir)
#   4) Açarların saxlanması — ya mühit dəyişənindən (bulud), ya fayldan (lokal)
# =====================================================================

import os, hmac, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# Açarların lokal saxlanacağı qovluq (yalnız öz kompüterində istifadə olunur)
D = "secrets"
os.makedirs(D, exist_ok=True)


def _key(name, env_name, n=32):
    """
    Açarı tapan köməkçi funksiya.
    Əvvəlcə BULUDDAKI mühit dəyişənindən (env_name) axtarır — çünki
    Render hər dəfə yenidən başlayanda yerli fayl itə bilər, mühit
    dəyişəni isə sabit qalır.
    Tapılmasa, LOKAL kompüterdə fayldan oxuyur, fayl yoxdursa təsadüfi
    yeni açar yaradıb fayla yazır (os.urandom = kriptoqrafik cəhətdən
    təhlükəsiz təsadüfi bayt generatoru).
    """
    env_val = os.environ.get(env_name)
    if env_val:
        return bytes.fromhex(env_val)
    p = os.path.join(D, name)
    if not os.path.exists(p):
        open(p, "wb").write(os.urandom(n))
    return open(p, "rb").read()


# AES şifrələmə açarı (IBAN-ları şifrələmək üçün)
AES_KEY = _key("aes.key", "AES_KEY_HEX")
# HMAC açarı (şifrəli IBAN-ı dəyişdirmədən "axtarıla bilən" indeks yaratmaq üçün)
HMAC_KEY = _key("hmac.key", "HMAC_KEY_HEX")

# ---- Rəqəmsal imza üçün açar cütü (ECDSA) ----
# PRIV = məxfi (private) açar, yalnız bank bilir, bununla əməliyyatları imzalayır.
# İctimai (public) açar PRIV-in içindən avtomatik çıxarılır, imzanı YOXLAMAQ üçün istifadə olunur.
_pem_env = os.environ.get("SIGN_PRIVATE_PEM")
if _pem_env:
    # Buludda: açar mühit dəyişənində saxlanılıb
    PRIV = serialization.load_pem_private_key(_pem_env.encode(), None)
else:
    # Lokalda: açar fayldan oxunur, yoxdursa YENİ açar cütü yaradılır
    _pem = os.path.join(D, "sign_private.pem")
    if not os.path.exists(_pem):
        k = ec.generate_private_key(ec.SECP256R1())   # P-256 əyrisi üzrə yeni açar cütü
        open(_pem, "wb").write(k.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    PRIV = serialization.load_pem_private_key(open(_pem, "rb").read(), None)


def encrypt(text: str) -> str:
    """
    AES-256-GCM ilə ŞİFRƏLƏMƏ.
    'nonce' hər dəfə fərqli, təsadüfi bir ədəddir — eyni mətni iki dəfə
    şifrələsən belə, nəticə hər dəfə fərqli çıxır (bu, təhlükəsizlik üçün vacibdir).
    Nəticə: nonce + şifrəli mətn, hex (16-lıq say sistemi) formatında bir sətir.
    """
    nonce = os.urandom(12)
    return (nonce + AESGCM(AES_KEY).encrypt(nonce, text.encode(), None)).hex()


def decrypt(token: str) -> str:
    """AES-256-GCM ilə DEŞİFRƏ (yalnız düzgün AES_KEY ilə mümkündür)."""
    raw = bytes.fromhex(token)
    return AESGCM(AES_KEY).decrypt(raw[:12], raw[12:], None).decode()


def blind_index(text: str) -> str:
    """
    'Kor indeks' — IBAN-ı deşifrə etmədən bazada TAPMAQ üçün istifadə olunur.
    HMAC bir-tərəfli funksiyadır: eyni IBAN həmişə eyni nəticəni verir,
    amma nəticədən geriyə IBAN-ı çıxarmaq mümkün deyil.
    Beləcə sistem "bu IBAN bazada varmı?" sualına cavab verə bilir,
    IBAN-ın özünü açıq saxlamadan.
    """
    return hmac.new(HMAC_KEY, text.encode(), hashlib.sha256).hexdigest()


def sign(payload: str) -> str:
    """
    RƏQƏMSAL İMZA yaradır (ECDSA + SHA-256).
    Əməliyyatın məzmunu (göndərən, alan, məbləğ, vaxt) məxfi açarla
    "möhürlənir". Bu imzanı yalnız bizim məxfi açarımız yarada bilər.
    """
    return PRIV.sign(payload.encode(), ec.ECDSA(hashes.SHA256())).hex()


def verify(payload: str, sig_hex: str) -> bool:
    """
    İmzanı YOXLAYIR: verilən məzmun (payload) və imza (sig_hex) bir-birinə
    uyğundurmu? Əgər kimsə əməliyyatın məbləğini bazada dəyişdirsə,
    payload dəyişəcək, imza isə köhnə məbləğə görə qalacaq — uyğunsuzluq
    yaranacaq və bu funksiya False (yanlış) qaytaracaq. Məhz bununla
    "Datanı dəyiş (demo)" düyməsi sındırılanda saxtakarlıq aşkarlanır.
    """
    try:
        PRIV.public_key().verify(bytes.fromhex(sig_hex), payload.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False
