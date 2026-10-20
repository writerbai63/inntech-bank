# =====================================================================
# main.py — BÜTÜN SAYTIN BEYNİ.
# Bu fayl 4 hissəyə bölünür:
#   1) Baza cədvəlləri (modellər) — hansı məlumat haradan saxlanılır
#   2) Yardımçı funksiyalar — audit jurnalı, token, maskalama və s.
#   3) Marşrutlar (routes) — hər URL (/login, /dashboard və s.) nə edir
#   4) Hücumçu terminalı — tədris məqsədli, bankın özünə aid olmayan hissə
# =====================================================================

import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import jwt, JWTError
from fastapi.responses import HTMLResponse
import config, crypto

# Bazaya qoşulma "mühərriki" (config.py-dan DB_URL-i götürür)
engine = create_engine(config.DB_URL)
Session = sessionmaker(bind=engine)
Base = declarative_base()

# Argon2 — parolları HASH-ləmək üçün istifadə olunan alət.
# (Hash = parolu geri açıla bilməyən formaya salmaq. Şifrələmədən fərqli
# olaraq, hash-dən əsl parolu bərpa etmək mümkün deyil.)
ph = PasswordHasher()

MAX_ATTEMPTS = 5     # neçə yanlış cəhddən sonra hesab bloklanır
LIMIT_AZN = 5000     # bir əməliyyat üçün maksimum icazəli məbləğ (anti-fraud)


# ---------------------------------------------------------------------
# BAZA CƏDVƏLLƏRİ (hər class = bir cədvəl)
# ---------------------------------------------------------------------

class User(Base):
    """İstifadəçilər cədvəli: müştərilər və işçilər bura yazılır."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)   # parolun AÇIQ halı YOXDUR, yalnız hash
    role = Column(String(20), nullable=False)              # "customer" və ya "staff"
    failed_attempts = Column(Integer, default=0)           # neçə dəfə yanlış parol yazılıb
    locked = Column(Integer, default=0)                    # 1 = hesab bloklanıb


class Account(Base):
    """Hesablar cədvəli: hər müştərinin IBAN-ı və balansı."""
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    iban_enc = Column(String(255), nullable=False)               # IBAN burada AES ilə ŞİFRƏLİ saxlanır
    iban_idx = Column(String(64), unique=True, nullable=False)   # HMAC "kor indeks" (axtarış üçün)
    balance = Column(Integer, default=0)                         # balans QƏPİKLƏ saxlanır (dəqiqlik üçün)


class Transfer(Base):
    """Köçürmələr cədvəli: hər əməliyyat burada, imzalanmış şəkildə saxlanır."""
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True)
    from_user = Column(Integer, nullable=False)
    from_iban_enc = Column(String(255), nullable=False)   # göndərənin IBAN-ı (şifrəli)
    to_iban_enc = Column(String(255), nullable=False)     # alanın IBAN-ı (şifrəli)
    amount = Column(Integer, nullable=False)              # məbləğ (qəpiklə)
    ts = Column(String(40), nullable=False)               # vaxt
    signature = Column(String(255), nullable=False)       # ECDSA rəqəmsal İMZA


class AuditLog(Base):
    """
    Audit jurnalı: kim, nə vaxt, nə etdi.
    prev_hash/hash sütunları ilə HASH ZƏNCİRİ yaradılır — hər qeyd
    özündən əvvəlki qeydin hash-ini daşıyır. Bu, jurnalın sonradan
    gizlicə dəyişdirilə bilməməsini təmin edir (zəncirdə bir halqa
    dəyişsə, bütün zəncir "pozulub" görünür).
    """
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(String(40))
    event = Column(String(40))
    detail = Column(String(255))
    prev_hash = Column(String(64))
    hash = Column(String(64))


# Proqram ilk işə düşəndə bu cədvəllər bazada yoxdursa, avtomatik yaradılır
Base.metadata.create_all(engine)


def seed():
    """
    Baza TAMAMİLƏ boşdursa, demo üçün ilkin istifadəçilər və hesablar yaradır.
    Bu funksiya yalnız bazada HEÇ BİR istifadəçi yoxdursa işləyir, ona görə
    serveri neçə dəfə yenidən başlatsan da, demo datanı təkrar yaratmır.
    """
    with Session() as db:
        if not db.query(User).count():
            for u, n, p, r in [("huseyn", "Hüseyn Qasımov", "123!", "customer"),
                                ("zahid", "Zahid Rzayev", "123!", "customer"),
                                ("nicat", "Nicat Abbasov", "123!", "customer"),
                                ("adil", "Adil Məmmədov", "123!", "customer"),
                                ("socl3", "SOC Analitiki", "1234", "staff")]:
                # Parol burada AÇIQ yazılıb (p), amma bazaya yazılmazdan əvvəl
                # ph.hash(p) ilə HASH-lənir. Bazada açıq parol heç vaxt olmur.
                db.add(User(username=u, full_name=n, password_hash=ph.hash(p), role=r))
            db.commit()
        if not db.query(Account).count():
            for u, iban, bal in [("huseyn", "AZ21INNT00000000000000000001", 125000),
                                  ("zahid", "AZ21INNT00000000000000000002", 50000),
                                  ("nicat", "AZ21INNT00000000000000000003", 75000),
                                  ("adil", "AZ21INNT00000000000000000004", 90000)]:
                uid = db.query(User).filter_by(username=u).first().id
                # IBAN bazaya yazılmazdan əvvəl AES ilə ŞİFRƏLƏNİR (crypto.encrypt)
                # və HMAC ilə "kor indeks" yaradılır (crypto.blind_index)
                db.add(Account(user_id=uid, iban_enc=crypto.encrypt(iban),
                               iban_idx=crypto.blind_index(iban), balance=bal))
            db.commit()


seed()  # server başlayanda bir dəfə işə düşür

app = FastAPI(title="InnTech Bank")
# /static ünvanına gələn sorğular "static" qovluğundakı fayllara (CSS, logo) yönləndirilir
app.mount("/static", StaticFiles(directory="static"), name="static")
# HTML "şablonları" (templates qovluğu) buradan oxunur
templates = Jinja2Templates(directory="templates")


# ---------------------------------------------------------------------
# YARDIMÇI FUNKSİYALAR
# ---------------------------------------------------------------------

def now():
    """Hazırkı vaxtı standart formatda (ISO) qaytarır."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _h(prev, ts, event, detail):
    """
    Audit jurnalındakı bir qeydin HASH-ini hesablayır.
    Daxilə əvvəlki qeydin hash-i (prev) də qatılır — məhz bu,
    "zənciri" yaradan hissədir: hər hash özündən əvvəlkinə bağlıdır.
    """
    return hashlib.sha256(f"{prev}|{ts}|{event}|{detail}".encode()).hexdigest()


def audit(db, event, detail):
    """Audit jurnalına yeni qeyd əlavə edir, hash zəncirinə bağlayaraq."""
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev = last.hash if last else "0" * 64   # ilk qeyd üçün "əvvəlki hash" 64 ədəd 0-dır
    ts = now()
    db.add(AuditLog(ts=ts, event=event, detail=detail, prev_hash=prev, hash=_h(prev, ts, event, detail)))
    db.commit()


def chain_ok(db):
    """
    Bütün audit jurnalını başdan sona gəzib, hash zəncirinin BÜTÖV olub
    olmadığını yoxlayır. Hər qeydin hash-i yenidən hesablanıb bazadakı
    hash ilə müqayisə olunur — uyğunsuzluq varsa, zəncir pozulmuş deməkdir
    (kimsə jurnalda dəyişiklik edib).
    """
    prev = "0" * 64
    for r in db.query(AuditLog).order_by(AuditLog.id):
        if r.prev_hash != prev or _h(r.prev_hash, r.ts, r.event, r.detail) != r.hash:
            return False
        prev = r.hash
    return True


# Ekranda göstərmək üçün həssas məlumatı MASKALAYAN köməkçi funksiyalar
mask_iban = lambda i: i[:4] + "****" + i[-4:]
mask_name = lambda n: " ".join(w[0] + "***" for w in n.split())
# Rəqəmsal imza üçün "nə imzalanacağını" formalaşdıran funksiya
payload = lambda f, t, a, ts: f"{f}|{t}|{a}|{ts}"


def make_token(user):
    """
    Girişdən sonra JWT (JSON Web Token) yaradır — bu, "imzalanmış bilet"dir.
    İçində istifadəçi adı, rolu və bitmə vaxtı (30 dəqiqə) var.
    SECRET_KEY ilə imzalanır ki, kimsə onu özü uydurub dəyişə bilməsin.
    """
    exp = datetime.now(timezone.utc) + timedelta(minutes=30)
    return jwt.encode({"sub": user.username, "role": user.role, "exp": exp}, config.SECRET_KEY, algorithm="HS256")


def current_user(request: Request):
    """
    Hər sorğuda "bu kimdir?" sualına cavab verir.
    Cookie-dəki JWT token oxunur, imzası yoxlanılır (jwt.decode),
    düzgündürsə, həmin istifadəçi bazadan tapılıb qaytarılır.
    """
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        data = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
    except JWTError:
        return None   # token yanlışdır və ya vaxtı bitib
    with Session() as db:
        return db.query(User).filter_by(username=data["sub"]).first()


# =======================================================================
# MARŞRUTLAR (ROUTES) — hər @app.get/@app.post bir URL-ə uyğundur
# =======================================================================

# ---------- GİRİŞ VƏ ƏSAS SƏHİFƏLƏR ----------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """Saytın ana səhifəsi (marketinq/tanıtım hissəsi)."""
    return templates.TemplateResponse(request, "index.html", {})


@app.get("/login")
def login_page(request: Request):
    """Müştəri giriş səhifəsi."""
    return templates.TemplateResponse(request, "login.html", {"portal": "customer"})


@app.get("/staff")
def staff_login_page(request: Request):
    """İşçi (SOC/sysadmin) giriş səhifəsi."""
    return templates.TemplateResponse(request, "login.html", {"portal": "staff"})


@app.post("/api/login")
def api_login(username: str = Form(...), password: str = Form(...), portal: str = Form(...)):
    """
    GİRİŞ MƏNTİQİ — bütün kriptoqrafiya və təhlükəsizlik yoxlamaları burada cəmlənib:
      1) İstifadəçi bazada varmı?
      2) Hesab bloklanıbmı?
      3) Parol düzgündürmü? (Argon2 ilə hash müqayisəsi)
      4) Yanlışdırsa — sayğacı artır, 5-ə çatanda hesabı bloklayır
      5) Rol (customer/staff) düzgün portala uyğundurmu?
      6) Hamısı keçərsə — JWT token yaradılır və cookie-yə qoyulur
    Hər addım "trace" siyahısına yazılır ki, ekranda canlı göstərilə bilsin,
    HƏM DƏ hər mühüm hadisə audit() ilə jurnala düşür.
    """
    trace = [f"Sorğu serverə çatdı (portal: {portal})"]
    fail = lambda msg: JSONResponse({"ok": False, "error": msg, "trace": trace}, status_code=401)
    with Session() as db:
        user = db.query(User).filter_by(username=username).first()
        if not user:
            trace.append("İstifadəçi tapılmadı")
            audit(db, "LOGIN_FAIL", f"namelum istifadeci: {username[:30]}")
            return fail("İstifadəçi adı və ya parol yanlışdır")
        if user.locked:
            trace.append("Hesab bloklanıb (5 uğursuz cəhd)")
            return fail("Hesab bloklanıb. Əməkdaşla əlaqə saxlayın")
        trace.append("Bazadan hash oxundu: " + user.password_hash[:38] + "…")
        try:
            # Argon2: daxil edilən parolu hash-ləyib bazadakı hash ilə müqayisə edir.
            # Uyğun gəlsə, heç bir xəta atmır (aşağı davam edir).
            ph.verify(user.password_hash, password)
            trace.append("Argon2: daxil edilən parolun hash-i bazadakı ilə uyğun gəldi")
        except VerifyMismatchError:
            # Parol yanlışdır — sayğacı artırır, lazım gəlsə hesabı bloklayır
            user.failed_attempts += 1
            trace.append(f"Argon2: uyğun gəlmədi (uğursuz cəhd {user.failed_attempts}/{MAX_ATTEMPTS})")
            db.commit()
            audit(db, "LOGIN_FAIL", f"{username}: yanlis parol ({user.failed_attempts}/{MAX_ATTEMPTS})")
            if user.failed_attempts >= MAX_ATTEMPTS:
                user.locked = 1
                db.commit()
                trace.append("Hesab bloklandı və hadisə qeydə alındı")
                audit(db, "ACCOUNT_LOCKED", f"{username}: brute-force sehvi")
            return fail("İstifadəçi adı və ya parol yanlışdır")
        if user.role != portal:
            # Məsələn, müştəri /staff portalına girməyə çalışırsa — rədd edilir
            trace.append(f"Rol yoxlaması: '{user.role}' bu portala girə bilməz")
            audit(db, "ROLE_DENIED", f"{username} ({user.role}) {portal} portalina girmeye calisdi")
            return fail("Bu hesab ilə bu portala giriş icazəsi yoxdur")
        # Hər şey düzgündürsə — sayğacı sıfırlayır, token yaradır
        user.failed_attempts = 0
        db.commit()
        trace += [f"Rol yoxlaması: '{user.role}' icazəlidir",
                  "JWT token yaradıldı (30 dəq., HS256 ilə imzalı)",
                  "Token httpOnly cookie-də saxlanıldı (JavaScript oxuya bilmir)"]
        audit(db, "LOGIN_OK", f"{username} ({user.role})")
        target = "/dashboard" if user.role == "customer" else "/staff/panel"
        resp = JSONResponse({"ok": True, "redirect": target, "trace": trace})
        # httponly=True → tokeni brauzerin JavaScript-i oxuya bilmir (XSS-dən qorunma)
        # samesite="strict" → başqa saytdan gələn sorğularda cookie göndərilmir (CSRF-dən qorunma)
        resp.set_cookie("session", make_token(user), httponly=True, samesite="strict", max_age=1800)
        return resp


@app.get("/logout")
def logout():
    """Çıxış: cookie silinir, giriş səhifəsinə yönləndirilir."""
    resp = RedirectResponse("/login")
    resp.delete_cookie("session")
    return resp


# ---------- MÜŞTƏRİ HİSSƏSİ ----------

@app.get("/dashboard")
def dashboard(request: Request, user=Depends(current_user)):
    """
    Müştərinin öz hesab səhifəsi.
    current_user() ilə "bu kimdir?" yoxlanılır — giriş etməyibsə və ya
    rolu "customer" deyilsə, giriş səhifəsinə geri göndərilir.
    """
    if not user or user.role != "customer":
        return RedirectResponse("/login")
    with Session() as db:
        acc = db.query(Account).filter_by(user_id=user.id).first()
        # Tarixçədəki hər köçürmənin IBAN-ı bazada ŞİFRƏLİ saxlanıb,
        # ekranda göstərmək üçün crypto.decrypt() ilə AÇILIR
        history = [{"to": crypto.decrypt(t.to_iban_enc), "amount": t.amount / 100, "ts": t.ts.replace("T", " ")[:16]}
                   for t in db.query(Transfer).filter_by(from_user=user.id).order_by(Transfer.id.desc()).limit(8)]
        ctx = {"user": user, "iban": crypto.decrypt(acc.iban_enc), "balance": acc.balance / 100, "history": history}
    return templates.TemplateResponse(request, "dashboard.html", ctx)


@app.post("/api/transfer")
def api_transfer(to_iban: str = Form(...), amount: str = Form(...), user=Depends(current_user)):
    """
    KÖÇÜRMƏ MƏNTİQİ — bütün addımlar sırayla yoxlanılır:
      1) İstifadəçi giriş edibmi və müştəridirmi?
      2) Məbləğ düzgün formatdadırmı, müsbətdirmi?
      3) Balans kifayətdirmi?
      4) Anti-fraud limiti (5000 AZN) keçilməyibmi?
      5) Alıcı IBAN HMAC "kor indeks" ilə tapılır (IBAN açıq axtarılmır!)
      6) IBAN-lar AES ilə şifrələnir
      7) Əməliyyat ECDSA ilə İMZALANIR
      8) Balanslar yenilənir, bazaya yazılır
      9) Audit jurnalına, hash zəncirinə bağlı şəkildə yazılır
    """
    if not user or user.role != "customer":
        return JSONResponse({"ok": False, "error": "Giriş tələb olunur", "trace": []}, status_code=401)
    to_iban = to_iban.replace(" ", "").upper()
    trace = [f"Sorğu gəldi, JWT yoxlandı (istifadəçi: {user.username}, rol: {user.role})"]
    fail = lambda msg: JSONResponse({"ok": False, "error": msg, "trace": trace}, status_code=400)
    try:
        cents = int(round(float(amount) * 100))   # AZN-i qəpiyə çeviririk (dəqiqlik üçün)
    except ValueError:
        return fail("Məbləğ düzgün deyil")
    if cents <= 0:
        return fail("Məbləğ müsbət olmalıdır")
    with Session() as db:
        src = db.query(Account).filter_by(user_id=user.id).first()
        if cents > src.balance:
            trace.append("Balans yoxlaması: kifayət qədər vəsait yoxdur")
            return fail("Balans kifayət deyil")
        trace.append("Balans yoxlaması: kifayət qədər vəsait var")
        if cents > LIMIT_AZN * 100:
            # ANTİ-FRAUD: şübhəli böyük məbləğ avtomatik dayandırılır
            trace.append(f"Anti-fraud: məbləğ {LIMIT_AZN} AZN limitini keçir, əməliyyat dayandırıldı")
            audit(db, "FRAUD_BLOCK", f"{user.username}: {cents/100} AZN limit asildi")
            return fail(f"Bir əməliyyat üçün limit {LIMIT_AZN} AZN-dir")
        trace.append("Anti-fraud: limit və vaxt qaydaları keçdi")
        # Alıcı IBAN-ın HMAC "kor indeksi" ilə tapılır — IBAN-ın özü bazada
        # açıq saxlanmadığı üçün, axtarış da açıq mətnlə aparıla bilmir
        dst = db.query(Account).filter_by(iban_idx=crypto.blind_index(to_iban)).first()
        trace.append("Alıcı HMAC indeksi ilə tapıldı (IBAN açıq mətnlə axtarılmadı)")
        if not dst or dst.id == src.id:
            return fail("Alıcı IBAN tapılmadı və ya özünüzə köçürmə")
        from_iban = crypto.decrypt(src.iban_enc)
        ts = now()
        # IBAN-lar yenidən AES ilə şifrələnir (əməliyyat qeydində saxlamaq üçün)
        to_enc, from_enc = crypto.encrypt(to_iban), crypto.encrypt(from_iban)
        trace.append("IBAN-lar AES-256-GCM ilə şifrələndi: " + to_enc[:28] + "…")
        # ƏMƏLİYYAT İMZALANIR: göndərən+alan+məbləğ+vaxt birlikdə "möhürlənir"
        sig = crypto.sign(payload(from_iban, to_iban, cents, ts))
        trace.append("ECDSA (P-256) ilə imzalandı: " + sig[:28] + "…")
        src.balance -= cents
        dst.balance += cents
        db.add(Transfer(from_user=user.id, from_iban_enc=from_enc, to_iban_enc=to_enc,
                        amount=cents, ts=ts, signature=sig))
        db.commit()
        trace.append("Balanslar yeniləndi, əməliyyat bazaya şifrəli yazıldı")
        audit(db, "TRANSFER", f"{user.username} -> {mask_iban(to_iban)}: {cents/100} AZN")
        last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        trace.append("Audit jurnalına yazıldı, hash zəncirinə bağlandı: " + last.hash[:20] + "…")
    return {"ok": True, "trace": trace}


# ---------- İŞÇİ (SOC / SYSADMIN) HİSSƏSİ ----------

def staff_only(user):
    """Sadə yoxlama: istifadəçi var və rolu 'staff'dırmı?"""
    return user and user.role == "staff"


@app.get("/staff/panel")
def staff_panel(request: Request, user=Depends(current_user)):
    """
    İşçi (SOC analitiki) paneli:
      - Bütün köçürmələri göstərir, AMMA adlar və IBAN-lar MASKALANIR
      - Hər əməliyyatın imzasını yenidən yoxlayır (crypto.verify) —
        kimsə bazada məbləği dəyişdiribsə, "İmza yanlış" göstərilir
      - Audit jurnalını və hash zəncirinin bütövlüyünü göstərir
      - BÜTÜN müştərilərin (yalnız bir hesabın yox) bloklanma statusunu göstərir
    """
    if not staff_only(user):
        return RedirectResponse("/staff")
    with Session() as db:
        rows = []
        for t in db.query(Transfer).order_by(Transfer.id.desc()).limit(20):
            f, to = crypto.decrypt(t.from_iban_enc), crypto.decrypt(t.to_iban_enc)
            sender = db.query(User).filter_by(id=t.from_user).first()
            rows.append({"id": t.id, "name": mask_name(sender.full_name), "from": mask_iban(f), "to": mask_iban(to),
                         "amount": t.amount / 100, "ts": t.ts.replace("T", " ")[:16], "sig": t.signature[:20] + "…",
                         # Burada imza yenidən yoxlanılır — saxtakarlıq aşkarlama məhz budur
                         "valid": crypto.verify(payload(f, to, t.amount, t.ts), t.signature)})
        logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(12).all()
        # DÜZƏLİŞ: tək bir "zahid" hesabı əvəzinə, BÜTÜN müştərilər siyahı kimi gəlir.
        # Beləcə panel hansı müştəri bloklanıbsa, onu göstərə bilir (hamısını yoxlayır).
        customers = db.query(User).filter_by(role="customer").order_by(User.username).all()
        ctx = {"user": user, "rows": rows, "logs": logs, "chain": chain_ok(db),
               "customers": customers}
    return templates.TemplateResponse(request, "staff_panel.html", ctx)


@app.get("/staff/db")
def staff_db(request: Request, user=Depends(current_user)):
    """
    'Baza görünüşü' — bazaya sızan hücumçunun görəcəyi məlumatı EYNİLƏ göstərir:
    Argon2 hash-lər, AES şifrəli IBAN-lar, ECDSA imzalar. Hamısı oxunmaz formadadır.
    """
    if not staff_only(user):
        return RedirectResponse("/staff")
    with Session() as db:
        ctx = {"user": user, "users": db.query(User).all(), "accounts": db.query(Account).all(),
               "transfers": db.query(Transfer).order_by(Transfer.id.desc()).limit(10).all()}
    return templates.TemplateResponse(request, "staff_db.html", ctx)


@app.post("/staff/tamper/{tid}")
def tamper(tid: int, user=Depends(current_user)):
    """
    DEMO MƏQSƏDLİ: bazaya sızmış hücumçunun məbləği gizlicə dəyişməsini
    təqlid edir (məbləğə 100 AZN əlavə olunur). Bu dəyişiklik imzaya
    toxunmur, ona görə növbəti dəfə crypto.verify() çağırılanda
    uyğunsuzluq aşkarlanacaq — "İmza yanlış, data dəyişdirilib".
    """
    if not staff_only(user):
        return RedirectResponse("/staff")
    with Session() as db:
        t = db.query(Transfer).filter_by(id=tid).first()
        if t:
            t.amount += 10000   # 100 AZN = 10000 qəpik
            db.commit()
    return RedirectResponse("/staff/panel", status_code=303)


@app.post("/api/staff/unlock")
def unlock_demo_account(username: str = Form(...), user=Depends(current_user)):
    """
    SYSADMIN əməliyyatı: bloklanmış HƏR HANSI müştəri hesabını aktivləşdirir.
    DÜZƏLİŞ: əvvəllər "zahid" sərt-kodlaşdırılmışdı, indi hansı hesabın
    blokdan çıxarılacağı formdan (username) gəlir — panel hər müştəri
    üçün öz düyməsini göstərdiyinə görə bu, artıq lazımdır.
    Hadisə, "kim, nə vaxt, hansı hesabı" detalı ilə audit jurnalına yazılır.
    """
    if not staff_only(user):
        return JSONResponse({"trace": []}, status_code=401)
    with Session() as db:
        target = db.query(User).filter_by(username=username, role="customer").first()
        if not target:
            return JSONResponse({"trace": [{"text": "İstifadəçi tapılmadı", "cls": "bad"}]}, status_code=404)
        target.locked, target.failed_attempts = 0, 0
        db.commit()
        audit(db, "ACCOUNT_UNLOCKED", f"{username}: {user.username} terefinden blokdan cixarildi")
    return {"trace": [{"text": f"{username} hesabı blokdan çıxarıldı, sayğac sıfırlandı, hadisə jurnala yazıldı", "cls": "good"}]}


# ---------- HÜCUMÇU TERMİNALI (bankın özünə aid DEYİL) ----------
# Bu, tədris məqsədli, ayrıca bir ekrandır. Bankın öz görünüşündən
# fərqlənir (qara-yaşıl "hacker terminal" dizaynı) ki, vizual olaraq da
# "bu, bizim tərəfimiz deyil, xarici hücumçu tərəfidir" aydın olsun.
# Buradan göndərilən sorğular HƏQİQİ /api/login ünvanına gedir.
@app.get("/attacker")
def attacker_console(request: Request):
    return templates.TemplateResponse(request, "attacker.html", {})
