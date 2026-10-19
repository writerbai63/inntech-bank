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

engine = create_engine(config.DB_URL)
Session = sessionmaker(bind=engine)
Base = declarative_base()
ph = PasswordHasher()
MAX_ATTEMPTS = 5
LIMIT_AZN = 5000


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)
    failed_attempts = Column(Integer, default=0)
    locked = Column(Integer, default=0)


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    iban_enc = Column(String(255), nullable=False)               # AES ile sifreli
    iban_idx = Column(String(64), unique=True, nullable=False)   # HMAC (axtaris ucun)
    balance = Column(Integer, default=0)                         # qepik


class Transfer(Base):
    __tablename__ = "transfers"
    id = Column(Integer, primary_key=True)
    from_user = Column(Integer, nullable=False)
    from_iban_enc = Column(String(255), nullable=False)
    to_iban_enc = Column(String(255), nullable=False)
    amount = Column(Integer, nullable=False)                     # qepik
    ts = Column(String(40), nullable=False)
    signature = Column(String(255), nullable=False)              # ECDSA imza


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    ts = Column(String(40))
    event = Column(String(40))
    detail = Column(String(255))
    prev_hash = Column(String(64))
    hash = Column(String(64))


Base.metadata.create_all(engine)


def seed():
    with Session() as db:
        if not db.query(User).count():
            for u, n, p, r in [("huseyn", "Hüseyn Qasımov", "123!", "customer"),
                                ("zahid", "Zahid Rzayev", "123!", "customer"),
                                ("nicat", "Nicat Abbasov", "123!", "customer"),
                                ("adil", "Adil Məmmədov", "123!", "customer"),
                                ("socl3", "SOC Analitiki", "1234", "staff")]:
                db.add(User(username=u, full_name=n, password_hash=ph.hash(p), role=r))
            db.commit()
        if not db.query(Account).count():
            for u, iban, bal in [("huseyn", "AZ21INNT00000000000000000001", 125000),
                                  ("zahid", "AZ21INNT00000000000000000002", 50000),
                                  ("nicat", "AZ21INNT00000000000000000003", 75000),
                                  ("adil", "AZ21INNT00000000000000000004", 90000)]:
                uid = db.query(User).filter_by(username=u).first().id
                db.add(Account(user_id=uid, iban_enc=crypto.encrypt(iban),
                               iban_idx=crypto.blind_index(iban), balance=bal))
            db.commit()


seed()
app = FastAPI(title="InnTech Bank")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ---------- yardimci funksiyalar ----------
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _h(prev, ts, event, detail):
    return hashlib.sha256(f"{prev}|{ts}|{event}|{detail}".encode()).hexdigest()


def audit(db, event, detail):
    """Her qeyd evvelkinin hash-ini saxlayir (hash zənciri)."""
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev = last.hash if last else "0" * 64
    ts = now()
    db.add(AuditLog(ts=ts, event=event, detail=detail, prev_hash=prev, hash=_h(prev, ts, event, detail)))
    db.commit()


def chain_ok(db):
    prev = "0" * 64
    for r in db.query(AuditLog).order_by(AuditLog.id):
        if r.prev_hash != prev or _h(r.prev_hash, r.ts, r.event, r.detail) != r.hash:
            return False
        prev = r.hash
    return True


mask_iban = lambda i: i[:4] + "****" + i[-4:]
mask_name = lambda n: " ".join(w[0] + "***" for w in n.split())
payload = lambda f, t, a, ts: f"{f}|{t}|{a}|{ts}"


def make_token(user):
    exp = datetime.now(timezone.utc) + timedelta(minutes=30)
    return jwt.encode({"sub": user.username, "role": user.role, "exp": exp}, config.SECRET_KEY, algorithm="HS256")


def current_user(request: Request):
    token = request.cookies.get("session")
    if not token:
        return None
    try:
        data = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
    except JWTError:
        return None
    with Session() as db:
        return db.query(User).filter_by(username=data["sub"]).first()


# ---------- giris ----------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"portal": "customer"})


@app.get("/staff")
def staff_login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"portal": "staff"})


@app.post("/api/login")
def api_login(username: str = Form(...), password: str = Form(...), portal: str = Form(...)):
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
            ph.verify(user.password_hash, password)
            trace.append("Argon2: daxil edilən parolun hash-i bazadakı ilə uyğun gəldi")
        except VerifyMismatchError:
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
            trace.append(f"Rol yoxlaması: '{user.role}' bu portala girə bilməz")
            audit(db, "ROLE_DENIED", f"{username} ({user.role}) {portal} portalina girmeye calisdi")
            return fail("Bu hesab ilə bu portala giriş icazəsi yoxdur")
        user.failed_attempts = 0
        db.commit()
        trace += [f"Rol yoxlaması: '{user.role}' icazəlidir",
                  "JWT token yaradıldı (30 dəq., HS256 ilə imzalı)",
                  "Token httpOnly cookie-də saxlanıldı (JavaScript oxuya bilmir)"]
        audit(db, "LOGIN_OK", f"{username} ({user.role})")
        target = "/dashboard" if user.role == "customer" else "/staff/panel"
        resp = JSONResponse({"ok": True, "redirect": target, "trace": trace})
        resp.set_cookie("session", make_token(user), httponly=True, samesite="strict", max_age=1800)
        return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login")
    resp.delete_cookie("session")
    return resp


# ---------- musteri ----------
@app.get("/dashboard")
def dashboard(request: Request, user=Depends(current_user)):
    if not user or user.role != "customer":
        return RedirectResponse("/login")
    with Session() as db:
        acc = db.query(Account).filter_by(user_id=user.id).first()
        history = [{"to": crypto.decrypt(t.to_iban_enc), "amount": t.amount / 100, "ts": t.ts.replace("T", " ")[:16]}
                   for t in db.query(Transfer).filter_by(from_user=user.id).order_by(Transfer.id.desc()).limit(8)]
        ctx = {"user": user, "iban": crypto.decrypt(acc.iban_enc), "balance": acc.balance / 100, "history": history}
    return templates.TemplateResponse(request, "dashboard.html", ctx)


@app.post("/api/transfer")
def api_transfer(to_iban: str = Form(...), amount: str = Form(...), user=Depends(current_user)):
    if not user or user.role != "customer":
        return JSONResponse({"ok": False, "error": "Giriş tələb olunur", "trace": []}, status_code=401)
    to_iban = to_iban.replace(" ", "").upper()
    trace = [f"Sorğu gəldi, JWT yoxlandı (istifadəçi: {user.username}, rol: {user.role})"]
    fail = lambda msg: JSONResponse({"ok": False, "error": msg, "trace": trace}, status_code=400)
    try:
        cents = int(round(float(amount) * 100))
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
            trace.append(f"Anti-fraud: məbləğ {LIMIT_AZN} AZN limitini keçir, əməliyyat dayandırıldı")
            audit(db, "FRAUD_BLOCK", f"{user.username}: {cents/100} AZN limit asildi")
            return fail(f"Bir əməliyyat üçün limit {LIMIT_AZN} AZN-dir")
        trace.append("Anti-fraud: limit və vaxt qaydaları keçdi")
        dst = db.query(Account).filter_by(iban_idx=crypto.blind_index(to_iban)).first()
        trace.append("Alıcı HMAC indeksi ilə tapıldı (IBAN açıq mətnlə axtarılmadı)")
        if not dst or dst.id == src.id:
            return fail("Alıcı IBAN tapılmadı və ya özünüzə köçürmə")
        from_iban = crypto.decrypt(src.iban_enc)
        ts = now()
        to_enc, from_enc = crypto.encrypt(to_iban), crypto.encrypt(from_iban)
        trace.append("IBAN-lar AES-256-GCM ilə şifrələndi: " + to_enc[:28] + "…")
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


# ---------- isci ----------
def staff_only(user):
    return user and user.role == "staff"


@app.get("/staff/panel")
def staff_panel(request: Request, user=Depends(current_user)):
    if not staff_only(user):
        return RedirectResponse("/staff")
    with Session() as db:
        rows = []
        for t in db.query(Transfer).order_by(Transfer.id.desc()).limit(20):
            f, to = crypto.decrypt(t.from_iban_enc), crypto.decrypt(t.to_iban_enc)
            sender = db.query(User).filter_by(id=t.from_user).first()
            rows.append({"id": t.id, "name": mask_name(sender.full_name), "from": mask_iban(f), "to": mask_iban(to),
                         "amount": t.amount / 100, "ts": t.ts.replace("T", " ")[:16], "sig": t.signature[:20] + "…",
                         "valid": crypto.verify(payload(f, to, t.amount, t.ts), t.signature)})
        logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(12).all()
        target = db.query(User).filter_by(username="zahid").first()
        ctx = {"user": user, "rows": rows, "logs": logs, "chain": chain_ok(db),
               "target_locked": bool(target.locked)}
    return templates.TemplateResponse(request, "staff_panel.html", ctx)


@app.get("/staff/db")
def staff_db(request: Request, user=Depends(current_user)):
    if not staff_only(user):
        return RedirectResponse("/staff")
    with Session() as db:
        ctx = {"user": user, "users": db.query(User).all(), "accounts": db.query(Account).all(),
               "transfers": db.query(Transfer).order_by(Transfer.id.desc()).limit(10).all()}
    return templates.TemplateResponse(request, "staff_db.html", ctx)


@app.post("/staff/tamper/{tid}")
def tamper(tid: int, user=Depends(current_user)):
    """DEMO: bazaya sizan hucumcunun mebleği deyismesini simulyasiya edir."""
    if not staff_only(user):
        return RedirectResponse("/staff")
    with Session() as db:
        t = db.query(Transfer).filter_by(id=tid).first()
        if t:
            t.amount += 10000
            db.commit()
    return RedirectResponse("/staff/panel", status_code=303)


@app.post("/api/staff/unlock")
def unlock_demo_account(user=Depends(current_user)):
    """İşçi hesabı blokdan çıxarır (demonu təkrar etmək üçün də lazımdır)."""
    if not staff_only(user):
        return JSONResponse({"trace": []}, status_code=401)
    with Session() as db:
        target = db.query(User).filter_by(username="zahid").first()
        target.locked, target.failed_attempts = 0, 0
        db.commit()
        audit(db, "ACCOUNT_UNLOCKED", f"zahid: {user.username} terefinden blokdan cixarildi")
    return {"trace": [{"text": "Hesab blokdan çıxarıldı, sayğac sıfırlandı, hadisə jurnala yazıldı", "cls": "good"}]}


# ---------- hucumcu terminali (bankin ozune aid DEYIL, temsili xarici ekran) ----------
@app.get("/attacker")
def attacker_console(request: Request):
    return templates.TemplateResponse(request, "attacker.html", {})
