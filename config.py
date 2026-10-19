import os
from sqlalchemy.engine import URL

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # Buludda (Render): mühit dəyişənindən oxuyur, parol kodda yoxdur
       if DATABASE_URL.startswith("postgres://"):
        DB_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql://"):
        DB_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
    else:
        DB_URL = DATABASE_URL
else:
    # Lokalda (öz kompüterində): öz Postgres parolunla qoşulur
    DB_PASSWORD = "Huseyn78$"   # <-- oz Postgres parolun
    DB_URL = URL.create("postgresql+psycopg2", username="postgres", password=DB_PASSWORD,
                        host="localhost", port=5432, database="inntech_bank")

SECRET_KEY = os.environ.get("SECRET_KEY", "bunu-uzun-tesadufi-metnle-deyis-2026")