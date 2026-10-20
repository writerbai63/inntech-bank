import os
from sqlalchemy.engine import URL

# =====================================================================
# config.py — Layihənin bütün "parametrləri" (baza ünvanı, gizli açar)
# burada toplanıb. Bu fayl kriptoqrafiya ilə bağlı deyil, amma
# INFOSEC baxımından vacibdir: parollar kodun özündə yazılmır,
# "environment variable" (mühit dəyişəni) adlanan ayrı, təhlükəsiz
# bir yerdən oxunur. Bu, real bankların da etdiyi işdir.
# =====================================================================

# Render (bulud) bizə DATABASE_URL adlı bir dəyişən verəcək.
# Lokal kompüterdə belə bir dəyişən olmadığı üçün bu None (boş) qayıdır.
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # --- BULUDDA İŞLƏYƏNDƏ (Render) ---
    # Render-in verdiyi ünvan "postgres://..." və ya "postgresql://..."
    # formatında olur, amma bizim istifadə etdiyimiz SQLAlchemy
    # kitabxanası "postgresql+psycopg2://..." formatını tələb edir.
    # Ona görə ünvanın əvvəlini uyğun formata çeviririk.
    if DATABASE_URL.startswith("postgres://"):
        DB_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
    elif DATABASE_URL.startswith("postgresql://"):
        DB_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
    else:
        DB_URL = DATABASE_URL
else:
    # --- LOKAL KOMPÜTERDƏ İŞLƏYƏNDƏ ---
    # Öz Postgres bazana bu məlumatlarla qoşuluruq.
    # Parol burada açıq yazılıb, ona görə bu fayl GitHub-a YÜKLƏNMİR
    # (.gitignore faylında qeyd olunub).
    DB_PASSWORD = "Huseyn78$"   # <-- oz Postgres parolun
    DB_URL = URL.create("postgresql+psycopg2", username="postgres", password=DB_PASSWORD,
                        host="localhost", port=5432, database="inntech_bank")

# SECRET_KEY — giriş sessiyalarını (JWT token) imzalamaq üçün istifadə olunan
# gizli açardır. Buludda mühit dəyişənindən oxunur, yoxdursa (lokalda)
# aşağıdakı defolt mətn istifadə olunur.
SECRET_KEY = os.environ.get("SECRET_KEY", "bunu-uzun-tesadufi-metnle-deyis-2026")
