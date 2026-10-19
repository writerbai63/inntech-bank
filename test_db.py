import psycopg2

conn = psycopg2.connect(
    host="localhost",
    port=5432,
    dbname="inntech_bank",
    user="postgres",
    password="BURA_POSTGRES_PAROLUNU_YAZ"
)
print("Baza qosuldu!")
conn.close()