import os, sqlite3
from contextlib import contextmanager

def connect():
    url=os.getenv("TURSO_DATABASE_URL","").strip()
    token=os.getenv("TURSO_AUTH_TOKEN","").strip()
    if url and token:
        import turso_serverless
        return turso_serverless.connect(url, auth_token=token)
    # Local-only fallback. Render should always receive Turso credentials.
    conn=sqlite3.connect(os.getenv("LOCAL_DB_PATH","nexora_local.db"), timeout=30)
    conn.row_factory=sqlite3.Row
    return conn

def init_db():
    db=connect()
    schema=[
    """CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer', credits INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, product_id TEXT NOT NULL, label TEXT NOT NULL, price_cents INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 1, FOREIGN KEY(product_id) REFERENCES products(id))""",
    """CREATE TABLE IF NOT EXISTS key_inventory(id TEXT PRIMARY KEY, product_id TEXT NOT NULL, plan_id TEXT, secret_value TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'available', sold_to TEXT, sold_at TEXT, created_at TEXT NOT NULL, FOREIGN KEY(product_id) REFERENCES products(id))""",
    """CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, product_id TEXT NOT NULL, plan_id TEXT NOT NULL, quantity INTEGER NOT NULL, total_cents INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS credit_ledger(id TEXT PRIMARY KEY, user_id TEXT NOT NULL, amount INTEGER NOT NULL, reason TEXT NOT NULL, admin_id TEXT, created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)"""
    ]
    for sql in schema: db.execute(sql)
    db.commit()
    db.close()

@contextmanager
def db_conn():
    c=connect()
    try: yield c
    finally: c.close()
