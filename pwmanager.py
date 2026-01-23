#!/usr/bin/env python3

#Application's purpose
"""
Simple local password manager MVP:
- Encrypted SQLite storage (Fernet)
- Add/list/get entries, password generator
- Optional TOTP storage (encrypted)
"""

#importing required funcitons
import sqlite3, os, sys, base64, time
from getpass import getpass                                             #securily read passowrds
from typing import Optional                                             #typed text could be either any type (str) or none
import secrets, string                                                  #provides cryptographically random number generation
from datetime import datetime                                           #for timestamps, datetime
import typer                                                            #to intereact with terminal 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC        #to turn master password into encryption key, PBKDF2 (password based key derivation function 2)
from cryptography.hazmat.primitives import hashes                       #import the hashes being used to encrypt
from cryptography.fernet import Fernet, InvalidToken                    #data protection and error handling if wrong password entered

APP = typer.Typer()             #creates application for terminal interface
DB_PATH = "vault.db"            #database name        
SALT_KEY = "kdf_salt"           #metadata keyname for storing salt in db
ITER_KEY = "kdf_iters"          #key name for storing PBKDF2 iteration count
DEFAULT_ITERS = 200_000         #default itertaion (high value makes brute force expensive)

# ---------- crypto helpers ----------

#funciton to derive 32 byte encryption key from password using PBKDF2
def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    raw = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(raw)

def new_salt() -> bytes:
    return secrets.token_bytes(16)

def encrypt(f: Fernet, plaintext: Optional[str]) -> Optional[bytes]:
    if plaintext is None:
        return None
    return f.encrypt(plaintext.encode("utf-8"))

def decrypt(f: Fernet, data: Optional[bytes]) -> Optional[str]:
    if data is None:
        return None
    try:
        return f.decrypt(data).decode("utf-8")
    except InvalidToken:
        raise RuntimeError("Incorrect master password or corrupted data.")

# ---------- DB helpers ----------

#initialize the db and store the crypto metadata
def init_db(conn: sqlite3.Connection, salt: bytes, iters: int):
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    username BLOB,
                    password BLOB,
                    category TEXT,
                    notes BLOB,
                    totp_secret BLOB,
                    created_at TEXT,
                    updated_at TEXT
                )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)""")
    # store salt & iteration count if not present
    cur.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (SALT_KEY, salt))
    cur.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (ITER_KEY, str(iters).encode()))
    conn.commit()

def get_meta(conn: sqlite3.Connection, key: str) -> Optional[bytes]:
    cur = conn.cursor()
    cur.execute("SELECT v FROM meta WHERE k = ?", (key,))
    r = cur.fetchone()
    return r[0] if r else None

# ---------- password generator ----------

#generates secure random password with configurable lengh and symbols
def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>/?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ---------- CLI commands ----------
@APP.command()
def init():
    """Initialize a new vault (creates DB and meta)."""
    if os.path.exists(DB_PATH):
        typer.confirm("vault.db already exists — overwrite?", abort=True)
        os.remove(DB_PATH)
    master = getpass("Create master password: ")
    confirm = getpass("Confirm master password: ")
    if master != confirm:
        typer.echo("Passwords do not match. Aborting.")
        raise typer.Exit(code=1)
    salt = new_salt()
    iters = DEFAULT_ITERS
    conn = sqlite3.connect(DB_PATH)
    init_db(conn, salt, iters)
    conn.close()
    typer.echo("Initialized vault at vault.db")

def _open_conn_and_fernet():
    if not os.path.exists(DB_PATH):
        typer.echo("Vault not found. Run `init` first.")
        raise typer.Exit(code=1)
    conn = sqlite3.connect(DB_PATH)
    salt = get_meta(conn, SALT_KEY)
    iters_b = get_meta(conn, ITER_KEY)
    if salt is None or iters_b is None:
        typer.echo("Vault metadata missing or corrupted.")
        conn.close()
        raise typer.Exit(code=1)
    iters = int(iters_b.decode())
    master = getpass("Master password: ")
    key = derive_key(master, salt, iters)
    f = Fernet(key)
    return conn, f

@APP.command()
def add(name: str, username: Optional[str] = typer.Option(None), category: Optional[str] = typer.Option("general"),
        length: int = typer.Option(16, help="Generate a password with this length"), generate: bool = False,
        notes: Optional[str] = None, totp: Optional[str] = None):
    """Add a new entry. Use --generate to auto-generate a password."""
    conn, f = _open_conn_and_fernet()
    cur = conn.cursor()
    if generate:
        password = generate_password(length)
        typer.echo(f"Generated password: {password}")
    else:
        password = getpass("Password for entry: ")
    cur.execute("INSERT INTO entries (name, username, password, category, notes, totp_secret, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (name,
                 encrypt(f, username),
                 encrypt(f, password),
                 category,
                 encrypt(f, notes),
                 encrypt(f, totp),
                 datetime.utcnow().isoformat(),
                 datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    typer.echo("Entry added.")

@APP.command()
def list(category: Optional[str] = typer.Option(None)):
    """List entries (names)."""
    conn, f = _open_conn_and_fernet()
    cur = conn.cursor()
    if category:
        cur.execute("SELECT id, name, category, created_at FROM entries WHERE category = ? ORDER BY name", (category,))
    else:
        cur.execute("SELECT id, name, category, created_at FROM entries ORDER BY name")
    rows = cur.fetchall()
    conn.close()
    for r in rows:
        typer.echo(f"{r[0]}: {r[1]} (category: {r[2]}, created: {r[3]})")

@APP.command()
def get(entry_id: int):
    """Retrieve an entry (decrypts username and password)."""
    conn, f = _open_conn_and_fernet()
    cur = conn.cursor()
    cur.execute("SELECT name, username, password, category, notes, totp_secret, created_at, updated_at FROM entries WHERE id = ?", (entry_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        typer.echo("Entry not found.")
        raise typer.Exit(code=1)
    name, username_b, password_b, category, notes_b, totp_b, created_at, updated_at = r
    try:
        username = decrypt(f, username_b)
        password = decrypt(f, password_b)
        notes = decrypt(f, notes_b)
        totp = decrypt(f, totp_b)
    except RuntimeError as e:
        typer.echo(str(e))
        raise typer.Exit(code=1)
    typer.echo(f"Name: {name}\nCategory: {category}\nUsername: {username}\nPassword: {password}\nNotes: {notes}\nTOTP secret: {totp}\nCreated: {created_at}\nUpdated: {updated_at}")

@APP.command()
def gen(length: int = 20, symbols: bool = True):
    """Just print a generated password."""
    p = generate_password(length, use_symbols=symbols)
    typer.echo(p)

if __name__ == "__main__":
    APP()

