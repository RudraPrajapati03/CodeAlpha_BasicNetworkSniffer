"""Safer educational SQLite account helpers; standard library only."""
import hashlib
import hmac
import os
import re
import sqlite3

_ITERATIONS = 310_000
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

def validate_username(username: str) -> str:
    if not isinstance(username, str) or not _USERNAME_RE.fullmatch(username):
        raise ValueError("Username must be 3-32 characters: letters, digits, _, ., or -.")
    return username

def initialize_db(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_salt BLOB NOT NULL,
        password_hash BLOB NOT NULL
    )""")
    conn.commit()

def _derive_password_hash(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)

def create_user(conn: sqlite3.Connection, username: str, password: str) -> None:
    username = validate_username(username)
    salt = os.urandom(16)
    password_hash = _derive_password_hash(password, salt)
    with conn:
        conn.execute(
            "INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)",
            (username, salt, password_hash),
        )

def authenticate(conn: sqlite3.Connection, username: str, password: str) -> bool:
    try:
        username = validate_username(username)
    except ValueError:
        return False
    row = conn.execute(
        "SELECT password_salt, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        return False
    salt, expected_hash = row
    try:
        actual_hash = _derive_password_hash(password, salt)
    except ValueError:
        return False
    return hmac.compare_digest(actual_hash, expected_hash)

def demo() -> None:
    conn = sqlite3.connect(":memory:")
    initialize_db(conn)
    create_user(conn, "demo_user", "Correct-Horse-Battery-9")
    print("Correct password accepted:", authenticate(conn, "demo_user", "Correct-Horse-Battery-9"))
    print("Incorrect password accepted:", authenticate(conn, "demo_user", "wrong-password"))
    conn.close()

if __name__ == "__main__":
    demo()
