"""INTENTIONALLY VULNERABLE teaching sample. Do not use in production."""
import sqlite3

def find_user(conn: sqlite3.Connection, username: str):
    # VULNERABILITY: untrusted input is concatenated into SQL.
    quote = chr(39)
    query = "SELECT username, password FROM users WHERE username = " + quote + username + quote
    return conn.execute(query).fetchone()

def password_matches(stored_password: str, supplied_password: str) -> bool:
    # VULNERABILITY: assumes passwords are stored in plaintext.
    return stored_password == supplied_password
