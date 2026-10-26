"""
database.py - a real (tiny) SQLite backend for the /login demo.

This exists to make the SQL Injection demo concrete instead of
simulated: there is an actual users table, and an actual SQL query
runs against it. Two query builders are provided on purpose:

  check_login_vulnerable() - builds SQL with an f-string. This is the
      textbook mistake that makes SQL Injection possible: user input
      becomes part of the SQL statement itself.

  check_login_safe() - uses a parameterized query (placeholders + a
      params tuple). The database driver keeps user input as DATA,
      never as part of the SQL statement, so injection payloads can't
      change the query's meaning - even if the WAF were somehow off.

settings.query_mode (see settings.py) decides which one app.py calls.
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.db")


def init_db():
    """Create the users table and seed two demo accounts, if not already there."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [("admin", "admin123"), ("alice", "wonderland")],
        )
    conn.commit()
    conn.close()


def check_login_vulnerable(username, password):
    """
    INTENTIONALLY VULNERABLE to SQL Injection.

    The query is assembled with an f-string, so anything the user
    types becomes literal SQL. A username like  ' OR '1'='1' --
    turns the query into one that is always true (the trailing --
    comments out the password check), returning every row.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = f"SELECT username FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error:
        row = None
    conn.close()
    return row, query


def check_login_safe(username, password):
    """
    SAFE from SQL Injection: a parameterized query.

    The ? placeholders are filled in by the SQLite driver, not by
    string concatenation, so the username/password are always treated
    as plain data - quotes and SQL keywords included - and can never
    change what the query does.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = "SELECT username FROM users WHERE username = ? AND password = ?"
    cur.execute(query, (username, password))
    row = cur.fetchone()
    conn.close()
    # Show the placeholder form alongside the actual values for the demo view.
    readable_query = f"{query}   -- params: ({username!r}, {password!r})"
    return row, readable_query
