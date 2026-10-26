import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Users table - intentionally stores plaintext passwords for SQLi/IDOR practice
    cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            secret_note TEXT
        )
    """)
    cur.executemany(
        "INSERT INTO users (username, password, email, role, secret_note) VALUES (?, ?, ?, ?, ?)",
        [
            ("admin", "S3cr3tAdm1n!", "admin@vulnlab.local", "admin", "FLAG{sqli_union_master}"),
            ("alice", "alice123", "alice@vulnlab.local", "user", "Alice's private diary entry."),
            ("bob", "bobpass", "bob@vulnlab.local", "user", "Bob's bank PIN is 4521 (fake, for IDOR practice)."),
            ("guest", "guest", "guest@vulnlab.local", "user", "Nothing to see here."),
        ],
    )

    # Accounts table - this is the REAL, properly-secured login for the site itself.
    # Passwords are hashed (never stored in plaintext). This is separate from the
    # intentionally-vulnerable `users` table above, which exists only for the
    # SQLi/IDOR practice modules.
    cur.execute("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            role TEXT DEFAULT 'user',
            private_data TEXT
        )
    """)
    cur.executemany(
        "INSERT INTO accounts (username, password_hash, display_name, role, private_data) VALUES (?, ?, ?, ?, ?)",
        [
            (
                "admin",
                generate_password_hash("Admin@123"),
                "Administrator",
                "admin",
                "ADMIN VAULT: lab master key = VL-ADMIN-9F21. Only admin should ever see this.",
            ),
            (
                "student",
                generate_password_hash("Student@123"),
                "Student",
                "user",
                "Personal note: remember to finish the IDOR module before Friday.",
            ),
        ],
    )

    # Products table for UNION-based SQLi practice
    cur.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT,
            price REAL
        )
    """)
    cur.executemany(
        "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
        [
            ("Laptop", "15 inch, 16GB RAM", 55999.0),
            ("Mouse", "Wireless optical mouse", 499.0),
            ("Keyboard", "Mechanical RGB keyboard", 2499.0),
            ("Monitor", "27 inch 144Hz", 18999.0),
        ],
    )

    # Guestbook table for stored XSS practice
    cur.execute("""
        CREATE TABLE guestbook (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            message TEXT
        )
    """)
    cur.execute(
        "INSERT INTO guestbook (name, message) VALUES (?, ?)",
        ("System", "Welcome to the guestbook! Try leaving a stored XSS payload here."),
    )

    # OTP table - simulated OTP delivery for practice. The OTP is never shown
    # on the webpage; it is only "delivered" by writing to otp_log.txt (acting
    # as a stand-in for a real SMS/email gateway, which this lab never calls).
    cur.execute("""
        CREATE TABLE otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            code TEXT,
            attempts INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Orders table - simulated checkout/payment practice. No real payment
    # gateway is ever contacted and no real money moves; "card" fields are
    # stored as plain fake lab data only, never validated against a real network.
    cur.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            item_name TEXT,
            amount REAL,
            card_last4 TEXT,
            status TEXT DEFAULT 'PAID (simulated)'
        )
    """)

    conn.commit()
    conn.close()
    print("Database initialized at", DB_PATH)


if __name__ == "__main__":
    init_db()
