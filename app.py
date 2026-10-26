"""
VulnLab - Intentional Vulnerability Practice Lab
=================================================
FOR LOCAL / ISOLATED LEARNING USE ONLY.
Do NOT deploy this on the public internet or any shared network.
Every endpoint here is deliberately insecure so you can practice
bug bounty / VAPT style testing (SQLi, XSS, Command Injection,
IDOR, Insecure File Upload, Broken Auth) in a safe sandbox.
"""

import sqlite3
import subprocess
import os
import secrets
import random
import datetime
from functools import wraps
from flask import Flask, request, render_template, g, redirect, url_for, session, flash
from werkzeug.security import check_password_hash

from database import init_db, DB_PATH

app = Flask(__name__)
# Real, randomly generated secret key for signing the SITE's own login session.
# (The deliberately weak key from earlier labs stays only inside the broken-auth
# module itself, demonstrated via a plain cookie rather than this session.)
app.secret_key = secrets.token_hex(32)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Simulated "SMS/email gateway" log. No real message is ever sent anywhere —
# this file is the ONLY place the OTP is written. It stands in for whatever a
# real provider (Twilio/MSG91/etc.) would normally deliver to a phone.
OTP_LOG_PATH = os.path.join(os.path.dirname(__file__), "otp_log.txt")


def deliver_otp_simulated(account_id, username, code):
    line = f"[{datetime.datetime.now().isoformat(timespec='seconds')}] Simulated SMS to account #{account_id} ({username}): your VulnLab OTP is {code}\n"
    with open(OTP_LOG_PATH, "a") as f:
        f.write(line)
    print(line.strip())  # also visible in the server console


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------- REAL AUTH (site gate)
def login_required(view):
    """Protects a route: only a genuinely logged-in account may access it.
    This is the CORRECT pattern (session-based, server-verified) — compare it
    with the intentionally broken /broken-auth module elsewhere in this app."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("account_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # SAFE: parameterized query, hashed password comparison
        row = get_db().execute(
            "SELECT id, username, password_hash, display_name, role FROM accounts WHERE username = ?",
            (username,),
        ).fetchone()
        if row and check_password_hash(row[2], password):
            session.clear()
            session["account_id"] = row[0]
            session["username"] = row[1]
            session["display_name"] = row[3]
            session["account_role"] = row[4]
            next_url = request.args.get("next") or url_for("home")
            return redirect(next_url)
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account/vault")
@login_required
def vault():
    """A correctly authorized page: every user only ever sees THEIR OWN record,
    taken from the server-side session, never from a client-suppliable id."""
    row = get_db().execute(
        "SELECT username, display_name, role, private_data FROM accounts WHERE id = ?",
        (session["account_id"],),
    ).fetchone()
    return render_template("vault.html", account=row)


# ---------------------------------------------------------------- HOME
@app.route("/")
@login_required
def home():
    return render_template("home.html")


# ---------------------------------------------------------- MODULE 1: SQLi LOGIN
@app.route("/sqli-login", methods=["GET", "POST"])
@login_required
def sqli_login():
    result = None
    query_shown = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: raw string concatenation -> classic SQL injection
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        query_shown = query
        try:
            cur = get_db().execute(query)
            row = cur.fetchone()
            if row:
                result = {"id": row[0], "username": row[1], "role": row[2]}
            else:
                result = "No match found."
        except sqlite3.Error as e:
            result = f"SQL Error: {e}"
    return render_template("sqli_login.html", result=result, query_shown=query_shown)


# ---------------------------------------------------------- MODULE 2: SQLi SEARCH (UNION-based)
@app.route("/sqli-search")
@login_required
def sqli_search():
    q = request.args.get("q", "")
    rows = []
    error = None
    query_shown = None
    if q:
        # VULNERABLE: unsanitized input concatenated into query -> good for UNION-based practice
        query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{q}%'"
        query_shown = query
        try:
            rows = get_db().execute(query).fetchall()
        except sqlite3.Error as e:
            error = str(e)
    return render_template("sqli_search.html", rows=rows, q=q, error=error, query_shown=query_shown)


# ---------------------------------------------------------- MODULE 3: REFLECTED XSS
@app.route("/xss-reflected")
@login_required
def xss_reflected():
    name = request.args.get("name", "")
    # VULNERABLE: user input rendered back without escaping (template uses |safe)
    return render_template("xss_reflected.html", name=name)


# ---------------------------------------------------------- MODULE 4: STORED XSS (Guestbook)
@app.route("/xss-stored", methods=["GET", "POST"])
@login_required
def xss_stored():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "Anonymous")
        message = request.form.get("message", "")
        # Stored as-is; rendered unescaped in template -> stored XSS
        db.execute("INSERT INTO guestbook (name, message) VALUES (?, ?)", (name, message))
        db.commit()
        return redirect(url_for("xss_stored"))
    entries = db.execute("SELECT name, message FROM guestbook ORDER BY id DESC").fetchall()
    return render_template("xss_stored.html", entries=entries)


# ---------------------------------------------------------- MODULE 5: COMMAND INJECTION
@app.route("/cmdi", methods=["GET", "POST"])
@login_required
def cmdi():
    output = None
    cmd_shown = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABLE: user input passed straight to shell
        cmd = f"ping -c 1 {host}"
        cmd_shown = cmd
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode(errors="ignore")
        except Exception as e:
            output = str(e)
    return render_template("cmdi.html", output=output, cmd_shown=cmd_shown)


# ---------------------------------------------------------- MODULE 6: IDOR
@app.route("/idor")
@login_required
def idor():
    session.setdefault("logged_in_user_id", 2)  # pretend "alice" (id=2) is logged in
    user_id = request.args.get("id", session["logged_in_user_id"])
    # VULNERABLE: no ownership/authorization check -> IDOR
    row = get_db().execute(
        "SELECT id, username, email, secret_note FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return render_template("idor.html", user=row, requested_id=user_id)


# ---------------------------------------------------------- MODULE 7: INSECURE FILE UPLOAD
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    message = None
    files = os.listdir(UPLOAD_DIR)
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # VULNERABLE: no extension/type/content checks -> can upload .php/.py/.html etc.
            save_path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(save_path)
            message = f"Uploaded: {f.filename}"
            files = os.listdir(UPLOAD_DIR)
    return render_template("upload.html", message=message, files=files)


# ---------------------------------------------------------- MODULE 8: BROKEN AUTH / WEAK SESSION
@app.route("/broken-auth")
@login_required
def broken_auth():
    # VULNERABLE: role trusted from a plain cookie, no signature/verification
    role = request.cookies.get("role", "user")
    return render_template("broken_auth.html", role=role)


# ---------------------------------------------------------- MODULE 9: OTP VERIFICATION
@app.route("/otp", methods=["GET"])
@login_required
def otp_page():
    return render_template("otp.html", sent=session.get("otp_sent", False))


@app.route("/otp/send", methods=["POST"])
@login_required
def otp_send():
    db = get_db()
    # VULNERABLE (on purpose): only 4 digits -> small keyspace for brute-force practice.
    code = f"{random.randint(0, 9999):04d}"
    db.execute(
        "INSERT INTO otp_codes (account_id, code, attempts, verified) VALUES (?, ?, 0, 0)",
        (session["account_id"], code),
    )
    db.commit()
    deliver_otp_simulated(session["account_id"], session["username"], code)
    session["otp_sent"] = True
    # The code itself is intentionally NOT returned here or rendered anywhere
    # in the page/response - check otp_log.txt (simulated gateway) instead.
    return redirect(url_for("otp_page"))


@app.route("/otp/verify", methods=["POST"])
@login_required
def otp_verify():
    db = get_db()
    submitted = request.form.get("code", "")
    row = db.execute(
        "SELECT id, code, attempts FROM otp_codes WHERE account_id = ? ORDER BY id DESC LIMIT 1",
        (session["account_id"],),
    ).fetchone()
    result = None
    if row:
        otp_id, real_code, attempts = row
        # VULNERABLE (on purpose): no attempt limit / lockout / delay -> brute-forceable
        db.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", (otp_id,))
        db.commit()
        if submitted == real_code:
            db.execute("UPDATE otp_codes SET verified = 1 WHERE id = ?", (otp_id,))
            db.commit()
            result = "success"
        else:
            result = "fail"
    else:
        result = "none_sent"
    return render_template("otp.html", sent=True, result=result)


# ---------------------------------------------------------- MODULE 10: SIMULATED CHECKOUT / PAYMENT
@app.route("/checkout", methods=["GET"])
@login_required
def checkout():
    products = get_db().execute("SELECT id, name, description, price FROM products").fetchall()
    return render_template("checkout.html", products=products)


@app.route("/checkout/pay", methods=["POST"])
@login_required
def checkout_pay():
    db = get_db()
    item_name = request.form.get("item_name", "Unknown item")
    # VULNERABLE (on purpose): trusts the price submitted by the CLIENT
    # (a hidden form field) instead of re-looking it up server-side from
    # the products table -> classic price-tampering / business-logic bug.
    amount = request.form.get("amount", "0")
    card_number = request.form.get("card_number", "0000000000000000")
    card_last4 = card_number[-4:] if len(card_number) >= 4 else "0000"

    db.execute(
        "INSERT INTO orders (account_id, item_name, amount, card_last4, status) VALUES (?, ?, ?, ?, 'PAID (simulated)')",
        (session["account_id"], item_name, amount, card_last4),
    )
    db.commit()
    return redirect(url_for("orders_page"))


@app.route("/orders")
@login_required
def orders_page():
    # Correctly scoped to the logged-in account only (compare with /idor).
    rows = get_db().execute(
        "SELECT id, item_name, amount, card_last4, status FROM orders WHERE account_id = ? ORDER BY id DESC",
        (session["account_id"],),
    ).fetchall()
    return render_template("orders.html", orders=rows)


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    print("=" * 60)
    print("  VulnLab running at http://127.0.0.1:5000")
    print("  FOR LOCAL LEARNING USE ONLY - do not expose publicly")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
