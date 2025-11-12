#!/usr/bin/env python3
import sqlite3
import time
from flask import Flask, g, render_template, request, redirect, url_for, session, flash
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import os

DB = "app.db"
LOCKOUT_THRESHOLD = 0       # failed attempts before temporary lock
LOCKOUT_SECONDS = 0       # lockout duration (5 minutes)
SESSION_TIMEOUT = 1800      # 30 minutes

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Rate limiter: per-IP rules (limits requests to login route)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def log_attempt(username, ip, success, reason=""):
    db = get_db()
    ts = int(time.time())
    db.execute("INSERT INTO login_attempts (username, ip, timestamp, success, reason) VALUES (?, ?, ?, ?, ?)",
               (username, ip, ts, 1 if success else 0, reason))
    db.commit()

def get_user(username):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return row

def increment_failed(username):
    db = get_db()
    db.execute("UPDATE users SET failed_count = failed_count + 1 WHERE username = ?", (username,))
    db.commit()

def reset_failed(username):
    db = get_db()
    db.execute("UPDATE users SET failed_count = 0, locked_until = 0 WHERE username = ?", (username,))
    db.commit()

def lock_account(username, seconds=LOCKOUT_SECONDS):
    until = int(time.time()) + seconds
    db = get_db()
    db.execute("UPDATE users SET locked_until = ?, failed_count = 0 WHERE username = ?", (until, username))
    db.commit()

def is_locked(user_row):
    if user_row is None:
        return False
    locked_until = user_row["locked_until"] or 0
    return int(time.time()) < locked_until

@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"], error_message="Too many login attempts from this IP. Try again later.")
def login():
    ip = request.remote_addr
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = get_user(username)
        # If user not found, still sleep a bit to avoid username probing (simple defense)
        if user is None:
            # log and fake check
            time.sleep(0.3)
            log_attempt(username, ip, False, reason="no-such-user")
            flash("Invalid credentials.", "error")
            return render_template("login.html")
        # Check lockout
        if is_locked(user):
            log_attempt(username, ip, False, reason="locked")
            flash("Account temporarily locked due to repeated failed attempts. Try later.", "error")
            return render_template("login.html")

        # Verify password using bcrypt
        stored_hash = user["password_hash"].encode()
        ok = bcrypt.checkpw(password.encode(), stored_hash)

        if ok:
            reset_failed(username)
            log_attempt(username, ip, True, reason="ok")
            session["user"] = username
            session["last_active"] = int(time.time())
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            increment_failed(username)
            # check threshold
            updated = get_user(username)
            if updated["failed_count"] >= LOCKOUT_THRESHOLD:
                lock_account(username)
                log_attempt(username, ip, False, reason="locked-after-threshold")
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_SECONDS//60} minutes.", "error")
            else:
                log_attempt(username, ip, False, reason="bad-password")
                flash("Invalid credentials.", "error")
            return render_template("login.html")
    # GET
    return render_template("login.html")

@app.before_request
def session_timeout():
    # Auto-logout after inactivity
    if "user" in session:
        now = int(time.time())
        last = session.get("last_active", now)
        if now - last > SESSION_TIMEOUT:
            session.clear()
            flash("Session timed out.", "info")
        else:
            session["last_active"] = now

@app.route("/dashboard")
def dashboard():
    if not session.get("user"):
        return redirect(url_for("login"))
    username = session.get("user")
    # show some minimal protected content
    return render_template("dashboard.html", user=username)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# Admin-only: simple view of recent attempts (local testing only)
@app.route("/admin/logs")
def admin_logs():
    if session.get("user") is None:
        return redirect(url_for("login"))
    # In a real app, you'd restrict this to real admin roles. This is just educational.
    db = get_db()
    rows = db.execute("SELECT * FROM login_attempts ORDER BY timestamp DESC LIMIT 200").fetchall()
    pretty = []
    for r in rows:
        pretty.append({
            "username": r["username"],
            "ip": r["ip"],
            "time": datetime.fromtimestamp(r["timestamp"]).isoformat(),
            "success": bool(r["success"]),
            "reason": r["reason"]
        })
    return {"attempts": pretty}

if __name__ == "__main__":
    # ensure DB exists
    if not os.path.exists(DB):
        with open("schema.sql","r") as f:
            schema = f.read()
        conn = sqlite3.connect(DB)
        conn.executescript(schema)
        conn.commit()
        conn.close()
        print("Database created. Use create_admin.py to add a user.")
    app.run(host="127.0.0.1", port=5000, debug=True)
