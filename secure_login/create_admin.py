#!/usr/bin/env python3
import sqlite3
import bcrypt
import time
import sys
import os

DB = "app.db"

def ensure_db():
    if not os.path.exists(DB):
        print("Database missing, creating from schema.sql...")
        with open("schema.sql","r") as f:
            schema = f.read()
        conn = sqlite3.connect(DB)
        conn.executescript(schema)
        conn.commit()
        conn.close()

def create_admin(username, password):
    ensure_db()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
        conn.commit()
        print(f"Created user '{username}'")
    except sqlite3.IntegrityError:
        print("User already exists. To change password, update the row directly or delete and recreate.")
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 create_admin.py <username> <password>")
        sys.exit(1)
    create_admin(sys.argv[1], sys.argv[2])
