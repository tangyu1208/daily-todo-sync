# -*- coding: utf-8 -*-
"""
按日记事 · Cloud Sync Backend
- 账号密码注册/登录
- 待办数据云端同步
- 部署: Render / Railway / 任意支持 Python 的平台
"""

import os
import json
import time
import secrets
import sqlite3
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "todos.db")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))


# ---------- DB ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            pass_hash TEXT,
            created_at REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS todos (
            username TEXT PRIMARY KEY,
            data TEXT DEFAULT '{}',
            updated_at REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT,
            created_at REAL
        );
    """)
    conn.commit()
    conn.close()


init_db()


# ---------- Helpers ----------
def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def generate_token():
    return secrets.token_urlsafe(32)


def verify_token(token):
    conn = get_db()
    row = conn.execute(
        "SELECT username FROM tokens WHERE token=? AND created_at > ?",
        (token, time.time() - 86400 * 30),
    ).fetchone()
    conn.close()
    return row["username"] if row else None


# ---------- Routes ----------
@app.route("/")
def index():
    return "按日记事 · Cloud Sync API ✅"


@app.route("/api/register", methods=["POST"])
def register():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or len(username) < 2:
        return jsonify(ok=False, error="用户名至少2个字符"), 400
    if not password or len(password) < 4:
        return jsonify(ok=False, error="密码至少4个字符"), 400
    conn = get_db()
    existing = conn.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify(ok=False, error="用户名已存在"), 400
    conn.execute(
        "INSERT INTO users(username, pass_hash, created_at) VALUES(?, ?, ?)",
        (username, hash_password(password), time.time()),
    )
    conn.commit()
    conn.close()
    return jsonify(ok=True, message="注册成功")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify(ok=False, error="请输入用户名和密码"), 400
    conn = get_db()
    row = conn.execute(
        "SELECT pass_hash FROM users WHERE username=?", (username,)
    ).fetchone()
    if not row or row["pass_hash"] != hash_password(password):
        conn.close()
        return jsonify(ok=False, error="用户名或密码错误"), 400
    token = generate_token()
    conn.execute(
        "INSERT INTO tokens(token, username, created_at) VALUES(?, ?, ?)",
        (token, username, time.time()),
    )
    conn.commit()
    conn.close()
    return jsonify(ok=True, token=token, username=username)


@app.route("/api/todos", methods=["GET"])
def get_todos():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = verify_token(token)
    if not username:
        return jsonify(ok=False, error="未登录或登录已过期"), 401
    conn = get_db()
    row = conn.execute(
        "SELECT data, updated_at FROM todos WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if row:
        return jsonify(ok=True, data=json.loads(row["data"]), updated_at=row["updated_at"])
    return jsonify(ok=True, data={}, updated_at=0)


@app.route("/api/todos", methods=["POST"])
def save_todos():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = verify_token(token)
    if not username:
        return jsonify(ok=False, error="未登录或登录已过期"), 401
    data = (request.json or {}).get("data", {})
    ts = time.time()
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO todos(username, data, updated_at) VALUES(?, ?, ?)",
        (username, json.dumps(data, ensure_ascii=False), ts),
    )
    conn.commit()
    conn.close()
    return jsonify(ok=True, updated_at=ts)


@app.route("/api/user", methods=["GET"])
def user_info():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = verify_token(token)
    if not username:
        return jsonify(ok=False, error="未登录"), 401
    return jsonify(ok=True, username=username)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
