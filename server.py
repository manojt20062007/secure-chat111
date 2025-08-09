# server.py
import os
import sqlite3
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS

DB_FILE = "users.db"
app = Flask(__name__)
CORS(app, origins="*")  # allow CORS for development; tighten in production


def hash_password(password: str) -> str:
    """Simple SHA-256 password hashing (compatible with lightweight client)."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def get_db_conn():
    conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize DB and attempt to add pubkey column if it doesn't exist."""
    conn = get_db_conn()
    c = conn.cursor()
    # create users table (password may be empty string for placeholder)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL DEFAULT '',
            pubkey TEXT
        )
        """
    )
    # create messages table (server stores opaque ciphertext)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


@app.route("/", methods=["GET"])
def home():
    return "✅ Secure Chat Server is Running (E2E stored ciphertext only)"


# -------------------------
# Auth endpoints
# -------------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    hashed = hash_password(password)

    try:
        conn = get_db_conn()
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        return jsonify({"status": "success", "message": "signup ok"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "username exists"}), 409
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if row and row["password"] == hash_password(password):
            return jsonify({"status": "success", "message": "Login successful"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    finally:
        conn.close()


# -------------------------
# Public key endpoints
# -------------------------
@app.route("/upload_pubkey", methods=["POST"])
def upload_pubkey():
    """
    Client should POST JSON: { "username": "...", "pubkey": "<base64 string>" }
    This stores the user's public key in the users table (upsert behavior).
    """
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    pubkey = data.get("pubkey")

    if not username or not pubkey:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = get_db_conn()
    try:
        c = conn.cursor()
        # Try update first
        c.execute("UPDATE users SET pubkey = ? WHERE username = ?", (pubkey, username))
        if c.rowcount == 0:
            # user not present: insert with empty password (useful if client uploads before signup step)
            try:
                c.execute("INSERT INTO users (username, password, pubkey) VALUES (?, ?, ?)", (username, "", pubkey))
            except sqlite3.IntegrityError:
                # race; ignore and try update again
                c.execute("UPDATE users SET pubkey = ? WHERE username = ?", (pubkey, username))
        conn.commit()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()


@app.route("/pubkey/<username>", methods=["GET"])
def get_pubkey(username):
    username = username.strip()
    if not username:
        return jsonify({"status": "error", "message": "Missing username"}), 400

    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT pubkey FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "user not found"}), 404
        pubkey = row["pubkey"]
        if not pubkey:
            return jsonify({"status": "error", "message": "no pubkey"}), 404
        return jsonify({"pubkey": pubkey}), 200
    finally:
        conn.close()


@app.route("/users", methods=["GET"])
def list_users():
    """Return list of usernames (useful for peer discovery)."""
    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        rows = c.fetchall()
        users = [r["username"] for r in rows if r["username"]]
        return jsonify({"users": users}), 200
    finally:
        conn.close()


# -------------------------
# Messaging (store opaque ciphertexts only)
# -------------------------
@app.route("/send", methods=["POST"])
def send_message():
    """
    Body JSON: { "sender": "alice", "receiver": "bob", "message": "<base64 nonce+ciphertext+tag>" }
    The server never inspects or decrypts the message — it stores it verbatim.
    """
    data = request.get_json(force=True)
    sender = (data.get("sender") or "").strip()
    receiver = (data.get("receiver") or "").strip()
    message = data.get("message")

    if not sender or not receiver or not message:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)", (sender, receiver, message))
        conn.commit()
        return jsonify({"status": "success", "message": "Message stored"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        conn.close()


@app.route("/messages", methods=["GET"])
def get_messages():
    """
    Query params: user1, user2
    Returns all messages between user1 and user2 (server returns stored opaque ciphertexts).
    Client is responsible for decrypting.
    """
    user1 = (request.args.get("user1") or "").strip()
    user2 = (request.args.get("user2") or "").strip()

    if not user1 or not user2:
        return jsonify({"status": "error", "message": "Missing users"}), 400

    conn = get_db_conn()
    try:
        c = conn.cursor()
        c.execute(
            """
            SELECT sender, receiver, message, timestamp FROM messages
            WHERE (sender = ? AND receiver = ?)
               OR (sender = ? AND receiver = ?)
            ORDER BY timestamp ASC
            """,
            (user1, user2, user2, user1),
        )
        rows = c.fetchall()
        messages = []
        for r in rows:
            messages.append({
                "sender": r["sender"],
                "receiver": r["receiver"],
                "message": r["message"],  # opaque base64 token
                "timestamp": r["timestamp"]
            })
        return jsonify({"status": "success", "messages": messages}), 200
    finally:
        conn.close()


# -------------------------
# Startup
# -------------------------
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    host = "0.0.0.0"
    print(f"Starting Secure Chat Server on {host}:{port}")
    app.run(host=host, port=port)
