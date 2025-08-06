from flask import Flask, request, jsonify
from crypto_utils import encrypt_message, decrypt_message, hash_password
import sqlite3
import os

app = Flask(__name__)
DB_FILE = "users.db"
CHAT_LOG = []

# --- DB SETUP ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL
                )""")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return "✅ Secure Chat Server is Running (HTTP API)"

# --- SIGNUP ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return jsonify({"status": "success", "message": "Signup successful"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    finally:
        conn.close()

# --- LOGIN ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result and result[0] == hash_password(password):
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

# --- SEND MESSAGE ---
@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    username = data.get("username")
    message = data.get("message")

    if not username or not message:
        return jsonify({"status": "error", "message": "Missing data"}), 400

    encrypted = encrypt_message(f"{username}: {message}")
    CHAT_LOG.append(encrypted)
    return jsonify({"status": "success", "message": "Message received"})

# --- GET MESSAGES ---
@app.route('/messages', methods=['GET'])
def get_messages():
    decrypted_messages = [decrypt_message(m) for m in CHAT_LOG]
    return jsonify({"messages": decrypted_messages})

# --- Main ---
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
