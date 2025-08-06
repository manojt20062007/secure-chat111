from flask import Flask, request, jsonify
from crypto_utils import encrypt_message, decrypt_message, hash_password
import sqlite3
import os

app = Flask(__name__)
DB_FILE = "users.db"

# Initialize DB with messages table
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                    sender TEXT,
                    receiver TEXT,
                    message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )""")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return "✅ Secure Chat Server is Running (E2E Chat Enabled)"

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return jsonify({"status": "success", "message": "Signup successful"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    finally:
        conn.close()

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

@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    sender = data.get("sender")
    receiver = data.get("receiver")
    message = data.get("message")

    if not sender or not receiver or not message:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    encrypted = encrypt_message(message)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)", (sender, receiver, encrypted))
    conn.commit()
    conn.close()

    return jsonify({"status": "success", "message": "Message sent"})

@app.route('/messages', methods=['GET'])
def get_messages():
    user1 = request.args.get("user1")
    user2 = request.args.get("user2")

    if not user1 or not user2:
        return jsonify({"status": "error", "message": "Missing users"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""SELECT sender, receiver, message, timestamp FROM messages
                 WHERE (sender = ? AND receiver = ?)
                    OR (sender = ? AND receiver = ?)
                 ORDER BY timestamp ASC""", (user1, user2, user2, user1))
    rows = c.fetchall()
    conn.close()

    decrypted_messages = []
    for sender, receiver, msg, ts in rows:
        decrypted_messages.append({
            "sender": sender,
            "receiver": receiver,
            "message": decrypt_message(msg),
            "timestamp": ts
        })

    return jsonify({"status": "success", "messages": decrypted_messages})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
