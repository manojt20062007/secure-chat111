import socket
import threading
import sqlite3
from flask import Flask, request, jsonify
from crypto_utils import encrypt_message, decrypt_message, hash_password
import os

DB_FILE = "database.db"
clients = {}

# Flask web status page
app = Flask(__name__)

@app.route('/')
def index():
    return "✅ Secure Chat Server is Running (Socket + HTTP API)"

# --- HTTP API: SIGNUP ---
@app.route('/signup', methods=['POST'])
def http_signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Missing username or password"}), 400

    if user_exists(username):
        return jsonify({"status": "error", "message": "Username already exists"}), 409

    if create_user(username, password):
        return jsonify({"status": "success", "message": "Signup successful"})
    else:
        return jsonify({"status": "error", "message": "Signup failed"}), 500

# --- HTTP API: LOGIN ---
@app.route('/login', methods=['POST'])
def http_login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if verify_user(username, password):
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

# --- DB SETUP ---
def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL)''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")
    finally:
        if conn:
            conn.close()

def user_exists(username):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        return c.fetchone() is not None
    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")
        return False
    finally:
        if conn:
            conn.close()

def create_user(username, password):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")
        return False
    finally:
        if conn:
            conn.close()

def verify_user(username, password):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if result:
            return result[0] == hash_password(password)
        return False
    except sqlite3.Error as e:
        print(f"[DB ERROR] {e}")
        return False
    finally:
        if conn:
            conn.close()

def broadcast(msg, sender_sock):
    for client in clients:
        if client != sender_sock:
            try:
                client.send(msg)
            except:
                client.close()
                if client in clients:
                    clients.pop(client)

def handle_client(client):
    try:
        login_data = client.recv(1024).decode().strip()

        if login_data.startswith("SIGNUP|"):
            parts = login_data.split('|', 2)
            if len(parts) != 3:
                client.send(b'INVALID_FORMAT')
                client.close()
                return

            _, username, password = parts
            if user_exists(username):
                client.send(b'SIGNUP_FAILED')
            else:
                if create_user(username, password):
                    print(f"[+] New user registered: {username}")
                    client.send(b'SIGNUP_SUCCESS')
                else:
                    client.send(b'SIGNUP_FAILED')
            client.close()
            return

        if '|' not in login_data:
            client.send(b'INVALID_FORMAT')
            client.close()
            return

        username, password = login_data.split('|', 1)
        if not verify_user(username, password):
            client.send(b'LOGIN_FAILED')
            client.close()
            return

        client.send(b'LOGIN_SUCCESS')
        clients[client] = username
        print(f"[+] {username} joined.")

        while True:
            data = client.recv(4096)
            msg = decrypt_message(data)
            print(f"{username}: {msg}")
            broadcast(data, client)

    except (ConnectionResetError, ConnectionAbortedError):
        pass
    except Exception as e:
        print(f"[CLIENT ERROR] {e}")
    finally:
        if client in clients:
            print(f"[-] {clients[client]} disconnected.")
            clients.pop(client)
        client.close()

def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 56789))
    server.listen()
    print("[+] Server running on 0.0.0.0:56789")

    # Run Flask app in background
    threading.Thread(target=lambda: app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080))), daemon=True).start()

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    start_server()
