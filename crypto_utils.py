import os
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = sha256(b'secure_shared_key').digest()

def encrypt_message(message):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, message.encode(), None)
    return nonce + encrypted

def decrypt_message(data):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    encrypted = data[12:]
    return aesgcm.decrypt(nonce, encrypted, None).decode()

def hash_password(password):
    return sha256(password.encode()).hexdigest()