import base64
import time
import hmac
import hashlib
import struct
import os
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

CONFIG_FILE = "client_secret.enc"
INTERVAL = 30
CODE_DIGITS = 6

def pad(data: bytes) -> bytes:
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def encrypt_secret(secret: str, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(secret.encode()))
    return base64.b64encode(salt + cipher.iv + ct_bytes)

def decrypt_secret(enc: bytes, password: str) -> str:
    raw = base64.b64decode(enc)
    salt, iv, ct = raw[:16], raw[16:32], raw[32:]
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct)).decode()

def generate_code(secret: bytes, interval=INTERVAL, digits=CODE_DIGITS) -> str:
    counter = int(time.time()) // interval
    msg = struct.pack(">Q", counter)
    h = hmac.new(secret, msg, hashlib.sha256).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

def setup_client():
    activation = input("Enter activation code (base32): ").strip()
    password = getpass("Set a password to protect your 2FA secret: ")
    encrypted = encrypt_secret(activation, password)
    with open(CONFIG_FILE, "wb") as f:
        f.write(encrypted)
    print("Secret stored and encrypted.")

def show_code_loop():
    if not os.path.exists(CONFIG_FILE):
        setup_client()

    password = getpass("Enter your password to unlock the 2FA secret: ")
    with open(CONFIG_FILE, "rb") as f:
        encrypted = f.read()

    try:
        secret_b32 = decrypt_secret(encrypted, password)
        secret = base64.b32decode(secret_b32)
    except:
        print("Decryption failed. Wrong password or corrupted file.")
        return

    print("Press Ctrl+C to exit.")
    try:
        while True:
            code = generate_code(secret)
            time_remaining = INTERVAL - int(time.time()) % INTERVAL
            print(f"\r2FA Code: {code} | Expires in: {time_remaining}s", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExited.")

if __name__ == "__main__":
    show_code_loop()
