import os
import base64
import json
import time
import hmac
import hashlib
import struct
import qrcode

DB_FILE = "users.json"
INTERVAL = 30
CODE_DIGITS = 6


def generate_secret():
    return os.urandom(20)


def base32_encode(secret: bytes) -> str:
    return base64.b32encode(secret).decode("utf-8").replace("=", "")


def base32_decode(secret: str) -> bytes:

    padding = "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(secret + padding)


def generate_recovery_codes(count=5):
    return [
        base64.b32encode(os.urandom(5)).decode("utf-8").replace("=", "")
        for _ in range(count)
    ]


def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)


def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def verify_code(secret: bytes, code: str, interval=INTERVAL, window=1) -> bool:
    current = int(time.time()) // interval
    for i in range(-window, window + 1):
        msg = struct.pack(">Q", current + i)
        h = hmac.new(secret, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        truncated_hash = h[offset : offset + 4]
        candidate = struct.unpack(">I", truncated_hash)[0] & 0x7FFFFFFF
        generated_code = str(candidate % (10**CODE_DIGITS)).zfill(CODE_DIGITS)
        if generated_code == code:
            return True
    return False


def setup_user():
    db = load_db()
    username = input("Enter username: ").strip()
    if username in db:
        print("User already exists.")
        return

    secret = generate_secret()
    recovery_codes = generate_recovery_codes()
    secret_b32 = base32_encode(secret)

    db[username] = {"secret": secret_b32, "recovery_codes": recovery_codes}
    save_db(db)

    print("\n=== Activation Secret ===")
    print(secret_b32)
    print("Recovery Codes:")
    for code in recovery_codes:
        print(" -", code)

    otpauth_uri = f"otpauth://totp/{username}?secret={secret_b32}&issuer=Custom2FA"
    qr = qrcode.make(otpauth_uri)
    qr_file = f"{username}_qr.png"
    qr.save(qr_file)
    print(f"QR code saved as: {qr_file}")
    print("Scan the QR code with Google Authenticator.")


def verify_user_code():
    db = load_db()
    username = input("Username: ").strip()
    if username not in db:
        print("User not found.")
        return

    code = input("Enter 2FA code: ").strip()
    secret = base32_decode(db[username]["secret"])

    if verify_code(secret, code):
        print("✅ 2FA Verification Successful.")
    elif code in db[username]["recovery_codes"]:
        print("⚠️ Logged in with recovery code.")
        db[username]["recovery_codes"].remove(code)
        save_db(db)
    else:
        print("❌ Invalid code.")


if __name__ == "__main__":
    print("1. Setup user\n2. Verify code")
    choice = input("Choose (1/2): ")
    if choice == "1":
        setup_user()
    else:
        verify_user_code()
