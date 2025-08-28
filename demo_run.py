# Headless demo (no GUI) to show real-time input/output in console
from aes_core import generate_key, encrypt, decrypt
import base64

def main():
    key = generate_key(256)  # 256-bit key
    key_b64 = base64.b64encode(key).decode("utf-8")
    plaintext = "Hello AES! 👋 This is a demo message."
    print("=== DEMO RUN ===")
    print(f"Key (Base64): {key_b64}")
    print(f"Plaintext: {plaintext}")
    ciphertext = encrypt(plaintext, key)
    print(f"Ciphertext (Base64 iv|ct): {ciphertext}")
    recovered = decrypt(ciphertext, key)
    print(f"Decrypted: {recovered}")
    print(f"Match: {recovered == plaintext}")

if __name__ == "__main__":
    main()
