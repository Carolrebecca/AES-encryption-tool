# AES in Python (PyCryptodome) — GUI + Report

> Palette: **beige/brown**. GUI uses AES-CBC with PKCS7 padding and Base64 output that includes the IV.

---

## 1) What is AES? (Short Summary)
- **AES (Advanced Encryption Standard)** is a **symmetric-key** block cipher standardized by NIST.
- **Block size**: 128 bits (16 bytes).
- **Key sizes**: 128, 192, 256 bits (i.e., 16/24/32 bytes) → **10/12/14 rounds** respectively.
- Widely used in **Wi‑Fi (WPA2/WPA3)**, **SSL/TLS**, **disk encryption (BitLocker/FileVault)**, **messaging apps**, **VPNs**, etc.

## 2) Mode, IV, Padding
- We use **CBC (Cipher Block Chaining)** mode.
- A fresh **random IV (16 bytes)** is generated per encryption. The IV is **not secret** but **must be unique**; here it’s **prefixed** to the ciphertext and the whole blob is Base64 encoded for easy transport.
- AES operates on 16‑byte blocks, so we apply **PKCS#7 padding** to the plaintext before encryption and remove it on decryption.

## 3) Inputs and Outputs
**Inputs**
- **Plaintext**: any UTF‑8 string.
- **Secret key**: **exactly** 16/24/32 bytes (AES‑128/192/256). You can provide it as **Text**, **Hex**, or **Base64** in the GUI.
- (Optional) You can generate a strong random key via buttons (**128/192/256‑bit**).

**Outputs**
- **Ciphertext**: **Base64** string of `(IV || ciphertext)` (IV followed by ciphertext).  
- **Decrypted plaintext**: the original UTF‑8 text.

## 4) How to Run (Installation)
```bash
# 1) Create/activate a virtual environment (recommended)
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 2) Install dependencies
pip install pycryptodome

# 3) Run the GUI
python aes_gui.py

# (Optional) Run console demo to see real-time I/O in terminal
python demo_run.py
```

## 5) Code Files
- `aes_core.py` — clean, well‑commented AES utilities (encrypt/decrypt, key parsing & generation).
- `aes_gui.py` — Tkinter GUI in a beige/brown palette.
- `demo_run.py` — headless console demo that prints inputs/outputs.

## 6) Screenshots To Capture (for your report)
1. GUI with plaintext & key entered (use **Base64** generated key button to ensure valid length).
2. After clicking **Encrypt →**, capture the **Ciphertext (Base64)** field.
3. After clicking **← Decrypt**, capture the **Decrypted Plaintext** field showing the original text.
> Windows: `Win + Shift + S` • macOS: `Shift + Cmd + 4` • Ubuntu: `Shift + PrtScr`

## 7) Security Comparison
- **Caesar/Vigenère ciphers** are substitution-based and vulnerable to **frequency analysis** and known-plaintext attacks; they offer **no modern security**.
- **AES** is designed against these classical weaknesses, operates on binary blocks with complex transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey), and—when used with proper **modes (CBC/GCM)**, **random IVs**, and **key management**—is considered **secure** for modern applications.

## 8) Notes on Correctness & Safety
- **Key length enforcement**: Only 16/24/32‑byte keys are accepted. The GUI can parse keys given as **Text/Hex/Base64**.
- **Fresh IV per encryption**: Randomly generated and included in output.
- **Padding**: **PKCS#7** via PyCryptodome utilities.
- **Common mistakes avoided**: Reusing IVs, home‑rolled padding, or truncating ciphertext.

## 9) Library Reference
- **PyCryptodome**: `Crypto.Cipher.AES`, `Crypto.Util.Padding`, `Crypto.Random`

---

### Appendix A — How CBC Works (1‑minute refresher)
Given blocks `P1..Pn` and key `K`, with random IV:
- `C1 = AES_Enc(K, P1 ⊕ IV)`
- `C2 = AES_Enc(K, P2 ⊕ C1)`
- ...
- Decryption reverses this by XORing with previous ciphertext block.

### Appendix B — Rounds by Key Size
- AES‑128 → **10 rounds**
- AES‑192 → **12 rounds**
- AES‑256 → **14 rounds**
