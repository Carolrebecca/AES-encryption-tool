import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

from aes_core import encrypt, decrypt, generate_key, parse_key

PALETTE = {
    "bg": "#F5F0E6",
    "panel": "#FFF8EE",
    "accent": "#B08968",
    "dark": "#6B4F3B",
    "text": "#2B2B2B",
    "ok": "#2E7D32",
    "err": "#C62828"
}


class AESApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Encrypt/Decrypt model")
        self.configure(bg=PALETTE["bg"])
        self.minsize(900, 640)

        self._build_style()
        self._build_widgets()

    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Card.TFrame", background=PALETTE["panel"], relief="flat")
        style.configure("TLabel", background=PALETTE["panel"], foreground=PALETTE["text"])
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground=PALETTE["dark"], background=PALETTE["bg"])
        style.configure("SubHeader.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("TButton", font=("Segoe UI", 11, "bold"))
        style.map(
            "TButton",
            background=[("!disabled", PALETTE["accent"]), ("pressed", PALETTE["dark"]), ("active", PALETTE["dark"])],
            foreground=[("!disabled", "white")]
        )
        style.configure("Key.TEntry", fieldbackground="white")
        style.configure("Plain.TEntry", fieldbackground="white")

    def _build_widgets(self):
        # Header
        header = ttk.Label(self, text="AES encryption tool", style="Header.TLabel")
        header.pack(padx=20, pady=(16, 8), anchor="w")

        

        # Main grid container
        container = ttk.Frame(self, style="Card.TFrame", padding=16)
        container.pack(fill="both", expand=True, padx=20, pady=12)

        container.columnconfigure(0, weight=1, uniform="col")
        container.columnconfigure(1, weight=1, uniform="col")

        # Left: Input & Key
        left = ttk.Frame(container, style="Card.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        # Right: Output
        right = ttk.Frame(container, style="Card.TFrame")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        # --- Left side content ---
        ttk.Label(left, text="Input").grid(row=0, column=0, sticky="w")
        self.plaintext = ScrolledText(left, height=10, wrap="word", background="white", foreground=PALETTE["text"], insertbackground=PALETTE["text"])
        self.plaintext.grid(row=1, column=0, sticky="nsew", pady=(4, 12))
        left.rowconfigure(1, weight=1)

        # Key controls
        key_frame = ttk.Frame(left, style="Card.TFrame")
        key_frame.grid(row=2, column=0, sticky="ew", pady=(4, 12))
        key_frame.columnconfigure(1, weight=1)

        self.key_encoding = tk.StringVar(value="text")
        ttk.Label(key_frame, text="Key Encoding:").grid(row=0, column=0, sticky="w")
        enc_frame = ttk.Frame(key_frame, style="Card.TFrame")
        enc_frame.grid(row=0, column=1, sticky="w", pady=4)
        for val, lbl in (("text", "Text"), ("hex", "Hex"), ("base64", "Base64")):
            ttk.Radiobutton(enc_frame, text=lbl, value=val, variable=self.key_encoding).pack(side="left", padx=(0, 8))

        ttk.Label(key_frame, text="Quick Keygen:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        btns = ttk.Frame(key_frame, style="Card.TFrame")
        btns.grid(row=1, column=1, sticky="w", pady=(6, 0))
        ttk.Button(btns, text="128-bit", command=lambda: self._gen_key(128)).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="192-bit", command=lambda: self._gen_key(192)).pack(side="left", padx=6)
        ttk.Button(btns, text="256-bit", command=lambda: self._gen_key(256)).pack(side="left", padx=6)

        # Moved Key entry BELOW Quick Keygen
        ttk.Label(key_frame, text="Key (16/24/32 bytes)").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=(6, 0))
        self.key_entry = ttk.Entry(key_frame, width=48, style="Key.TEntry")
        self.key_entry.grid(row=2, column=1, sticky="ew", pady=(6, 6))

        # Action buttons
        action_frame = ttk.Frame(left, style="Card.TFrame")
        action_frame.grid(row=3, column=0, sticky="ew", pady=(4, 0))
        ttk.Button(action_frame, text="Encrypt →", command=self.do_encrypt).pack(side="left", padx=(0, 10))
        ttk.Button(action_frame, text="← Decrypt", command=self.do_decrypt).pack(side="left", padx=10)
        ttk.Button(action_frame, text="ALL CLEAR", command=self.do_clear).pack(side="left", padx=10)  # NEW button

        # --- Right side content ---
        ttk.Label(right, text="Ciphertext (Base64, includes IV)").grid(row=0, column=0, sticky="w")
        self.ciphertext = ScrolledText(right, height=8, wrap="word", background="white", foreground=PALETTE["text"], insertbackground=PALETTE["text"])
        self.ciphertext.grid(row=1, column=0, sticky="nsew", pady=(4, 12))

        ct_btns = ttk.Frame(right, style="Card.TFrame")
        ct_btns.grid(row=2, column=0, sticky="w")
        ttk.Button(ct_btns, text="Copy Ciphertext", command=lambda: self._copy(self.ciphertext)).pack(side="left")

        ttk.Label(right, text="Decrypted Plaintext").grid(row=3, column=0, sticky="w", pady=(12, 0))
        self.decrypted = ScrolledText(right, height=8, wrap="word", background="white", foreground=PALETTE["text"], insertbackground=PALETTE["text"])
        self.decrypted.grid(row=4, column=0, sticky="nsew", pady=(4, 12))

        right.rowconfigure(1, weight=1)
        right.rowconfigure(4, weight=1)

        # Status bar
        self.status = tk.StringVar(value="Ready.")
        status_bar = tk.Label(self, textvariable=self.status, anchor="w", bg=PALETTE["dark"], fg="white", padx=12)
        status_bar.pack(side="bottom", fill="x")

    def _gen_key(self, bits: int):
        key = generate_key(bits)
        # Put a base64 version into the entry for convenience:
        b64 = __import__("base64").b64encode(key).decode("utf-8")
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, b64)
        self.key_encoding.set("base64")
        self.status.set(f"Generated {bits}-bit AES key (Base64).")

    def _copy(self, widget: ScrolledText):
        try:
            text = widget.get("1.0", "end-1c")
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status.set("Copied to clipboard.")
        except Exception as e:
            self.status.set(f"Copy failed: {e}")

    def _parse_key_from_ui(self) -> bytes:
        raw = self.key_entry.get().strip()
        if not raw:
            raise ValueError("Key is empty. Provide a 16/24/32-byte key.")
        return parse_key(raw, self.key_encoding.get())

    def do_encrypt(self):
        try:
            key = self._parse_key_from_ui()
            pt = self.plaintext.get("1.0", "end-1c")
            if not pt:
                raise ValueError("Plaintext is empty.")
            ct_b64 = encrypt(pt, key)
            self.ciphertext.delete("1.0", "end")
            self.ciphertext.insert("1.0", ct_b64)
            self.status.set("Encryption successful. Ciphertext includes IV (Base64).")
        except Exception as e:
            self.status.set(f"Encryption error: {e}")
            messagebox.showerror("Encryption Error", str(e))

    def do_decrypt(self):
        try:
            key = self._parse_key_from_ui()
            ct_b64 = self.ciphertext.get("1.0", "end-1c").strip()
            if not ct_b64:
                raise ValueError("Ciphertext is empty.")
            pt = decrypt(ct_b64, key)
            self.decrypted.delete("1.0", "end")
            self.decrypted.insert("1.0", pt)
            self.status.set("Decryption successful. Plaintext recovered.")
        except Exception as e:
            self.status.set(f"Decryption error: {e}")
            messagebox.showerror("Decryption Error", str(e))

    def do_clear(self):
        """Clear all text boxes and key entry."""
        self.plaintext.delete("1.0", "end")
        self.ciphertext.delete("1.0", "end")
        self.decrypted.delete("1.0", "end")
        self.key_entry.delete(0, "end")
        self.status.set("Cleared all fields.")


if __name__ == "__main__":
    app = AESApp()
    app.mainloop()
