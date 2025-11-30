import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from PIL import Image, ImageDraw, ImageFilter, ImageTk, ImageOps

# ---------- Crypto constants ----------
MAGIC = b'ENCRv2'  # 6 bytes signature
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HASH_SIZE = 32  # SHA-256
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE + HASH_SIZE

PBKDF2_ITER = 200_000
KEY_LEN = 32  # 256-bit AES
CHUNK_SIZE = 64 * 1024  # 64KB

# ---------- Theme constants ----------
BG_FILENAME = "royal_bg_generated.png"
WINDOW_W = 820
WINDOW_H = 560

# ---------- Utility crypto functions ----------
def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode('utf-8'), salt, dkLen=KEY_LEN, count=PBKDF2_ITER, hmac_hash_module=SHA256)

def generate_random_key() -> bytes:
    return get_random_bytes(KEY_LEN)

# ---------- Generate a unique royal gold & black background ----------
def generate_royal_background(path=BG_FILENAME, w=WINDOW_W, h=WINDOW_H):
    """Programmatically generate a royal black->gold blurred background image and save it."""
    base = Image.new("RGB", (w, h), (10, 10, 12))
    draw = ImageDraw.Draw(base)
    for i in range(h):
        t = i / (h - 1)
        if t < 0.6:
            r = int(10 + (50 - 10) * (t / 0.6))
            g = int(10 + (30 - 10) * (t / 0.6))
            b = int(12 + (20 - 12) * (t / 0.6))
        else:
            tt = (t - 0.6) / 0.4
            r = int(50 + (220 - 50) * tt)
            g = int(30 + (180 - 30) * tt)
            b = int(20 + (40 - 20) * tt)
        draw.line([(0, i), (w, i)], fill=(r, g, b))

    glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    centers = [(int(w*0.15), int(h*0.2)), (int(w*0.78), int(h*0.18)), (int(w*0.5), int(h*0.6))]
    for idx, (cx, cy) in enumerate(centers):
        radius = int(min(w, h) * (0.6 - idx*0.12))
        for r in range(radius, 0, -20):
            alpha = int(22 * (1 - r / radius))
            color = (255, 215, 70, alpha)
            gdraw.ellipse((cx-r, cy-r, cx+r, cy+r), fill=color)

    base = Image.alpha_composite(base.convert("RGBA"), glow)
    base = base.filter(ImageFilter.GaussianBlur(22))

    stripes = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    sdraw = ImageDraw.Draw(stripes)
    stripe_color = (255, 230, 160, 28)
    spacing = 60
    for x in range(-w, w, spacing):
        sdraw.line([(x, 0), (x + w, h)], fill=stripe_color, width=18)
    stripes = stripes.filter(ImageFilter.GaussianBlur(10))
    base = Image.alpha_composite(base, stripes)

    vignette = Image.new("L", (w, h), 0)
    vdraw = ImageDraw.Draw(vignette)
    vdraw.ellipse((-int(w*0.2), -int(h*0.15), int(w*1.2), int(h*1.2)), fill=255)
    vignette = vignette.filter(ImageFilter.GaussianBlur(160))
    black = Image.new("RGBA", (w, h), (0,0,0,180))
    base.paste(black, (0,0), mask=ImageOps.invert(vignette).convert("L"))

    base.convert("RGB").save(path, quality=90)
    return path

# ---------- Encryption / Decryption ----------
def encrypt_stream(input_path: str, out_path: str, derived_key: bytes, header_salt: bytes, progress_callback=None):
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    sha = SHA256.new()
    total = os.path.getsize(input_path)
    processed = 0
    with open(input_path, 'rb') as fin, open(out_path, 'wb') as fout:
        fout.write(MAGIC + header_salt + nonce + (b'\x00' * HASH_SIZE))
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            sha.update(chunk)
            ct = cipher.encrypt(chunk)
            fout.write(ct)
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, total)
        tag = cipher.digest()
        fout.write(tag)
        fout.seek(len(MAGIC) + SALT_SIZE + NONCE_SIZE)
        fout.write(sha.digest())
    return True

def decrypt_stream(input_path: str, out_path: str, password=None, raw_key=None, progress_callback=None):
    total = os.path.getsize(input_path)
    if total < HEADER_SIZE + TAG_SIZE:
        raise ValueError("File too small or invalid.")
    with open(input_path, 'rb') as fin:
        header = fin.read(HEADER_SIZE)
        if header[:len(MAGIC)] != MAGIC:
            raise ValueError("Unrecognized encrypted file format.")
        header_salt = header[len(MAGIC):len(MAGIC)+SALT_SIZE]
        nonce = header[len(MAGIC)+SALT_SIZE:len(MAGIC)+SALT_SIZE+NONCE_SIZE]
        expected_hash = header[len(MAGIC)+SALT_SIZE+NONCE_SIZE:HEADER_SIZE]

        if password:
            derived_key = derive_key_from_password(password, header_salt)
        elif raw_key:
            derived_key = raw_key
        else:
            raise ValueError("No password or key provided for decryption.")

        ciphertext_size = total - HEADER_SIZE - TAG_SIZE
        if ciphertext_size < 0:
            raise ValueError("Invalid file size.")

        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        processed = 0
        sha = SHA256.new()

        with open(out_path, 'wb') as fout:
            remaining = ciphertext_size
            while remaining > 0:
                to_read = min(CHUNK_SIZE, remaining)
                ct_chunk = fin.read(to_read)
                if not ct_chunk:
                    raise ValueError("Unexpected end of file.")
                pt = cipher.decrypt(ct_chunk)
                fout.write(pt)
                sha.update(pt)
                remaining -= len(ct_chunk)
                processed += len(ct_chunk)
                if progress_callback:
                    progress_callback(processed, ciphertext_size)

            tag = fin.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise ValueError("Missing auth tag.")
            try:
                cipher.verify(tag)
            except ValueError:
                fout.close()
                os.remove(out_path)
                raise ValueError("Authentication failed (wrong key or tampered file).")

        if sha.digest() != expected_hash:
            os.remove(out_path)
            raise ValueError("Plaintext hash mismatch (data corrupted).")

    return True

# ---------- GUI ----------
class RoyalApp:
    def __init__(self, root):
        self.root = root
        self.root.title(" Secure File Encryption & Decrption")
        self.root.geometry(f"{WINDOW_W}x{WINDOW_H}")
        self.root.resizable(False, False)

        if not os.path.exists(BG_FILENAME):
            try:
                generate_royal_background(BG_FILENAME, WINDOW_W, WINDOW_H)
            except Exception:
                pass

        self.bg_img = None
        try:
            bg = Image.open(BG_FILENAME).resize((WINDOW_W, WINDOW_H))
            overlay = Image.new("RGBA", (WINDOW_W, WINDOW_H), (0,0,0,80))
            bg = Image.alpha_composite(bg.convert("RGBA"), overlay)
            self.bg_img = ImageTk.PhotoImage(bg)
            self.canvas = tk.Canvas(root, width=WINDOW_W, height=WINDOW_H, highlightthickness=0)
            self.canvas.pack(fill="both", expand=True)
            self.canvas.create_image(0, 0, anchor="nw", image=self.bg_img)
        except Exception:
            self.canvas = tk.Canvas(root, width=WINDOW_W, height=WINDOW_H, bg="#0a0a0a", highlightthickness=0)
            self.canvas.pack(fill="both", expand=True)

        self.selected_file = None
        self.key_bytes = None

        card_w = 760
        card_h = 480
        card_x = (WINDOW_W - card_w) // 2
        card_y = (WINDOW_H - card_h) // 2

        card_img = self._create_card_image(card_w, card_h)
        self.card_photo = ImageTk.PhotoImage(card_img)
        self.canvas.create_image(card_x, card_y, anchor="nw", image=self.card_photo)

        self.frame = tk.Frame(self.canvas, bg="#000000")
        self.frame.place(x=card_x + 18, y=card_y + 18, width=card_w - 36, height=card_h - 36)
        self._build_widgets()

    def _create_card_image(self, w, h):
        card = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        dd = ImageDraw.Draw(card)
        radius = 24
        self._rounded_rect(dd, (0,0,w,h), radius, fill=(8,8,10,200))
        self._rounded_rect(dd, (4,4,w-4,72), radius-8, fill=(255,255,255,20))
        self._rounded_rect(dd, (0,0,w,h), radius, outline=(232,190,95,200), width=2)
        return card.filter(ImageFilter.GaussianBlur(0.6))

    def _rounded_rect(self, draw, box, r, fill=None, outline=None, width=1):
        draw.rounded_rectangle(box, radius=r, fill=fill, outline=outline, width=width)

    def _build_widgets(self):
        title = tk.Label(self.frame, text="Secure File Encryption & Decryption", font=("Segoe UI", 20, "bold"), fg="#FFD76B", bg="#000000")
        title.pack(anchor="nw", pady=(6,2))

        fs = tk.Frame(self.frame, bg="#000000")
        fs.pack(fill="x", padx=6)
        self.file_label = tk.Label(fs, text="No file selected", bg="#000000", fg="#fff", anchor="w")
        self.file_label.pack(side="left", fill="x", expand=True, padx=(8,6))
        select_btn = self._gold_button(fs, "Select File", command=self.select_file)
        select_btn.pack(side="right", padx=6)

        key_frame = tk.Frame(self.frame, bg="#000000")
        key_frame.pack(fill="x", padx=6, pady=8)
        tk.Label(key_frame, text="Password (leave empty to use .key file):", bg="#000000", fg="#f3e6c6", font=("Segoe UI", 9)).pack(anchor="w", pady=(0,4))
        pwrow = tk.Frame(key_frame, bg="#000000")
        pwrow.pack(fill="x")
        self.pw_entry = tk.Entry(pwrow, show="*", width=36, font=("Segoe UI", 10))
        self.pw_entry.pack(side="left", padx=(8,6))
        gen_btn = self._gold_button(pwrow, "Generate Key", command=self.generate_and_save_key, small=True)
        gen_btn.pack(side="left", padx=6)
        load_btn = self._gold_button(pwrow, "Load Key", command=self.load_key_file, small=True)
        load_btn.pack(side="left", padx=6)

        ops = tk.Frame(self.frame, bg="#000000")
        ops.pack(fill="x", padx=6, pady=6)
        enc_btn = self._gold_button(ops, "Encrypt", command=self.encrypt_selected, width=16)
        enc_btn.pack(side="left", padx=12)
        dec_btn = self._gold_button(ops, "Decrypt", command=self.decrypt_selected, width=16)
        dec_btn.pack(side="left", padx=6)

        self.progress = ttk.Progressbar(self.frame, length=640, mode="determinate")
        self.progress.pack(padx=8, pady=(10,4))
        tk.Label(self.frame, text="Status / Log:", bg="#000000", fg="#e9d9b1").pack(anchor="w", padx=8)
        self.log = ScrolledText(self.frame, height=8, bg="#050405", fg="#fff", insertbackground="#fff")
        self.log.pack(fill="both", padx=8, pady=6, expand=True)
        footer = tk.Label(self.frame, text="AES-256 GCM  •  PBKDF2 200k rounds  •  SHA-256 integrity", bg="#000000", fg="#d6c79b")
        footer.pack(anchor="e", padx=8, pady=(0,6))

        style = ttk.Style()
        style.theme_use('default')
        style.configure("TProgressbar", troughcolor='#202020', background='#D4A017', thickness=12)

    def _gold_button(self, parent, text, command=None, width=None, small=False):
        btn = tk.Button(parent, text=text, command=command, bd=0, relief="flat",
                        fg="#0A0A0A", bg="#E9C46A", activebackground="#FFD76B",
                        font=("Segoe UI", 10, "bold"), padx=12, pady=6)
        def on_enter(e): btn.config(bg="#FFD76B")
        def on_leave(e): btn.config(bg="#E9C46A")
        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        if width: btn.config(width=width)
        if small: btn.config(font=("Segoe UI", 9, "bold"), padx=8, pady=4)
        return btn

    def log_message(self, text):
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.selected_file = path
            self.file_label.config(text=os.path.basename(path))
            self.log_message(f"Selected: {path}")

    def generate_and_save_key(self):
        key = generate_random_key()
        out = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key file", "*.key")], title="Save key file")
        if out:
            try:
                with open(out, "wb") as f:
                    f.write(key)
                self.log_message(f"Random key generated and saved to {out}")
                messagebox.showinfo("Key Saved", f"Random key saved to:\n{out}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save key: {e}")

    def load_key_file(self):
        path = filedialog.askopenfilename(filetypes=[("Key files", "*.key"), ("All files", "*.*")])
        if path:
            try:
                with open(path, "rb") as f:
                    kb = f.read()
                if len(kb) != KEY_LEN:
                    messagebox.showwarning("Key length", f"Loaded key length is {len(kb)} bytes; expected {KEY_LEN}. It may not work.")
                self.key_bytes = kb
                self.log_message(f"Loaded raw key: {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {e}")

    def _progress_enc(self, processed, total):
        self.progress['value'] = int(processed * 100 / total) if total > 0 else 0
        self.root.update_idletasks()

    def _progress_dec(self, processed, total):
        self.progress['value'] = int(processed * 100 / total) if total > 0 else 0
        self.root.update_idletasks()

    def encrypt_selected(self):
        if not self.selected_file:
            messagebox.showwarning("No file", "Please select a file to encrypt.")
            return
        password = self.pw_entry.get().strip()
        if password:
            header_salt = get_random_bytes(SALT_SIZE)
            derived_key = derive_key_from_password(password, header_salt)
        elif self.key_bytes:
            header_salt = get_random_bytes(SALT_SIZE)
            derived_key = self.key_bytes
        else:
            if messagebox.askyesno("No key", "No password entered and no key file loaded.\nGenerate a random key file now?"):
                self.generate_and_save_key()
            return

        out = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted file", "*.enc")], title="Save encrypted file as")
        if not out:
            return
        try:
            self.progress['value'] = 0
            self.log_message(f"Encrypting -> {out}")
            encrypt_stream(self.selected_file, out, derived_key, header_salt, progress_callback=self._progress_enc)
            self.progress['value'] = 100
            self.log_message("Encryption complete ✅")
        except Exception as e:
            messagebox.showerror("Encryption failed", str(e))
            self.log_message(f"Error: {e}")

    def decrypt_selected(self):
        if not self.selected_file:
            messagebox.showwarning("No file", "Please select a file to decrypt.")
            return
        password = self.pw_entry.get().strip()
        raw_key = self.key_bytes
        out = filedialog.asksaveasfilename(defaultextension=".dec", title="Save decrypted file as")
        if not out:
            return
        try:
            self.progress['value'] = 0
            self.log_message(f"Decrypting -> {out}")
            decrypt_stream(self.selected_file, out, password=password if password else None, raw_key=raw_key, progress_callback=self._progress_dec)
            self.progress['value'] = 100
            self.log_message("Decryption complete ✅")
        except Exception as e:
            messagebox.showerror("Decryption failed", str(e))
            self.log_message(f"Error: {e}")

# ---------- Run ----------
if __name__ == "__main__":
    root = tk.Tk()
    app = RoyalApp(root)
    root.mainloop()
