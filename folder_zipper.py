"""
Folder Packer, Splitter & Encrypter
-----------------------------------
Function 1: Tar a folder (preserves symlinks) → encrypt with AES-256-GCM → split into 20MB chunks → wrap each in a plain zip
Function 2: Unwrap zips → reassemble → decrypt → untar to restore original folder with symlinks

Uses `cryptography` (cffi-backed) instead of pycryptodome to avoid AppLocker blocks
on user-roaming .pyd files in locked-down environments.
"""

import os
import sys
import math
import struct
import shutil
import tarfile
import zipfile
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CHUNK_SIZE = 20 * 1024 * 1024  # 20 MB
MAGIC = b"FPE1"                # file format magic
PBKDF2_ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256


# ─────────────────────────────────────────────
#  CRYPTO HELPERS
# ─────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(in_path: str, out_path: str, password: str, progress_cb=None):
    """
    Encrypt in_path → out_path using AES-256-GCM.
    Format: MAGIC(4) | salt(16) | for each block: nonce(12) | len(4) | ciphertext+tag
    Blocks are 1 MB so we can stream large files without loading into memory.
    """
    BLOCK = 1024 * 1024
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    total = os.path.getsize(in_path)
    written = 0

    with open(in_path, "rb") as src, open(out_path, "wb") as dst:
        dst.write(MAGIC)
        dst.write(salt)
        while True:
            block = src.read(BLOCK)
            if not block:
                break
            nonce = os.urandom(NONCE_LEN)
            ct = aesgcm.encrypt(nonce, block, None)
            dst.write(nonce)
            dst.write(struct.pack(">I", len(ct)))
            dst.write(ct)
            written += len(block)
            if progress_cb and total:
                progress_cb(written, total)


def decrypt_file(in_path: str, out_path: str, password: str, progress_cb=None):
    """Decrypt a file produced by encrypt_file()."""
    total = os.path.getsize(in_path)
    read = 0

    with open(in_path, "rb") as src, open(out_path, "wb") as dst:
        magic = src.read(4)
        if magic != MAGIC:
            raise ValueError("Not a valid encrypted file (bad magic header).")
        salt = src.read(SALT_LEN)
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        read += 4 + SALT_LEN

        while True:
            nonce = src.read(NONCE_LEN)
            if not nonce:
                break
            if len(nonce) < NONCE_LEN:
                raise ValueError("Truncated file.")
            length_bytes = src.read(4)
            if len(length_bytes) < 4:
                raise ValueError("Truncated file.")
            length = struct.unpack(">I", length_bytes)[0]
            ct = src.read(length)
            if len(ct) < length:
                raise ValueError("Truncated file.")
            try:
                pt = aesgcm.decrypt(nonce, ct, None)
            except Exception:
                raise ValueError("Decryption failed — wrong password or corrupted data.")
            dst.write(pt)
            read += NONCE_LEN + 4 + length
            if progress_cb and total:
                progress_cb(read, total)


# ─────────────────────────────────────────────
#  CORE LOGIC
# ─────────────────────────────────────────────

def tar_folder(folder_path: str, tar_path: str, progress_cb=None):
    """Tar and gzip an entire folder preserving symlinks."""
    folder_path = os.path.abspath(folder_path)
    arcname_base = os.path.basename(folder_path)

    items = []
    for root, dirs, files in os.walk(folder_path):
        for d in dirs:
            items.append(os.path.join(root, d))
        for f in files:
            items.append(os.path.join(root, f))

    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(folder_path, arcname=arcname_base, recursive=False)
        for i, filepath in enumerate(items):
            arcname = os.path.join(arcname_base, os.path.relpath(filepath, folder_path))
            tar.add(filepath, arcname=arcname, recursive=False)
            if progress_cb and i % 50 == 0:
                progress_cb(int((i + 1) / max(len(items), 1) * 30))  # 0–30 %
        if progress_cb:
            progress_cb(30)


def split_file(file_path: str, output_dir: str, chunk_size: int = CHUNK_SIZE, progress_cb=None):
    """Split file_path into chunk_size parts wrapped in plain zips."""
    total = os.path.getsize(file_path)
    num_parts = math.ceil(total / chunk_size)
    base_name = os.path.basename(file_path).replace(".enc", "")
    parts = []

    with open(file_path, "rb") as src:
        for i in range(num_parts):
            part_name = f"{base_name}.part{i+1:03d}"
            zip_path = os.path.join(output_dir, f"{part_name}.zip")
            data = src.read(chunk_size)
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
                zf.writestr(part_name, data)
            parts.append(zip_path)
            if progress_cb:
                progress_cb(60 + int((i + 1) / num_parts * 40))  # 60–100 %

    return parts


def combine_zips(zip_paths: list, combined_path: str, progress_cb=None):
    """Unwrap each plain zip and concatenate into one encrypted file."""
    sorted_paths = sorted(zip_paths, key=lambda p: os.path.basename(p))
    num = len(sorted_paths)

    with open(combined_path, "wb") as out:
        for i, zp in enumerate(sorted_paths):
            with zipfile.ZipFile(zp, "r") as zf:
                inner = zf.namelist()[0]
                out.write(zf.read(inner))
            if progress_cb:
                progress_cb(int((i + 1) / num * 30))  # 0–30 %


def untar_archive(tar_path: str, extract_dir: str, progress_cb=None):
    """Extract a tar.gz archive preserving symlinks."""
    with tarfile.open(tar_path, "r:gz") as tar:
        members = tar.getmembers()
        for i, member in enumerate(members):
            tar.extract(member, path=extract_dir)
            if progress_cb and i % 50 == 0:
                progress_cb(70 + int((i + 1) / max(len(members), 1) * 30))  # 70–100 %
        if progress_cb:
            progress_cb(100)


# ─────────────────────────────────────────────
#  GUI
# ─────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Folder Packer & Encrypter (AES-256-GCM, Symlink Safe)")
        self.resizable(False, False)
        self.configure(bg="#1e1e2e")

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook", background="#1e1e2e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#313244", foreground="#cdd6f4",
                        padding=[14, 6], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", "#89b4fa")],
                  foreground=[("selected", "#1e1e2e")])
        style.configure("TFrame", background="#1e1e2e")
        style.configure("TLabel", background="#1e1e2e", foreground="#cdd6f4",
                        font=("Segoe UI", 10))
        style.configure("TEntry", fieldbackground="#313244", foreground="#cdd6f4",
                        insertcolor="#cdd6f4", borderwidth=1)
        style.configure("Accent.TButton", background="#89b4fa", foreground="#1e1e2e",
                        font=("Segoe UI", 10, "bold"), padding=6)
        style.map("Accent.TButton",
                  background=[("active", "#74c7ec")])
        style.configure("TProgressbar", troughcolor="#313244", background="#a6e3a1",
                        thickness=14)
        style.configure("Red.TButton", background="#f38ba8", foreground="#1e1e2e",
                        font=("Segoe UI", 10, "bold"), padding=6)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=14, pady=14)

        self._build_pack_tab(nb)
        self._build_unpack_tab(nb)

    def _row(self, parent, row, label, var, btn_text, btn_cmd, show=""):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=8, pady=6)
        entry = ttk.Entry(parent, textvariable=var, width=42, show=show)
        entry.grid(row=row, column=1, padx=6, pady=6)
        if btn_text:
            ttk.Button(parent, text=btn_text, style="Accent.TButton",
                       command=btn_cmd).grid(row=row, column=2, padx=4)

    def _progress_bar(self, parent, row):
        pb = ttk.Progressbar(parent, orient="horizontal", length=340, mode="determinate")
        pb.grid(row=row, column=0, columnspan=3, padx=8, pady=(8, 2), sticky="ew")
        lbl = ttk.Label(parent, text="")
        lbl.grid(row=row + 1, column=0, columnspan=3)
        return pb, lbl

    # ─── PACK TAB ────────────────────────────────────
    def _build_pack_tab(self, nb):
        frame = ttk.Frame(nb, padding=16)
        nb.add(frame, text="  📦  Tar & Encrypt  ")

        self.z_folder = tk.StringVar()
        self.z_outdir = tk.StringVar()
        self.z_pw = tk.StringVar()

        self._row(frame, 0, "Source Folder:", self.z_folder, "Browse…", self._browse_pack_folder)
        self._row(frame, 1, "Output Folder:", self.z_outdir, "Browse…", self._browse_pack_out)
        self._row(frame, 2, "Password:", self.z_pw, None, None, show="•")

        info = ttk.Label(frame,
                         text="Will create: <name>.part001.zip, .part002.zip … (≤20 MB each, AES-256-GCM)",
                         font=("Segoe UI", 8), foreground="#a6adc8")
        info.grid(row=3, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 8))

        ttk.Button(frame, text="🚀  Start Tar & Encrypt", style="Accent.TButton",
                   command=self._start_pack).grid(row=4, column=0, columnspan=3,
                                                  pady=(4, 8), ipadx=10)

        self.z_pb, self.z_lbl = self._progress_bar(frame, 5)

    def _browse_pack_folder(self):
        p = filedialog.askdirectory(title="Select source folder")
        if p:
            self.z_folder.set(p)
            if not self.z_outdir.get():
                self.z_outdir.set(os.path.dirname(p))

    def _browse_pack_out(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.z_outdir.set(p)

    def _start_pack(self):
        folder = self.z_folder.get().strip()
        outdir = self.z_outdir.get().strip()
        pw = self.z_pw.get()

        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid source folder.")
            return
        if not outdir:
            messagebox.showerror("Error", "Please select an output folder.")
            return
        if not pw:
            messagebox.showerror("Error", "Please enter a password.")
            return

        self.z_pb["value"] = 0
        self.z_lbl.config(text="Starting…")
        threading.Thread(target=self._pack_worker,
                         args=(folder, outdir, pw), daemon=True).start()

    def _pack_worker(self, folder, outdir, pw):
        try:
            name = os.path.basename(folder.rstrip("/\\"))
            tmp_tar = os.path.join(outdir, f"{name}_tmp.tar.gz")
            tmp_enc = os.path.join(outdir, f"{name}.enc")

            self._set_z(2, "Archiving folder (preserving symlinks)…")
            tar_folder(folder, tmp_tar, lambda v: self._set_z(v, "Archiving folder…"))

            self._set_z(32, "Encrypting (AES-256-GCM)…")
            tar_size = os.path.getsize(tmp_tar)
            def enc_progress(done, total):
                pct = 32 + int(done / total * 28)  # 32–60 %
                self._set_z(pct, "Encrypting…")
            encrypt_file(tmp_tar, tmp_enc, pw, enc_progress)
            os.remove(tmp_tar)

            self._set_z(62, "Splitting into chunks…")
            parts = split_file(tmp_enc, outdir, progress_cb=lambda v: self._set_z(v, "Splitting…"))
            os.remove(tmp_enc)

            self._set_z(100, f"✅  Done! {len(parts)} chunk(s) saved to output folder.")
        except Exception as e:
            err = str(e)
            self.after(0, lambda: messagebox.showerror("Error", err))
            self._set_z(0, "❌  Failed.")

    def _set_z(self, val, msg):
        self.after(0, lambda: self.z_pb.__setitem__("value", val))
        self.after(0, lambda: self.z_lbl.config(text=msg))

    # ─── UNPACK TAB ──────────────────────────────────
    def _build_unpack_tab(self, nb):
        frame = ttk.Frame(nb, padding=16)
        nb.add(frame, text="  🔓  Decrypt & Untar  ")

        self.u_chunks = tk.StringVar()
        self.u_outdir = tk.StringVar()
        self.u_pw = tk.StringVar()

        ttk.Label(frame, text="Encrypted Chunks:").grid(row=0, column=0, sticky="nw",
                                                          padx=8, pady=6)

        lb_frame = tk.Frame(frame, bg="#313244", bd=1, relief="sunken")
        lb_frame.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        self.u_listbox = tk.Listbox(lb_frame, bg="#313244", fg="#cdd6f4",
                                    selectbackground="#89b4fa", selectforeground="#1e1e2e",
                                    height=5, width=40, font=("Consolas", 9),
                                    selectmode=tk.EXTENDED, bd=0, highlightthickness=0)
        self.u_listbox.pack(side="left", fill="both", expand=True)

        sb = tk.Scrollbar(lb_frame, orient="vertical", command=self.u_listbox.yview)
        sb.pack(side="right", fill="y")
        self.u_listbox.config(yscrollcommand=sb.set)

        btn_col = ttk.Frame(frame)
        btn_col.grid(row=0, column=2, padx=4, sticky="n")
        ttk.Button(btn_col, text="Add…", style="Accent.TButton",
                   command=self._add_chunks).pack(pady=2)
        ttk.Button(btn_col, text="Remove", style="Red.TButton",
                   command=self._remove_chunk).pack(pady=2)
        ttk.Button(btn_col, text="Clear", style="Red.TButton",
                   command=self._clear_chunks).pack(pady=2)

        self._row(frame, 1, "Output Folder:", self.u_outdir, "Browse…", self._browse_unpack_out)
        self._row(frame, 2, "Password:", self.u_pw, None, None, show="•")

        ttk.Button(frame, text="🔓  Decrypt & Restore", style="Accent.TButton",
                   command=self._start_unpack).grid(row=3, column=0, columnspan=3,
                                                    pady=(8, 8), ipadx=10)

        self.u_pb, self.u_lbl = self._progress_bar(frame, 4)

    def _add_chunks(self):
        files = filedialog.askopenfilenames(
            title="Select encrypted chunk zips",
            filetypes=[("Zip files", "*.zip"), ("All files", "*.*")])
        existing = list(self.u_listbox.get(0, tk.END))
        for f in files:
            if f not in existing:
                self.u_listbox.insert(tk.END, f)

    def _remove_chunk(self):
        sel = list(self.u_listbox.curselection())
        for i in reversed(sel):
            self.u_listbox.delete(i)

    def _clear_chunks(self):
        self.u_listbox.delete(0, tk.END)

    def _browse_unpack_out(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.u_outdir.set(p)

    def _start_unpack(self):
        chunks = list(self.u_listbox.get(0, tk.END))
        outdir = self.u_outdir.get().strip()
        pw = self.u_pw.get()

        if not chunks:
            messagebox.showerror("Error", "Please add at least one encrypted chunk zip.")
            return
        if not outdir:
            messagebox.showerror("Error", "Please select an output folder.")
            return
        if not pw:
            messagebox.showerror("Error", "Please enter the password.")
            return

        self.u_pb["value"] = 0
        self.u_lbl.config(text="Starting…")
        threading.Thread(target=self._unpack_worker,
                         args=(chunks, outdir, pw), daemon=True).start()

    def _unpack_worker(self, chunks, outdir, pw):
        try:
            first = os.path.basename(chunks[0])
            base = first.split(".part")[0]
            combined_enc = os.path.join(outdir, f"{base}_combined.enc")
            combined_tar = os.path.join(outdir, f"{base}_combined.tar.gz")

            self._set_u(2, "Combining chunks…")
            combine_zips(chunks, combined_enc,
                         lambda v: self._set_u(v, "Combining…"))

            self._set_u(32, "Decrypting (AES-256-GCM)…")
            def dec_progress(done, total):
                pct = 32 + int(done / total * 30)  # 32–62 %
                self._set_u(pct, "Decrypting…")
            decrypt_file(combined_enc, combined_tar, pw, dec_progress)
            os.remove(combined_enc)

            self._set_u(64, "Extracting archive (restoring symlinks)…")
            untar_archive(combined_tar, outdir,
                          lambda v: self._set_u(v, "Extracting…"))
            os.remove(combined_tar)

            self._set_u(100, f"✅  Done! Restored to: {outdir}")
        except Exception as e:
            err = str(e)
            self.after(0, lambda: messagebox.showerror("Error", err))
            self._set_u(0, "❌  Failed.")

    def _set_u(self, val, msg):
        self.after(0, lambda: self.u_pb.__setitem__("value", val))
        self.after(0, lambda: self.u_lbl.config(text=msg))


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()