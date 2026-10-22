"""Tk interface for Folder Packer. See README.md for setup and format details."""

import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from archive_core import pack_folder, restore_folder


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
        self._busy = False
        self._events = queue.Queue()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_id = self.after(50, self._drain_events)

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
        self.z_confirm = tk.StringVar()

        self._row(frame, 0, "Source Folder:", self.z_folder, "Browse…", self._browse_pack_folder)
        self._row(frame, 1, "Output Folder:", self.z_outdir, "Browse…", self._browse_pack_out)
        self._row(frame, 2, "Password:", self.z_pw, None, None, show="•")

        self._row(frame, 3, "Confirm Password:", self.z_confirm, None, None, show="•")

        info = ttk.Label(frame,
                         text="Will create: <name>.part001.zip, .part002.zip … (≤20,000,000 bytes each, AES-256-GCM)",
                         font=("Segoe UI", 8), foreground="#a6adc8")
        info.grid(row=4, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 8))

        self.z_start = ttk.Button(frame, text="🚀  Start Tar & Encrypt", style="Accent.TButton",
                                  command=self._start_pack)
        self.z_start.grid(row=5, column=0, columnspan=3, pady=(4, 8), ipadx=10)

        self.z_pb, self.z_lbl = self._progress_bar(frame, 6)

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
        if self._busy:
            return
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

        if pw != self.z_confirm.get():
            messagebox.showerror("Error", "Passwords do not match.")
            return
        self._set_busy(True)
        self.z_pb["value"] = 0
        self.z_lbl.config(text="Starting…")
        threading.Thread(target=self._pack_worker,
                         args=(folder, outdir, pw), daemon=True).start()

    def _pack_worker(self, folder, outdir, pw):
        try:
            parts = pack_folder(folder, outdir, pw,
                                lambda v: self._set_z(v, "Packing and encrypting…"))
            self._set_z(100, f"✅  Done! {len(parts)} chunk(s) saved to output folder.")
        except Exception as exc:
            self._events.put(("error", str(exc)))
            self._set_z(0, "❌  Failed.")
        finally:
            self._events.put(("finished",))

    def _set_z(self, val, msg):
        self._events.put(("progress", "z", val, msg))

    # ─── UNPACK TAB ──────────────────────────────────
    def _build_unpack_tab(self, nb):
        frame = ttk.Frame(nb, padding=16)
        nb.add(frame, text="  🔓  Decrypt & Untar  ")

        self.u_legacy = tk.BooleanVar(value=False)
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

        ttk.Checkbutton(frame, text="Recover old FPE1 archives (completeness cannot be verified)",
                        variable=self.u_legacy).grid(row=3, column=0, columnspan=3, pady=4)
        self.u_start = ttk.Button(frame, text="🔓  Decrypt & Restore", style="Accent.TButton",
                                  command=self._start_unpack)
        self.u_start.grid(row=4, column=0, columnspan=3, pady=(8, 8), ipadx=10)

        self.u_pb, self.u_lbl = self._progress_bar(frame, 5)

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
        if self._busy:
            return
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

        legacy = self.u_legacy.get()
        if legacy and not messagebox.askyesno(
                "Legacy recovery", "FPE1 cannot detect missing or reordered complete blocks. "
                "Only recover trusted archives and verify the restored files. Continue?"):
            return
        self._set_busy(True)
        self.u_pb["value"] = 0
        self.u_lbl.config(text="Starting…")
        threading.Thread(target=self._unpack_worker,
                         args=(chunks, outdir, pw, legacy), daemon=True).start()

    def _unpack_worker(self, chunks, outdir, pw, legacy=False):
        try:
            restore_folder(chunks, outdir, pw,
                           lambda v: self._set_u(v, "Restoring archive…"), allow_legacy=legacy)
            self._set_u(100, f"✅  Done! Restored to: {outdir}")
        except Exception as exc:
            self._events.put(("error", str(exc)))
            self._set_u(0, "❌  Failed.")
        finally:
            self._events.put(("finished",))

    def _set_u(self, val, msg):
        self._events.put(("progress", "u", val, msg))

    def _set_busy(self, busy):
        self._busy = busy
        for button in (self.z_start, self.u_start):
            button.state(["disabled"] if busy else ["!disabled"])

    def _drain_events(self):
        # All Tk calls stay on the main thread, including error dialogs.
        for _ in range(100):
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            if event[0] == "progress":
                _, tab, value, message = event
                getattr(self, tab + "_pb")["value"] = value
                getattr(self, tab + "_lbl").config(text=message)
            elif event[0] == "error":
                messagebox.showerror("Error", event[1])
            elif event[0] == "finished":
                self._set_busy(False)
        self._poll_id = self.after(50, self._drain_events)

    def destroy(self):
        if getattr(self, "_poll_id", None):
            self.after_cancel(self._poll_id)
            self._poll_id = None
        super().destroy()

    def _on_close(self):
        if self._busy:
            messagebox.showinfo("Operation in progress", "Wait for the current job to finish before closing.")
        else:
            self.destroy()


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
