"""Exercise Tk callbacks and real background jobs without interactive dialogs."""
from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from folder_zipper import App


class GuiTests(unittest.TestCase):
    def setUp(self):
        try:
            self.app = App()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")
        self.app.withdraw()
        self.addCleanup(self.app.destroy)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "test.txt").write_text("test")
        self.output = self.root / "output"
        self.output.mkdir()

    def wait_for_job(self):
        deadline = time.monotonic() + 20
        while self.app._busy and time.monotonic() < deadline:
            self.app.update()
            time.sleep(0.01)
        self.assertFalse(self.app._busy, "Worker did not finish")

    def test_confirmation_busy_guard_pack_and_restore(self):
        app = self.app
        app.z_folder.set(str(self.source))
        app.z_outdir.set(str(self.output))
        app.z_pw.set("password")
        app.z_confirm.set("mismatch")
        with patch("folder_zipper.messagebox.showerror") as errors:
            app._start_pack()
            errors.assert_called_once()
            self.assertFalse(app._busy)
        app.z_confirm.set("password")
        with patch("folder_zipper.messagebox.showerror") as errors:
            app._start_pack()
            self.assertTrue(app.z_start.instate(["disabled"]))
            self.assertTrue(app.u_start.instate(["disabled"]))
            app._start_pack()  # A second click cannot start another job.
            with patch("folder_zipper.messagebox.showinfo") as info:
                app._on_close()
                info.assert_called_once()
            self.wait_for_job()
            errors.assert_not_called()
        self.assertEqual(app.z_pb["value"], 100)
        restore = self.root / "restore"
        restore.mkdir()
        for part in self.output.glob("*.zip"):
            app.u_listbox.insert(tk.END, str(part))
        app.u_outdir.set(str(restore))
        app.u_pw.set("password")
        with patch("folder_zipper.messagebox.showerror") as errors:
            app._start_unpack()
            self.wait_for_job()
            errors.assert_not_called()
        self.assertEqual((restore / "source/test.txt").read_text(), "test")
        self.assertEqual(app.u_pb["value"], 100)
        self.assertTrue(app.u_start.instate(["!disabled"]))

    def test_error_event_reenables_buttons(self):
        self.app.z_folder.set(str(self.source))
        self.app.z_outdir.set(str(self.root / "missing"))
        self.app.z_pw.set("password")
        self.app.z_confirm.set("password")
        with patch("folder_zipper.messagebox.showerror") as errors:
            self.app._start_pack()
            self.wait_for_job()
            errors.assert_called_once()
        self.assertTrue(self.app.z_start.instate(["!disabled"]))


if __name__ == "__main__":
    unittest.main()
