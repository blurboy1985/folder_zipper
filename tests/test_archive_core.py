import io
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import archive_core as core


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "hello.txt").write_text("Hello Singapore", encoding="utf-8")
        (self.source / "empty").mkdir()
        self.output = self.root / "output"
        self.output.mkdir()

    def encrypt(self, data):
        plain, enc = self.root / "plain", self.root / "data.enc"
        plain.write_bytes(data)
        core.encrypt_file(plain, enc, "password")
        return enc

    def assert_bad_encryption(self, data, password="password"):
        enc, result = self.root / "bad.enc", self.root / "result"
        enc.write_bytes(data)
        with self.assertRaises(ValueError):
            core.decrypt_file(enc, result, password)
        self.assertFalse(result.exists(), "Failed decryption left plaintext behind")

    def test_pack_restore_roundtrip_and_no_overwrite(self):
        parts = core.pack_folder(self.source, self.output, "password")
        restore = self.root / "restore"
        restore.mkdir()
        core.restore_folder(parts[::-1], restore, "password")
        self.assertEqual((restore / "source/hello.txt").read_text(), "Hello Singapore")
        self.assertTrue((restore / "source/empty").is_dir())
        with self.assertRaises(FileExistsError):
            core.restore_folder(parts, restore, "password")
        self.assertEqual(sorted(p.name for p in restore.iterdir()), ["source"])
        self.assertFalse(any(p.name.startswith(".folder-") for p in self.output.iterdir()))

    def test_wrong_password_cleans_workspace(self):
        parts = core.pack_folder(self.source, self.output, "password")
        restore = self.root / "restore"
        restore.mkdir()
        with self.assertRaises(ValueError):
            core.restore_folder(parts, restore, "wrong")
        self.assertEqual(list(restore.iterdir()), [])

    def test_encrypt_empty_and_block_boundaries(self):
        for size in (0, 1, core.BLOCK_SIZE, core.BLOCK_SIZE + 1):
            with self.subTest(size=size):
                plain = self.root / f"plain{size}"
                enc = self.root / f"enc{size}"
                out = self.root / f"out{size}"
                data = os.urandom(size)
                plain.write_bytes(data)
                core.encrypt_file(plain, enc, "password")
                core.decrypt_file(enc, out, "password")
                self.assertEqual(out.read_bytes(), data)

    def test_block_reordering_removal_duplication_and_splicing_rejected(self):
        enc = self.encrypt(b"A" * core.BLOCK_SIZE + b"B" * core.BLOCK_SIZE)
        data = enc.read_bytes()
        start = core.HEADER_SIZE
        end = start + 4 + core.BLOCK_SIZE + 16
        second_end = end + 4 + core.BLOCK_SIZE + 16
        a, b, final = data[start:end], data[end:second_end], data[second_end:]
        other = self.root / "other.enc"
        core.encrypt_file(self.root / "plain", other, "password")
        other_block = other.read_bytes()[start:end]
        for altered in (data[:end], data[:start] + b + a + final,
                        data[:start] + a + a + final,
                        data[:start] + a + other_block + final,
                        data[:-1], data + b"extra", data[:start], data[:start] + final):
            self.assert_bad_encryption(altered)

    def test_header_length_and_wrong_password_rejected(self):
        data = self.encrypt(b"hello").read_bytes()
        self.assert_bad_encryption(data, "wrong")
        for pos in (4, 20, 35):
            altered = bytearray(data)
            altered[pos] ^= 1
            self.assert_bad_encryption(altered)
        self.assert_bad_encryption(data[:core.HEADER_SIZE] + b"\xff" * 4 + data[core.HEADER_SIZE + 4:])
        self.assert_bad_encryption(b"FPE2short")

    def test_existing_output_preserved(self):
        enc = self.encrypt(b"hello")
        target = self.root / "existing"
        target.write_bytes(b"important")
        with self.assertRaises(FileExistsError):
            core.decrypt_file(enc, target, "password")
        self.assertEqual(target.read_bytes(), b"important")
        with self.assertRaises(FileExistsError):
            core.encrypt_file(target, enc, "password")

    def test_numeric_order_above_1000_and_zip_size_cap(self):
        data = os.urandom(400_000)
        source = self.root / "many.enc"
        source.write_bytes(data)
        parts = core.split_file(source, self.output, chunk_size=512)
        self.assertGreater(len(parts), 1000)
        self.assertTrue(all(Path(p).stat().st_size <= 512 for p in parts))
        joined = self.root / "joined"
        core.combine_zips(parts[::-1], joined)
        self.assertEqual(joined.read_bytes(), data)

    def test_default_zip_limit_and_unicode_filename(self):
        source = self.root / "资料.enc"
        source.write_bytes(b"x" * core.CHUNK_SIZE)
        parts = core.split_file(source, self.output)
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(Path(p).stat().st_size <= 20_000_000 for p in parts))

    def test_missing_duplicate_and_mixed_parts(self):
        source = self.root / "data.enc"
        source.write_bytes(os.urandom(3000))
        parts = core.split_file(source, self.output, chunk_size=512)
        other_dir = self.root / "other"
        other_dir.mkdir()
        other = core.split_file(source, other_dir, chunk_size=512)
        for selection in (parts[:-1], parts[1:], parts + parts[:1], parts[:1] + other[1:]):
            with self.subTest(selection=len(selection)), self.assertRaises(ValueError):
                core.combine_zips(selection, self.root / "bad-combined")
            self.assertFalse((self.root / "bad-combined").exists())

    def test_split_failure_rolls_back_and_refuses_stale_parts(self):
        enc = self.encrypt(b"hello")
        def fail(_):
            raise OSError("simulated failure")
        with self.assertRaises(OSError):
            core.split_file(enc, self.output, progress_cb=fail)
        self.assertEqual(list(self.output.iterdir()), [])
        sentinel = self.output / "data.part999.zip"
        sentinel.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            core.split_file(enc, self.output)
        self.assertEqual(sentinel.read_bytes(), b"existing")

    def test_pack_failure_cleans_plaintext(self):
        with patch.object(core, "encrypt_file", side_effect=OSError("simulated failure")):
            with self.assertRaises(OSError):
                core.pack_folder(self.source, self.output, "password")
        self.assertEqual(list(self.output.iterdir()), [])

    def test_reject_output_inside_source(self):
        with self.assertRaises(ValueError):
            core.pack_folder(self.source, self.source, "password")
        with self.assertRaises(ValueError):
            core.tar_folder(self.source, self.source / "self.tar.gz")

    def make_tar(self, entries):
        path = self.root / "test.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            root = tarfile.TarInfo("source")
            root.type = tarfile.DIRTYPE
            tar.addfile(root)
            for name, kind, content in entries:
                info = tarfile.TarInfo(name)
                if kind == "file":
                    payload = content.encode()
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
                else:
                    info.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.FIFOTYPE
                    info.linkname = content
                    tar.addfile(info)
        return path

    def test_unsafe_archives_do_not_publish_any_files(self):
        cases = [
            [("../escape", "file", "bad")],
            [("/absolute", "file", "bad")],
            [("source/C:ads", "file", "bad")],
            [("source/CON", "file", "bad")],
            [("source/a.", "file", "bad")],
            [("source/a", "file", "first"), ("source/A", "file", "second")],
            [("source/a/one", "file", "first"), ("source/A/two", "file", "second")],
            [("source/link", "symlink", "."), ("source/link/file", "file", "bad")],
            [("source/link", "symlink", "../../escape")],
            [("source/link", "symlink", "/escape")],
            [("source/pipe", "pipe", "")],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                with self.assertRaises((ValueError, tarfile.FilterError)):
                    core.untar_archive(self.make_tar(entries), self.output)
                self.assertEqual(list(self.output.iterdir()), [])

    def test_safe_symlink_roundtrip_when_supported(self):
        link = self.source / "link"
        try:
            link.symlink_to("hello.txt")
        except OSError:
            self.skipTest("This account cannot create symlinks")
        parts = core.pack_folder(self.source, self.output, "password")
        restore = self.root / "restore"
        restore.mkdir()
        core.restore_folder(parts, restore, "password")
        self.assertTrue((restore / "source/link").is_symlink())
        self.assertEqual((restore / "source/link").read_text(), "Hello Singapore")

    def test_legacy_requires_opt_in(self):
        salt, nonce = os.urandom(16), os.urandom(12)
        aes = core.AESGCM(core.derive_key("password", salt))
        ct = aes.encrypt(nonce, b"legacy data", None)
        data = b"FPE1" + salt + nonce + struct.pack(">I", len(ct)) + ct
        self.assert_bad_encryption(data)
        enc = self.root / "legacy.enc"
        enc.write_bytes(data)
        core.decrypt_file(enc, self.root / "legacy-out", "password", allow_legacy=True)
        self.assertEqual((self.root / "legacy-out").read_bytes(), b"legacy data")
        enc.write_bytes(data[:20])
        with self.assertRaises(ValueError):
            core.decrypt_file(enc, self.root / "empty-out", "wrong", allow_legacy=True)
        self.assertFalse((self.root / "empty-out").exists())

    def test_full_legacy_restore(self):
        archive = self.make_tar([("source/hello.txt", "file", "old data")])
        salt, nonce = os.urandom(16), os.urandom(12)
        aes = core.AESGCM(core.derive_key("password", salt))
        ct = aes.encrypt(nonce, archive.read_bytes(), None)
        data = b"FPE1" + salt + nonce + struct.pack(">I", len(ct)) + ct
        part = self.output / "old.part001.zip"
        with zipfile.ZipFile(part, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("old.part001", data)
        restore = self.root / "restore"
        restore.mkdir()
        with self.assertRaises(ValueError):
            core.restore_folder([part], restore, "password")
        core.restore_folder([part], restore, "password", allow_legacy=True)
        self.assertEqual((restore / "source/hello.txt").read_text(), "old data")

    @unittest.skipIf(os.name == "nt", "POSIX directory mode check")
    def test_read_only_directory_permissions_applied_after_children(self):
        archive = self.root / "readonly.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            root = tarfile.TarInfo("source")
            root.type, root.mode = tarfile.DIRTYPE, 0o555
            tar.addfile(root)
            child = tarfile.TarInfo("source/file")
            child.size = 1
            tar.addfile(child, io.BytesIO(b"x"))
        try:
            core.untar_archive(archive, self.output)
            self.assertEqual((self.output / "source/file").read_bytes(), b"x")
            self.assertEqual((self.output / "source").stat().st_mode & 0o777, 0o555)
        finally:
            if (self.output / "source").exists():
                (self.output / "source").chmod(0o755)

    def test_zip_validation_and_streaming(self):
        path = self.output / "test.part001.zip"
        meta = core._comment("a" * 32, 1, 1)
        for mode, entries in ((zipfile.ZIP_DEFLATED, [("test.part001", b"x" * 10000)]),
                              (zipfile.ZIP_STORED, [("wrong", b"x")]),
                              (zipfile.ZIP_STORED, [("test.part001", b"x"), ("extra", b"x")])):
            with zipfile.ZipFile(path, "w", compression=mode) as zf:
                zf.comment = meta
                for name, data in entries:
                    zf.writestr(name, data)
            with self.assertRaises(ValueError):
                core.combine_zips([path], self.root / "bad")
        path.unlink()
        enc = self.encrypt(b"hello")
        parts = core.split_file(enc, self.output)
        with patch.object(zipfile.ZipFile, "read", side_effect=AssertionError("Must stream ZIP data")):
            core.combine_zips(parts, self.root / "combined")


if __name__ == "__main__":
    unittest.main()
