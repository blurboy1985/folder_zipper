"""Streaming archive operations, independent of the Tk interface (Python 3.12+)."""

from contextlib import contextmanager
import io
import json
import math
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import struct
import tarfile
import tempfile
import uuid
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CHUNK_SIZE = 20_000_000  # Final ZIP limit: decimal MB, including all ZIP metadata.
BLOCK_SIZE = 1024 * 1024
MAGIC = b"FPE2"
PBKDF2_ITERATIONS = 200_000
SALT_LEN, NONCE_LEN, KEY_LEN = 16, 12, 32
HEADER_SIZE = 36  # magic | salt | nonce prefix (8) | plaintext size (uint64)
MAX_BLOCKS = 2**32 - 1  # Reserve one nonce for the final authenticated record.
PART_RE = re.compile(r"(.+)\.part([0-9]+)\.zip\Z")
DEVICE_RE = re.compile(r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?\Z", re.IGNORECASE)


def derive_key(password, salt):
    if not password or len(salt) != SALT_LEN:
        raise ValueError("A password and a complete 16-byte salt are required.")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                      salt=salt, iterations=PBKDF2_ITERATIONS).derive(password.encode("utf-8"))


@contextmanager
def new_output(path):
    """Never truncate existing files; remove only our own incomplete output."""
    with open(path, "xb") as stream:
        try:
            yield stream
        except BaseException:
            stream.close()
            os.unlink(path)
            raise


def _read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("Truncated encrypted file.")
    return data


def encrypt_file(in_path, out_path, password, progress_cb=None):
    """FPE2 authenticates the header, block positions, size and final record."""
    with open(in_path, "rb") as src, new_output(out_path) as dst:
        total = os.fstat(src.fileno()).st_size
        if math.ceil(total / BLOCK_SIZE) > MAX_BLOCKS:
            raise ValueError("File is too large for this format.")
        salt, prefix = os.urandom(SALT_LEN), os.urandom(8)
        header = MAGIC + salt + prefix + struct.pack(">Q", total)
        aes = AESGCM(derive_key(password, salt))
        dst.write(header)
        done, index = 0, 0
        while done < total:
            block = _read_exact(src, min(BLOCK_SIZE, total - done))
            counter = struct.pack(">I", index)
            ct = aes.encrypt(prefix + counter, block, header + counter + b"D")
            dst.write(struct.pack(">I", len(ct)))
            dst.write(ct)
            done += len(block)
            index += 1
            if progress_cb:
                progress_cb(done, max(total, 1))
        if src.read(1):
            raise ValueError("Source changed while encrypting; retry with a stable source.")
        counter = struct.pack(">I", index)
        dst.write(struct.pack(">I", 16))
        dst.write(aes.encrypt(prefix + counter, b"", header + counter + b"F"))


def _decrypt_legacy(src, dst, password, progress_cb, total):
    aes = AESGCM(derive_key(password, _read_exact(src, SALT_LEN)))
    blocks = 0
    while True:
        nonce = src.read(NONCE_LEN)
        if not nonce:
            break
        if len(nonce) != NONCE_LEN:
            raise ValueError("Truncated encrypted file.")
        length = struct.unpack(">I", _read_exact(src, 4))[0]
        if not 17 <= length <= BLOCK_SIZE + 16:
            raise ValueError("Invalid encrypted block size.")
        dst.write(aes.decrypt(nonce, _read_exact(src, length), None))
        blocks += 1
        if progress_cb:
            progress_cb(src.tell(), total)
    if not blocks:
        raise ValueError("Legacy file has no authenticated data.")


def decrypt_file(in_path, out_path, password, progress_cb=None, *, allow_legacy=False):
    """Reject incomplete/reordered FPE2 streams; legacy recovery requires opt-in."""
    try:
        with open(in_path, "rb") as src, new_output(out_path) as dst:
            total = os.fstat(src.fileno()).st_size
            magic = _read_exact(src, 4)
            if magic == b"FPE1":
                if not allow_legacy:
                    raise ValueError("FPE1 needs explicit legacy recovery; completeness cannot be verified.")
                _decrypt_legacy(src, dst, password, progress_cb, total)
                return
            if magic != MAGIC:
                raise ValueError("Not a supported encrypted file.")
            header = magic + _read_exact(src, HEADER_SIZE - 4)
            salt, prefix = header[4:20], header[20:28]
            remaining = struct.unpack(">Q", header[28:36])[0]
            if math.ceil(remaining / BLOCK_SIZE) > MAX_BLOCKS:
                raise ValueError("Invalid plaintext size.")
            aes = AESGCM(derive_key(password, salt))
            index = 0
            while remaining:
                expected = min(BLOCK_SIZE, remaining)
                length = struct.unpack(">I", _read_exact(src, 4))[0]
                if length != expected + 16:
                    raise ValueError("Invalid encrypted block size.")
                counter = struct.pack(">I", index)
                dst.write(aes.decrypt(prefix + counter, _read_exact(src, length),
                                      header + counter + b"D"))
                remaining -= expected
                index += 1
                if progress_cb:
                    progress_cb(src.tell(), total)
            if struct.unpack(">I", _read_exact(src, 4))[0] != 16:
                raise ValueError("Missing authenticated final record.")
            counter = struct.pack(">I", index)
            aes.decrypt(prefix + counter, _read_exact(src, 16), header + counter + b"F")
            if src.read(1):
                raise ValueError("Unexpected data after final record.")
            if progress_cb:
                progress_cb(total, total)
    except InvalidTag as exc:
        raise ValueError("Decryption failed: wrong password or corrupted data.") from exc


def _safe_name(name):
    """Use portable paths; reject traversal, Windows devices, ADS and aliases."""
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or PureWindowsPath(name).drive or "\\" in name
            or any(c in name for c in ':<>"|?*')
            or any(ord(c) < 32 for c in name)
            or any(part in ("", ".", "..") or part.endswith((" ", "."))
                   or DEVICE_RE.fullmatch(part.split(".")[0].rstrip(" ")) for part in name.split("/"))):
        raise ValueError(f"Unsafe or nonportable archive path: {name!r}")
    return path


def tar_folder(folder_path, tar_path, progress_cb=None):
    source = Path(folder_path).resolve()
    if not source.is_dir() or not source.name:
        raise ValueError("Select a named source folder.")
    target = Path(tar_path).resolve()
    if target.is_relative_to(source):
        raise ValueError("Temporary archive must be outside the source folder.")
    count = 0
    def validate(member):
        nonlocal count
        _safe_name(member.name)
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError(f"Unsupported special file: {member.name}")
        if member.issym() or member.islnk():
            _validate_link(member, source.name)
        count += 1
        if progress_cb and count % 50 == 0:
            progress_cb(15)  # Indeterminate file count; avoid collecting every path.
        return member
    with new_output(tar_path) as output, tarfile.open(fileobj=output, mode="w:gz", dereference=False) as tar:
        tar.add(source, arcname=source.name, filter=validate)
    if progress_cb:
        progress_cb(30)


def _comment(archive_id, index, count):
    return json.dumps({"format": "FPE2", "id": archive_id, "index": index, "count": count},
                      separators=(",", ":")).encode("ascii")


def split_file(file_path, output_dir, chunk_size=CHUNK_SIZE, progress_cb=None):
    """chunk_size caps the complete ZIP size, rather than only its payload."""
    if not isinstance(chunk_size, int) or not 512 <= chunk_size <= CHUNK_SIZE:
        raise ValueError(f"ZIP size limit must be between 512 and {CHUNK_SIZE} bytes.")
    output_dir = Path(output_dir)
    base = Path(file_path).stem
    _safe_name(base)
    # Reserve metadata for the maximum possible part number; no ZIP64 at this size.
    digits = max(3, len(str(max(1, os.path.getsize(file_path)))))
    longest = f"{base}.part{'9' * digits}"
    archive_id = uuid.uuid4().hex
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED, allowZip64=False) as zf:
        zf.writestr(longest, b"")
        zf.comment = _comment(archive_id, 10**digits - 1, 10**digits - 1)
    payload_size = chunk_size - len(buffer.getvalue())
    if payload_size <= 0:
        raise ValueError("ZIP size limit is too small for this filename.")
    total = os.path.getsize(file_path)
    if total == 0:
        raise ValueError("Cannot split an empty file.")
    count = max(1, math.ceil(total / payload_size))
    # Refuse stale parts from an earlier, longer run too.
    if any(p.name.startswith(base + ".part") and p.name.endswith(".zip") for p in output_dir.iterdir()):
        raise FileExistsError("Output already contains parts with this name. Choose an empty output folder.")
    created = []
    try:
        with open(file_path, "rb") as src:
            for i in range(1, count + 1):
                name = f"{base}.part{i:03d}"
                path = output_dir / (name + ".zip")
                with new_output(path) as stream:
                    with zipfile.ZipFile(stream, "w", zipfile.ZIP_STORED, allowZip64=False) as zf:
                        zf.writestr(name, src.read(payload_size))
                        zf.comment = _comment(archive_id, i, count)
                    if stream.tell() > chunk_size:
                        raise ValueError("ZIP exceeded the configured size limit.")
                created.append(str(path))
                if progress_cb:
                    progress_cb(60 + int(i / count * 40))
            if src.read(1) or src.tell() != total:
                raise ValueError("Source changed while splitting.")
        return created
    except BaseException:
        for path in created:
            os.unlink(path)
        raise


def combine_zips(zip_paths, combined_path, progress_cb=None, *, allow_legacy=False):
    parts, base, identity, expected_count = {}, None, None, None
    if not zip_paths:
        raise ValueError("No archive parts selected.")
    for path in zip_paths:
        match = PART_RE.fullmatch(Path(path).name)
        if not match:
            raise ValueError("Part names must end in .partNNN.zip.")
        name, index = match[1], int(match[2])
        if index < 1 or index in parts or (base is not None and base != name):
            raise ValueError("Duplicate, invalid or mixed archive parts.")
        base = name
        with zipfile.ZipFile(path) as zf:
            _part_info(zf, Path(path).stem)
            if zf.comment:
                try:
                    meta = json.loads(zf.comment)
                    valid = (meta["format"] == "FPE2" and isinstance(meta["id"], str)
                             and re.fullmatch(r"[0-9a-f]{32}", meta["id"])
                             and type(meta["index"]) is int and meta["index"] == index
                             and type(meta["count"]) is int and meta["count"] >= index)
                    if not valid:
                        raise ValueError("Invalid part metadata.")
                    current_id, count = meta["id"], meta["count"]
                except (ValueError, KeyError, TypeError) as exc:
                    raise ValueError("Invalid part metadata.") from exc
            elif allow_legacy:
                current_id, count = "legacy", len(zip_paths)
            else:
                raise ValueError("Parts without metadata require explicit legacy recovery.")
            if identity is not None and (identity != current_id or expected_count != count):
                raise ValueError("Parts belong to different archives.")
            identity, expected_count = current_id, count
        parts[index] = path
    if expected_count != len(parts) or sorted(parts) != list(range(1, len(parts) + 1)):
        raise ValueError("Missing archive parts. Select every part starting at 001.")
    with new_output(combined_path) as out:
        for index, path in sorted(parts.items()):
            with zipfile.ZipFile(path) as zf:
                info = _part_info(zf, Path(path).stem)
                with zf.open(info) as stream:
                    shutil.copyfileobj(stream, out, length=BLOCK_SIZE)
            if progress_cb:
                progress_cb(int(index / len(parts) * 30))


def _part_info(zf, expected_name):
    infos = zf.infolist()
    if (len(infos) != 1 or infos[0].filename != expected_name or infos[0].is_dir()
            or infos[0].compress_type != zipfile.ZIP_STORED
            or not 0 < infos[0].file_size <= 20 * 1024 * 1024
            or infos[0].flag_bits & 1):
        raise ValueError("Each ZIP must contain exactly one bounded, uncompressed archive part.")
    return infos[0]


def _validate_link(member, root):
    target = member.linkname
    if not target or PurePosixPath(target).is_absolute() or "\\" in target or PureWindowsPath(target).drive:
        raise ValueError(f"Unsafe link: {member.name}")
    parts = list(PurePosixPath(member.name).parent.parts) if member.issym() else []
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if len(parts) <= 1:
                raise ValueError(f"Link escapes archive root: {member.name}")
            parts.pop()
        else:
            _safe_name(part)
            parts.append(part)
    if not parts or parts[0] != root:
        raise ValueError(f"Link escapes archive root: {member.name}")


def untar_archive(tar_path, extract_dir, progress_cb=None):
    """Extract privately with explicit filtering, then publish into a new folder."""
    destination = Path(extract_dir).resolve()
    if not destination.is_dir():
        raise ValueError("Select an existing output folder.")
    with tempfile.TemporaryDirectory(prefix=".folder-restore-", dir=destination) as work:
        stage = Path(work)
        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                raise ValueError("Archive is empty.")
            root = _safe_name(members[0].name).parts[0]
            seen = set()
            spellings = {}
            types = {m.name.casefold(): m.isdir() for m in members}
            for member in members:
                name = _safe_name(member.name)
                key = str(name).casefold()  # Also reject Windows case aliases on Linux.
                if name.parts[0] != root or key in seen:
                    raise ValueError("Archive must contain one root folder without duplicate paths.")
                seen.add(key)
                for length in range(1, len(name.parts) + 1):
                    prefix = str(PurePosixPath(*name.parts[:length]))
                    alias = prefix.casefold()
                    if alias in spellings and spellings[alias] != prefix:
                        raise ValueError("Archive contains case-colliding directory paths.")
                    spellings[alias] = prefix
                    if length < len(name.parts) and alias in types and not types[alias]:
                        raise ValueError("Archive contains children beneath a file or link.")
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError("Special archive files are not supported.")
                if member.issym() or member.islnk():
                    _validate_link(member, root)
            if not any(m.name == root and m.isdir() for m in members):
                raise ValueError("Archive needs a root directory entry.")
            if os.path.lexists(destination / root):
                raise FileExistsError("Restored folder already exists. Choose another output folder.")
            def safe_filter(member, path):
                filtered = tarfile.data_filter(member, path)
                if member.isdir():
                    # data_filter intentionally drops directory modes. Restore
                    # ordinary permissions, excluding special/group-write bits;
                    # extractall applies them after creating all descendants.
                    filtered = filtered.replace(mode=member.mode & 0o755)
                # Resolve symlink chains, not just lexical .. segments.
                actual = (Path(path) / member.name).resolve()
                boundary = stage / root
                if not actual.is_relative_to(boundary):
                    raise ValueError("Archive path escapes its root folder.")
                if member.issym() or member.islnk():
                    target = ((Path(path) / member.name).parent / member.linkname
                              if member.issym() else Path(path) / member.linkname).resolve()
                    if not target.is_relative_to(boundary):
                        raise ValueError("Archive link escapes its root folder.")
                return filtered
            # extractall restores directory permissions only after writing children.
            tar.extractall(path=stage, members=members, filter=safe_filter)
            if progress_cb:
                progress_cb(99)
        # Exclusive directory reservation avoids overwriting even an empty directory.
        final = destination / root
        final.mkdir()
        try:
            staged_root = stage / root
            root_stat = staged_root.stat()
            # Publication needs write access to the staged parent, even when the
            # archived directory was read-only. Restore its saved mode last.
            staged_root.chmod(root_stat.st_mode | stat.S_IRWXU)
            for child in staged_root.iterdir():
                child.rename(final / child.name)
            shutil.copystat(staged_root, final)
            os.utime(final, ns=(root_stat.st_atime_ns, root_stat.st_mtime_ns))
            final.chmod(stat.S_IMODE(root_stat.st_mode))
        except BaseException:
            shutil.rmtree(final)
            raise
    if progress_cb:
        progress_cb(100)


def pack_folder(folder, outdir, password, progress_cb=None):
    source, output = Path(folder).resolve(), Path(outdir).resolve()
    if not output.is_dir() or output.is_relative_to(source):
        raise ValueError("Choose an existing output folder outside the source folder.")
    with tempfile.TemporaryDirectory(prefix=".folder-pack-", dir=output) as work:
        tar_path = Path(work) / "archive.tar.gz"
        enc_path = Path(work) / (source.name + ".enc")
        tar_folder(source, tar_path, progress_cb)
        encrypt_file(tar_path, enc_path, password,
                     lambda done, total: progress_cb(32 + int(done / total * 28)) if progress_cb else None)
        return split_file(enc_path, output, progress_cb=progress_cb)


def restore_folder(chunks, outdir, password, progress_cb=None, *, allow_legacy=False):
    if not Path(outdir).is_dir():
        raise ValueError("Choose an existing output folder.")
    with tempfile.TemporaryDirectory(prefix=".folder-unpack-", dir=outdir) as work:
        enc, tar = Path(work) / "combined.enc", Path(work) / "archive.tar.gz"
        combine_zips(chunks, enc, progress_cb, allow_legacy=allow_legacy)
        decrypt_file(enc, tar, password,
                     lambda done, total: progress_cb(32 + int(done / total * 30)) if progress_cb else None,
                     allow_legacy=allow_legacy)
        untar_archive(tar, outdir, progress_cb)
