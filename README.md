# Folder Packer & Encrypter

A local Tk application that compresses a folder, encrypts it with AES-256-GCM,
and splits it into ordinary ZIP attachments. Restore by selecting **every ZIP
part**, entering the password, and choosing an output folder.

## Requirements and launch

Python **3.12–3.14**, Tkinter, and `cryptography` are supported. CI tests Windows
and Linux on these Python versions. No network connection is needed at runtime.

Windows PowerShell, from the project directory:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe folder_zipper.py
```

Linux (with Python and Tk already available):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python folder_zipper.py
```

In managed environments, use your organisation's approved Python, Tk and package
source. An approved offline wheel directory can replace internet package access:

```powershell
.\.venv\Scripts\python.exe -m pip install --no-index --find-links C:\approved-wheels -r requirements.txt
```

The dependency may still be subject to local application-control policy; using
`cryptography` does not guarantee that AppLocker will permit its native modules.

## Usage and file safety

- Pack: choose a source folder, an existing output folder **outside** the source,
  and enter and confirm a password. Choose a strong, unique password and retain
  it separately; there is no password recovery.
- ZIPs are named `<folder>.part001.zip`, `part002.zip`, etc. Each complete ZIP,
  including its headers and metadata, is at most **20,000,000 bytes (20 MB)**.
  Email systems may impose lower limits or count transport encoding overhead.
- Restore: add all ZIPs, enter the password, and choose an existing output
  directory. Selection order does not matter. Missing, duplicate and mixed parts
  are rejected. Keep the original part names.
- Existing parts and restored folders are never replaced. Use a fresh output
  directory for another run with the same folder name.
- Only one job runs at a time. Wait for it to finish before closing the app.
- Temporary plaintext archives are created in a unique workspace under the
  output directory and removed on normal completion or handled errors. Restores
  are staged before publication. Abrupt process termination, power loss or
  cleanup failures can leave temporary data; deletion is **not secure erasure**.
  Use an output location with appropriate access controls and sufficient disk
  space for temporary archives, ciphertext, ZIPs and restored contents.
- Use a stable source folder: this is not a filesystem snapshot. Files modified
  while packing can produce an inconsistent backup.

## Symlinks and archive extraction

The application preserves supported relative symlinks that stay within the
archived root folder. External or absolute links, traversal paths, special
device files, duplicate/case-colliding paths and nonportable Windows names are
rejected. Extraction explicitly uses Python's `tarfile.data_filter` on every
supported Python version, with additional root and link validation.

Windows symlink creation depends on account privileges and system policy. No
administrator rights are assumed. A system unable to recreate a link may fail
restoration; successful symlink creation is tested where the account allows it.
Directory permissions are restored after children are extracted, with special
and group/other-write bits removed. Platform
metadata such as ACLs, alternate data streams and Windows junction semantics
is not guaranteed to round-trip.

## Format and compatibility

New files use **FPE2**. AES-256 keys are derived with PBKDF2-HMAC-SHA256,
200,000 iterations, and a fresh 16-byte random salt per file. The header is:

```text
FPE2 (4) | salt (16) | random nonce prefix (8) | plaintext size (uint64, big-endian)
```

Each data record contains a uint32 ciphertext length followed by up to 1 MiB
of encrypted plaintext and a 16-byte GCM tag. Its 12-byte nonce is the file's
prefix followed by a uint32 block counter starting at zero. Associated data is
the entire header, that counter, and `D`. A mandatory final record authenticates
empty plaintext with the next counter and associated-data suffix `F`. Header,
block order, total size and completion are authenticated; trailing data is
rejected. Empty plaintext also has an authenticated final record. Decryption
limits record lengths before reading their bodies and removes incomplete output.

ZIP comments record the format, a random archive ID, part index and part count.
This metadata detects ordinary selection mistakes; cryptographic authenticity
comes from the reassembled FPE2 stream. ZIP names and size metadata are visible;
the inner tar archive and file contents are encrypted. This custom container
format has regression tests but has not had an independent cryptographic audit.

Old **FPE1** archives require the **Recover old FPE1 archives** checkbox and a
warning acknowledgement. Old ZIPs without metadata are accepted only in this
mode. Legacy blocks authenticate individually, so missing or reordered whole
blocks cannot reliably be detected. Check recovered files against an independent
source. New FPE2 archives cannot be restored by the original FPE1-only app.

## Verification

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -W error::DeprecationWarning -m unittest discover -s tests -v
```

Linux:

```sh
.venv/bin/python -W error::DeprecationWarning -m unittest discover -s tests -v
```

GUI tests need a display and skip if none is available. CI uses a virtual display
on Linux. Tests cover pack/restore, tampering, final-record validation, wrong
passwords, legacy opt-in, numeric ordering above 1,000 parts, ZIP limits,
streaming ZIP reads, unsafe extraction, overwrite prevention and failure cleanup.

Design references: [AESGCM associated data and nonce requirements](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
and [Python extraction filters](https://docs.python.org/3.12/library/tarfile.html#extraction-filters).
