# File Hash Checker

A small command-line tool that calculates a local file's SHA-256 hash. You can compare it with a hash supplied by a trusted source to check file integrity.

## Requirements
- Python 3.10+
- No third-party packages

## Run
From this folder:

```bash
python hash_checker.py path/to/file
```

To compare against a known hash:

```bash
python hash_checker.py path/to/file --expected YOUR_SHA256_HASH
```

## Safety and limitations
This tool reads the file you specify and does not upload it. A matching hash supports integrity checking only when the expected hash came from a trusted, independent source. It does not prove that a file is safe.
