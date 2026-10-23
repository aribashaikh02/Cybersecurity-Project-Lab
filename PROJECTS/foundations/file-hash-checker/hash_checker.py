"""Calculate and optionally verify the SHA-256 hash of a local file."""

import argparse
import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest for a file, reading it in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Calculate a local file's SHA-256 hash.")
    parser.add_argument("file", type=Path, help="Path to the file to hash")
    parser.add_argument("--expected", help="Optional expected SHA-256 hex digest")
    args = parser.parse_args()

    if not args.file.is_file():
        parser.error(f"Not a readable regular file: {args.file}")

    actual = sha256_file(args.file)
    print(f"File:   {args.file}")
    print(f"SHA256: {actual}")

    if args.expected:
        matches = actual.lower() == args.expected.strip().lower()
        print(f"Match:  {'YES' if matches else 'NO'}")
        return 0 if matches else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
