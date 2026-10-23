"""Count common severity labels in a local text log."""

import argparse
from collections import Counter
from pathlib import Path

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def count_levels(path: Path) -> Counter:
    """Count severity labels that appear in each line."""
    counts = Counter()
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            upper_line = line.upper()
            for level in LEVELS:
                if level in upper_line:
                    counts[level] += 1
                    break
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Count common levels in a local log file.")
    parser.add_argument("logfile", type=Path, help="Path to a text log")
    args = parser.parse_args()
    if not args.logfile.is_file():
        parser.error(f"File not found: {args.logfile}")

    counts = count_levels(args.logfile)
    print(f"Log summary: {args.logfile}")
    for level in LEVELS:
        print(f"{level:8} {counts[level]}")


if __name__ == "__main__":
    main()
