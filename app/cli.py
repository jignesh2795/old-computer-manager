"""Command-line entry point for the first read-only discovery build."""

from __future__ import annotations

import platform
import socket
import sys


def main() -> int:
    print("Old Computer Manager v0.1.0-alpha")
    print("Read-only discovery mode")
    print(f"Platform: {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Computer name: {socket.gethostname()}")
    print("Collectors will be added incrementally.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
