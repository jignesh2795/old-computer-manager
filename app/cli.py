"""Command-line entry point for the first read-only discovery build."""

from __future__ import annotations

import json
import platform
import socket
import sys

from app.discovery import run


def main() -> int:
    print("Old Computer Manager v0.1.0-alpha")
    print("Read-only discovery mode")
    print(f"Platform: {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Computer name: {socket.gethostname()}")
    print("Collecting baseline information...\n")

    results = run()
    print(json.dumps(results, indent=2, default=str))
    print("\nBaseline saved to data/computer.db")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
