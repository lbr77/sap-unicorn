#!/usr/bin/env python3
"""Pull the arm64e slice of the `commerce` daemon off the local macOS install.

The binary is Apple's and is deliberately not distributed with this repo.
"""

import subprocess
import sys

SRC = ("/System/Library/PrivateFrameworks/CommerceKit.framework"
       "/Versions/A/Resources/commerce")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "commerce.a64"
    arch = sys.argv[2] if len(sys.argv) > 2 else "arm64e"
    subprocess.run(["lipo", "-thin", arch, SRC, "-output", out], check=True)
    subprocess.run(["shasum", "-a", "256", out], check=True)
    print(f"wrote {out} ({arch})")
    print("note: entry addresses in sapunicorn/emu_a64.py are build-specific; "
          "re-run tools/locate.py if your macOS build differs")


if __name__ == "__main__":
    main()
