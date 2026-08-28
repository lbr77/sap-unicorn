#!/usr/bin/env python3
"""Produce an X-Apple-ActionSignature for a payload, without macOS.

    python sign.py --binary commerce.a64 --mac AABBCCDDEEFF --in payload.plist

With no --in, a small demo payload is signed so you can check the pipeline.
"""

import argparse
import base64
import sys

from sapunicorn.session import SapSession


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="commerce.a64",
                    help="arm64e slice of the commerce daemon (tools/extract.py)")
    ap.add_argument("--mac", default="aabbccddeeff",
                    help="MAC address bound into the SAP session; must match the "
                         "`guid` you send in the login payload")
    ap.add_argument("--in", dest="infile", help="payload to sign ('-' for stdin)")
    ap.add_argument("--raw", action="store_true", help="write raw bytes, not base64")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.infile == "-":
        payload = sys.stdin.buffer.read()
    elif args.infile:
        payload = open(args.infile, "rb").read()
    else:
        import plistlib
        payload = plistlib.dumps({"appleId": "demo@example.com", "why": "signIn"})
        print("[i] no --in given, signing a demo payload", file=sys.stderr)

    session = SapSession(binary=args.binary, mac=args.mac, verbose=args.verbose)
    sig = session.sign(payload)

    if args.raw:
        sys.stdout.buffer.write(sig)
    else:
        print(base64.b64encode(sig).decode())


if __name__ == "__main__":
    main()
