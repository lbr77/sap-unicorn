#!/usr/bin/env python3
"""HTTP signing service: hands out X-Apple-ActionSignature values.

Lets a client on any platform obtain SAP signatures without CommerceKit.
A SAP session is established lazily per GUID and then reused, so only the
first request for a given GUID pays the handshake cost.

    python server.py --binary commerce.a64 --port 8099

    curl -s --data-binary @payload.plist \
         'http://127.0.0.1:8099/sign?guid=AABBCCDDEEFF' | base64

The GUID must be the same value the client sends as `guid` in the Apple
payload, because the SAP session is bound to that MAC address.
"""

import argparse
import base64
import json
import re
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from sapunicorn.session import SapSession, SapError

GUID_RE = re.compile(r"^[0-9A-Fa-f]{12}$")

_binary = "commerce.a64"
_sessions = {}
_lock = threading.Lock()      # the emulator is a single CPU; serialise access


def get_session(guid):
    """One SapSession per GUID, created on first use."""
    with _lock:
        s = _sessions.get(guid)
        if s is None:
            s = SapSession(binary=_binary, mac=guid, verbose=False)
            _sessions[guid] = s
        return s


class Handler(BaseHTTPRequestHandler):
    server_version = "sap-unicorn/1.0"

    def log_message(self, fmt, *args):
        print(f"[{self.address_string()}] {fmt % args}")

    def _send(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode() + b"\n", "application/json")

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/health", "/"):
            return self._json(200, {"status": "ok",
                                    "binary": _binary,
                                    "sessions": sorted(_sessions)})
        self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/sign":
            return self._json(404, {"error": "not found"})

        guid = (parse_qs(parsed.query).get("guid") or [""])[0].strip()
        if not GUID_RE.match(guid):
            return self._json(400, {"error": "guid must be 12 hex digits "
                                             "(MAC address, no separators)"})

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return self._json(400, {"error": "empty payload"})
        payload = self.rfile.read(length)

        try:
            session = get_session(guid.lower())
            with _lock:
                sig = session.sign(payload)
        except SapError as e:
            return self._json(502, {"error": f"sap: {e}"})
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})

        if "base64" in (self.headers.get("Accept") or ""):
            return self._send(200, base64.b64encode(sig), "text/plain")
        self._send(200, sig)


def main():
    global _binary
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="commerce.a64")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--warm", metavar="GUID",
                    help="establish a session for this GUID at startup")
    args = ap.parse_args()
    _binary = args.binary

    if args.warm:
        print(f"[warm] establishing session for {args.warm}")
        get_session(args.warm.lower())
        print("[warm] ready")

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[serve] http://{args.host}:{args.port}  binary={_binary}")
    print("[serve] POST /sign?guid=AABBCCDDEEFF   GET /health")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve] bye")


if __name__ == "__main__":
    main()
