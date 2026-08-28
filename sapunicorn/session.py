"""A complete SAP signing session driven entirely from Python.

Establishes the FairPlay SAP session by emulating the signing code lifted out
of the macOS `commerce` daemon, doing the two handshake legs against Apple's
servers over plain HTTPS, and then signing arbitrary payloads locally.
"""

import plistlib
import struct
import urllib.request

from .emu_a64 import EmuA64, SCRATCH

# Both URLs come from the CommerceKit bag: https://init.itunes.apple.com/bag.xml?ix=6
BAG_URL = "https://init.itunes.apple.com/bag.xml?ix=6"
SETUP_CERT_URL = "https://s.mzstatic.com/sap/setupCert.plist"
SETUP_URL = "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy"
SAP_VERSION = 0xC8            # bag key `sign-sap-version` = 200

HW = SCRATCH
CTX = SCRATCH + 0x100
OUT = SCRATCH + 0x200
OUTLEN = SCRATCH + 0x208
FLAG = SCRATCH + 0x210
IN = SCRATCH + 0x1000


class SapError(RuntimeError):
    pass


def _fetch(url, data=None, content_type=None, timeout=45):
    headers = {"Content-Type": content_type} if content_type else {}
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


class SapSession:
    """One established SAP session. Call `sign()` as many times as you like."""

    def __init__(self, binary="commerce.a64", mac="aabbccddeeff", verbose=False):
        self.verbose = verbose
        self.emu = EmuA64(binary, verbose=verbose)
        self.mac = bytes.fromhex(mac.replace(":", "").replace("-", ""))
        if len(self.mac) != 6:
            raise ValueError("mac must be 6 bytes")
        self.ctx = 0
        self._open()

    # ---- internals -------------------------------------------------
    def _log(self, *a):
        if self.verbose:
            print(*a)

    def _call(self, func, args):
        return self.emu.call(func, args, timeout=300 * 1000 * 1000,
                             maxinsn=2_000_000_000)

    def _process(self, data):
        """Run one handshake leg through the SAP state machine."""
        for a in (OUT, OUTLEN, FLAG):
            self.emu.uc.mem_write(a, b"\x00" * 8)
        self.emu.uc.mem_write(IN, data)
        rc = self._call(self.emu.entries["proc_cert"],
                        (SAP_VERSION, HW, self.ctx, IN, len(data), OUT, OUTLEN, FLAG))
        if rc != 0:
            raise SapError(f"SAP handshake step failed: {rc & 0xFFFFFFFF:#x}")
        ptr = struct.unpack("<Q", self.emu.uc.mem_read(OUT, 8))[0]
        n = struct.unpack("<I", self.emu.uc.mem_read(OUTLEN, 4))[0]
        return bytes(self.emu.uc.mem_read(ptr, n)) if ptr and n else b""

    def _open(self):
        # FairPlayHWInfo_ { uint32 IDLength; uint8 ID[20]; }
        self.emu.uc.mem_write(HW, struct.pack("<I", 6) + self.mac + b"\x00" * 14)
        self.emu.uc.mem_write(CTX, b"\x00" * 8)

        rc = self._call(self.emu.entries["ctx_init"], (CTX, HW))
        if rc != 0:
            raise SapError(f"SAP context init failed: {rc & 0xFFFFFFFF:#x}")
        self.ctx = struct.unpack("<Q", self.emu.uc.mem_read(CTX, 8))[0]
        self._log(f"[sap] context = {self.ctx:#x}")

        cert = plistlib.loads(_fetch(SETUP_CERT_URL))["sign-sap-setup-cert"]
        self._log(f"[sap] setup cert: {len(cert)} bytes")
        setup_buffer = self._process(cert)
        self._log(f"[sap] setup buffer: {len(setup_buffer)} bytes")

        body = plistlib.dumps({"sign-sap-setup-buffer": setup_buffer})
        resp = _fetch(SETUP_URL, data=body, content_type="application/x-apple-plist")
        server_buffer = plistlib.loads(resp)["sign-sap-setup-buffer"]
        self._log(f"[sap] server response: {len(server_buffer)} bytes")

        self._process(server_buffer)
        self._log("[sap] session established")

    # ---- public ----------------------------------------------------
    def sign(self, payload: bytes) -> bytes:
        """Return the raw SAP signature for `payload` (base64 it for the header)."""
        if not self.ctx:
            raise SapError("session is not open")
        self.emu.uc.mem_write(IN, payload)
        for a in (OUT, OUTLEN):
            self.emu.uc.mem_write(a, b"\x00" * 8)
        rc = self._call(self.emu.entries["sign"], (self.ctx, IN, len(payload), OUT, OUTLEN))
        if rc != 0:
            raise SapError(f"SAP sign failed: {rc & 0xFFFFFFFF:#x}")
        ptr = struct.unpack("<Q", self.emu.uc.mem_read(OUT, 8))[0]
        n = struct.unpack("<I", self.emu.uc.mem_read(OUTLEN, 4))[0]
        if not ptr or not n:
            raise SapError("SAP returned an empty signature")
        return bytes(self.emu.uc.mem_read(ptr, n))
