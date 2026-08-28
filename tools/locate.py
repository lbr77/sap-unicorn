"""List direct calls from the SigningSession methods into the obfuscated blob.

Anything branching outside __auth_stubs / __objc_stubs is a call into the
statically linked FairPlay code.
"""

import os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from sapunicorn.macho64 import Image

im = Image(os.environ.get("SAP_BIN", "commerce.a64"))
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

stubs = im.section("__auth_stubs")
objcs = im.section("__objc_stubs")
STUB_LO, STUB_HI = stubs.addr, objcs.addr + objcs.size

METHODS = {
    "-[SigningSession _openSessionWithType:withCompletionHandler:]": (0x100010A84, 0x100011178),
    "-[SigningSession signData:error:]": (0x1000111FC, 0x100011380),
    "-[SigningSession signedResponseData:withSignature:error:]": (0x100011380, 0x1000114F4),
    "-[SigningSession processSignature:]": (0x1000114F4, 0x1000115C0),
    "-[FairPlayContext _setupFPContext]": (0x10000E5C0, 0x10000E680),
}

for name, (lo, hi) in METHODS.items():
    out = []
    for i in md.disasm(im.read(lo, hi - lo), lo):
        if i.mnemonic == "bl" and i.op_str.startswith("#"):
            t = int(i.op_str[1:], 16)
            if not (STUB_LO <= t < STUB_HI):
                out.append((i.address, t))
    print(f"\n{name}")
    for a, t in out:
        print(f"    {a:#012x}  bl  {t:#012x}   <-- into blob")
    if not out:
        print("    (no direct blob calls)")
