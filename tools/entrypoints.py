"""Enumerate every call from the daemon's own code into the obfuscated blob.

Daemon code = the ObjC/C part of `commerce` (low addresses, has ObjC methods).
Blob = the statically linked, obfuscated FairPlay library above it.
Any entry point we are not calling in the emulator is a candidate for the
initialisation that ctx_init depends on.
"""

import os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from sapunicorn.macho64 import Image

im = Image(os.environ.get("SAP_BIN", "commerce.a64"))
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

# --- where does the daemon's own ObjC code end? ---
methods = {}          # imp -> "-[Cls sel]"
for cls, ms in im.objc_classes():
    for sel, imp in ms:
        if imp:
            methods[imp] = f"[{cls} {sel}]"
boundary = max(methods) if methods else 0
print(f"ObjC methods: {len(methods)}, highest imp = {boundary:#x}")

stubs = im.section("__auth_stubs")
objcs = im.section("__objc_stubs")
STUB_LO, STUB_HI = stubs.addr, objcs.addr + objcs.size
tx = im.section("__text")
BLOB_LO = boundary + 0x200          # a little slack past the last method

def owner(addr):
    """nearest preceding ObjC method, for labelling call sites"""
    best, name = 0, None
    for imp, n in methods.items():
        if best < imp <= addr:
            best, name = imp, n
    return name or "?"

edges = {}
for i in md.disasm(im.read(tx.addr, tx.size), tx.addr):
    if i.mnemonic != "bl" or not i.op_str.startswith("#"):
        continue
    src, dst = i.address, int(i.op_str[1:], 16)
    if src < BLOB_LO <= dst and not (STUB_LO <= dst < STUB_HI):
        edges.setdefault(dst, []).append(src)

print(f"\n=== daemon -> blob entry points: {len(edges)} ===")
KNOWN = {0x1001108F8: "ctx_init", 0x10007A718: "process_cert",
         0x1000C68EC: "sign", 0x10001FD8C: "verify", 0x100121C8C: "fp_global_init"}
for dst in sorted(edges):
    tag = KNOWN.get(dst, "")
    srcs = edges[dst]
    print(f"  {dst:#012x}  {tag:<15} called from {len(srcs)} site(s)")
    for s in srcs[:6]:
        print(f"        {s:#012x}  in {owner(s)}")
