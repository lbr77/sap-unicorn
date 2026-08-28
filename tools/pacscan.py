"""Survey pointer-authentication instructions in the arm64e image."""

import os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from sapunicorn.macho64 import Image

im = Image(os.environ.get("SAP_BIN", "commerce.a64"))
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

PAC = ("pac", "aut", "braa", "brab", "blraa", "blrab", "retaa", "retab",
       "eretaa", "eretab", "ldraa", "ldrab", "xpac")

counts = {}
for sec in im.sections:
    if sec.segname != "__TEXT" or sec.name not in ("__text", "__auth_stubs", "__objc_stubs"):
        continue
    data = im.read(sec.addr, sec.size)
    n = 0
    for i in md.disasm(data, sec.addr):
        n += 1
        if i.mnemonic.startswith(PAC):
            counts[i.mnemonic] = counts.get(i.mnemonic, 0) + 1
    print(f"{sec.name:<16} {sec.addr:#x} size={sec.size:#x} decoded={n}")

print("\n=== PAC instructions ===")
total = 0
for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
    print(f"  {k:<10} {v}")
    total += v
print(f"  TOTAL     {total}")

# auth pointers among the fixups
auth_rebases = sum(1 for _ in im.rebases)
print(f"\nrebases={len(im.rebases)} binds={len(im.binds)}")
