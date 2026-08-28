import sys
import os
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from sapunicorn.macho64 import Image
im = Image(os.environ.get("SAP_BIN", "commerce.a64"))
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
def dis(a, n, show_all=True):
    print(f"\n===== {a:#x} =====")
    for i in md.disasm(im.read(a, n), a):
        mark = ""
        if i.mnemonic in ("bl","b") and i.op_str.startswith("#"):
            mark = "   <-- call"
        if show_all or mark:
            print(f"  {i.address:#012x}  {i.mnemonic:<8} {i.op_str}{mark}")
for spec in sys.argv[1:]:
    a, n = spec.split(":")
    dis(int(a, 16), int(n))
