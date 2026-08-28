"""Run the arm64e FairPlay/SAP code under Unicorn.

Pointer authentication is stripped consistently (both signing and
authentication), so pointers stay plain and PAuth support is not required.
"""

import struct
import sys
from unicorn import *
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from .locate import locate
from .macho64 import Image

BIN = "commerce.a64"   # arm64e slice of the `commerce` daemon (see tools/extract.py)

IMP_BASE = 0x2_0000_0000
IMP_SLOT = 0x10
HEAP_BASE = 0x3_0000_0000
HEAP_SIZE = 0x400_0000
STACK_BASE = 0x7F_0000_0000
STACK_SIZE = 0x200_0000
SCRATCH = 0x4_0000_0000
RET_MAGIC = 0x6_0000_0000
ONCE_TRAMP = 0x6_0000_0100   # returns 0 after a once-init routine finishes

# Reference entry points for the pinned build (see BUILDS.md). They are
# recovered from the binary at load time; these are only used to report drift.
#   ctx_init  (&ctx, &hwInfo) -> int
#   proc_cert (sapVersion, &hwInfo, ctx, buf, len, &out, &outlen, &flag) -> int
#   sign      (ctx, data, len, &out, &outlen) -> int
REFERENCE_ENTRIES = {
    "ctx_init": 0x1001108F8,
    "proc_cert": 0x10007A718,
    "sign": 0x1000C68EC,
    "verify": 0x10001FD8C,
}
REFERENCE_BUILD = "macOS 26.4 (25E246)"
REFERENCE_SHA256 = "b8d99ab12ade93521b4501d5e0f8f4989acce078370990fa0b9565c041941db7"

NOP = 0xD503201F
RET = 0xD65F03C0


def align_up(x, a=0x4000):
    return (x + a - 1) & ~(a - 1)


def align_down(x, a=0x4000):
    return x & ~(a - 1)


class EmuA64:
    def __init__(self, path=BIN, verbose=True):
        self.im = Image(path)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        # the blob uses ARMv8.2-SHA3 (eor3) and other extensions; the default
        # CPU model traps them, so ask for the fully featured one.
        self.uc.ctl_set_cpu_model(UC_CPU_ARM64_MAX)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.verbose = verbose
        self.callmap = {}
        self.unimpl = {}
        self.log = []
        self.heap = HEAP_BASE
        self.once_done = set()
        self.once_stack = []
        self.rngstate = 0x2545F4914F6CDD1D
        self.nblocks = 0
        self.blocks = []
        self.entries = locate(self.im)
        self.patched = self._strip_pac()
        self._map()
        self._hooks()

    # ---------- PAC stripping ----------
    def _strip_pac(self):
        n = 0
        for sec in self.im.sections:
            if sec.segname != "__TEXT" or sec.name not in ("__text", "__auth_stubs", "__objc_stubs"):
                continue
            base, buf = self.im._find(sec.addr)
            off0 = sec.addr - base
            data = bytes(buf[off0:off0 + sec.size])
            for i in self.md.disasm(data, sec.addr):
                mn, ops = i.mnemonic, i.op_str
                new = None
                if mn in ("braa", "brab", "braaz", "brabz"):
                    r = self._reg(ops.split(",")[0])
                    if r is not None:
                        new = 0xD61F0000 | (r << 5)
                elif mn in ("blraa", "blrab", "blraaz", "blrabz"):
                    r = self._reg(ops.split(",")[0])
                    if r is not None:
                        new = 0xD63F0000 | (r << 5)
                elif mn in ("retaa", "retab"):
                    new = RET
                elif mn.startswith(("pac", "aut", "xpac")):
                    new = NOP
                if new is not None:
                    struct.pack_into("<I", buf, i.address - base, new)
                    n += 1
        return n

    @staticmethod
    def _reg(tok):
        tok = tok.strip()
        if tok == "xzr":
            return 31
        if tok.startswith("x") and tok[1:].isdigit():
            return int(tok[1:])
        return None

    # ---------- mapping ----------
    def _map(self):
        self.impname = {}
        for addr, ordinal, addend in self.im.binds:
            name = self.im.imports[ordinal]
            slot = IMP_BASE + ordinal * IMP_SLOT
            self.impname[slot] = name
            self.im.write64(addr, slot + addend)

        for name, (base, buf) in self.im.mem.items():
            self.uc.mem_map(align_down(base), align_up(len(buf)), UC_PROT_ALL)
            self.uc.mem_write(base, bytes(buf))

        n = len(self.im.imports)
        self.uc.mem_map(IMP_BASE, align_up(n * IMP_SLOT + 0x4000), UC_PROT_ALL)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        self.uc.mem_map(SCRATCH, 0x100000, UC_PROT_ALL)
        self.uc.mem_map(align_down(RET_MAGIC), 0x4000, UC_PROT_ALL)

        for slot, name in self.impname.items():
            if name == "___stack_chk_guard":
                self.uc.mem_write(slot, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
            else:
                self.uc.mem_write(slot, b"\x00" * 8)

        if self.verbose:
            print(f"[load] base={self.im.base:#x} rebases={len(self.im.rebases)} "
                  f"binds={len(self.im.binds)} imports={n} pac_patched={self.patched}")
            print(f"[load] built for macOS {self.im.minos}, sha256 {self.im.sha256[:16]}...")
            drift = [k for k, v in REFERENCE_ENTRIES.items() if self.entries.get(k) != v]
            tag = f" (differs from {REFERENCE_BUILD}: {', '.join(drift)})" if drift else ""
            print("[load] entries " +
                  " ".join(f"{k}={v:#x}" for k, v in self.entries.items() if v) + tag)

    # ---------- hooks ----------
    def _hooks(self):
        n = len(self.im.imports)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_imp,
                         begin=IMP_BASE, end=IMP_BASE + n * IMP_SLOT)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)
        self.uc.hook_add(UC_HOOK_INSN_INVALID, self._hook_invalid)
        self.uc.hook_add(UC_HOOK_BLOCK, self._hook_block)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_once_ret,
                         begin=ONCE_TRAMP, end=ONCE_TRAMP)

    def _hook_once_ret(self, uc, addr, size, ud):
        lr = self.once_stack.pop() if self.once_stack else RET_MAGIC
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _hook_block(self, uc, addr, size, ud):
        self.nblocks += 1
        self.blocks.append(addr)
        if len(self.blocks) > 400:
            del self.blocks[:200]

    def _hook_invalid(self, uc, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        code = bytes(uc.mem_read(pc, 4))
        print(f"[!!] invalid instruction at {pc:#x}: {code.hex()}")
        return False

    def _hook_unmapped(self, uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        print(f"[!!] unmapped access {address:#x} size={size} at pc={pc:#x}")
        return False

    def _ret(self, uc, val=0):
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_X0, val & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _hook_imp(self, uc, addr, size, ud):
        name = self.impname.get(addr & ~(IMP_SLOT - 1), f"<{addr:#x}>")
        self.callmap[name] = self.callmap.get(name, 0) + 1
        a0 = uc.reg_read(UC_ARM64_REG_X0)
        a1 = uc.reg_read(UC_ARM64_REG_X1)
        a2 = uc.reg_read(UC_ARM64_REG_X2)

        if name == "_malloc":
            p = self.heap
            self.heap = (self.heap + max(a0, 16) + 0x1F) & ~0xF
            uc.mem_write(p, b"\x00" * min(a0, 0x10000))
            self.log.append(f"malloc({a0}) = {p:#x}")
            return self._ret(uc, p)
        if name in ("_free", "_vm_deallocate"):
            return self._ret(uc, 0)
        if name in ("_memcpy", "_memmove"):
            if a2:
                uc.mem_write(a0, bytes(uc.mem_read(a1, a2)))
            return self._ret(uc, a0)
        if name == "_memset":
            if a2:
                uc.mem_write(a0, bytes([a1 & 0xFF]) * a2)
            return self._ret(uc, a0)
        if name == "_bzero":
            if a1:
                uc.mem_write(a0, b"\x00" * a1)
            return self._ret(uc, 0)
        if name == "_arc4random":
            self.rngstate = (self.rngstate * 6364136223846793005 + 1442695040888963407) % (1 << 64)
            return self._ret(uc, (self.rngstate >> 33) & 0xFFFFFFFF)
        if name in ("_gettimeofday", "_time"):
            return self._ret(uc, 0)
        # Stack probe: must return without disturbing any argument register.
        if name == "___chkstk_darwin":
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        # sysctlbyname(name, oldp, oldlenp, newp, newlen)
        if name == "_sysctlbyname":
            nm = ""
            try:
                raw = bytes(uc.mem_read(a0, 64))
                nm = raw[:raw.index(b"\0")].decode()
            except Exception:
                pass
            self.log.append(f"sysctlbyname({nm!r})")
            if a1:
                uc.mem_write(a1, struct.pack("<I", 0))   # kern.hv_vmm_present = 0
            if a2:
                uc.mem_write(a2, struct.pack("<Q", 4))
            return self._ret(uc, 0)
        if name == "_pthread_once":
            if a0 in self.once_done:
                return self._ret(uc, 0)
            self.once_done.add(a0)
            self.log.append(f"pthread_once({a0:#x}) -> init {a1:#x}")
            # Real pthread_once returns 0; the init routine is void. Run it with
            # LR pointing at a trampoline that forces x0 = 0 on the way back.
            self.once_stack.append(uc.reg_read(UC_ARM64_REG_LR))
            uc.reg_write(UC_ARM64_REG_LR, ONCE_TRAMP)
            uc.reg_write(UC_ARM64_REG_PC, a1)
            return
        if name == "_dispatch_once":
            if a0 in self.once_done:
                return self._ret(uc, 0)
            self.once_done.add(a0)
            invoke = struct.unpack("<Q", uc.mem_read(a1 + 16, 8))[0]
            self.once_stack.append(uc.reg_read(UC_ARM64_REG_LR))
            uc.reg_write(UC_ARM64_REG_LR, ONCE_TRAMP)
            uc.reg_write(UC_ARM64_REG_X0, a1)
            uc.reg_write(UC_ARM64_REG_PC, invoke)
            return
        if name.startswith(("_pthread_rwlock", "_pthread_mutex")):
            return self._ret(uc, 0)
        if name == "___stack_chk_fail":
            print("[!!] ___stack_chk_fail")
            uc.emu_stop()
            return
        self.unimpl[name] = self.unimpl.get(name, 0) + 1
        lr = uc.reg_read(UC_ARM64_REG_LR)
        print(f"[imp] UNIMPLEMENTED {name}(x0={a0:#x}, x1={a1:#x}, x2={a2:#x}) <- lr {lr:#x}")
        return self._ret(uc, 0)

    # ---------- calling ----------
    def call(self, func, args=(), timeout=0, maxinsn=0):
        uc = self.uc
        sp = (STACK_BASE + STACK_SIZE - 0x10000) & ~0xF
        uc.reg_write(UC_ARM64_REG_SP, sp)
        uc.reg_write(UC_ARM64_REG_LR, RET_MAGIC)
        regs = [UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
        for r in regs:
            uc.reg_write(r, 0)
        for r, v in zip(regs, args):
            uc.reg_write(r, v)
        self.blocks, self.nblocks = [], 0
        print(f"\n[call] {func:#x}({', '.join(f'{a:#x}' for a in args)})")
        try:
            uc.emu_start(func, RET_MAGIC, timeout=timeout, count=maxinsn)
        except UcError as e:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            print(f"[err] {e} at pc={pc:#x} blocks={self.nblocks}")
            print("[path] " + " ".join(f"{a:#x}" for a in self.blocks[-10:]))
            return None
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        s = x0 & 0xFFFFFFFF
        s = s - (1 << 32) if s >> 31 else s
        print(f"[ret] x0 = {x0:#x} (int32 {s})  blocks = {self.nblocks}")
        return x0
