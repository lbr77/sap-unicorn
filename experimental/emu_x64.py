"""Run the obfuscated FairPlay/SAP code out of the `commerce` daemon under Unicorn.

Every imported symbol becomes a self-reporting stub, so the emulator tells us
empirically which host services the blob actually needs.
"""

import struct
import sys
from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from machoload_x64 import MachO

BIN = "commerce.x64"

IMP_BASE = 0x2_0000_0000     # one 16-byte slot per import
IMP_SLOT = 0x10
HEAP_BASE = 0x3_0000_0000
HEAP_SIZE = 0x400_0000
STACK_BASE = 0x7FF0_0000_0000
STACK_SIZE = 0x200_0000
SCRATCH = 0x4_0000_0000
GS_BASE = 0x5_0000_0000
RET_MAGIC = 0x6_0000_0000     # sentinel return address

# SAP entry points recovered from IDA (macOS 27.0 build of `commerce`)
SAP_CTX_INIT = 0x1000A2180    # sub_1000A2180(ctx_out, hwinfo)
SAP_PROC_CERT = 0x10002C580   # sub_10002C580(type, hw, ctx, cert, certlen, &out, &outlen, &flag)
SAP_SIGN = 0x1000742A0        # sub_1000742A0(ctx, data, len, &out, &outlen)
FP_GLOBAL_INIT = 0x1001612C0  # sub_1001612C0(0, hwinfo, scInfoPath, &globalCtx)


def align_down(x, a=0x1000):
    return x & ~(a - 1)


def align_up(x, a=0x1000):
    return (x + a - 1) & ~(a - 1)


class Emu:
    def __init__(self, path, trace=0):
        self.macho = MachO(path)
        self.macho.parse_fixups()
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.trace = trace
        self.icount = 0
        self.unimpl = {}
        self.callmap = {}
        self.heap = HEAP_BASE
        self.once_done = set()
        self.rngstate = 0x2545F4914F6CDD1D
        self.tsc = 0x1000000
        self.rdtsc_hits = 0
        self.RDTSC_SITES = [0x10002c61c, 0x10006a27a, 0x10006fda3, 0x10007f47b, 0x1000bd822,
                            0x100102262, 0x10012bce6, 0x10012db90, 0x100130e09, 0x10013df95]
        self.log = []
        self.blocks = []
        self.nblocks = 0
        self.watch_err = None
        self.err_at = None
        self._load()
        self._imports()
        self._hooks()

    # ---------------- loading ----------------
    def _load(self):
        self.segdata = {}
        for s in self.macho.segments:
            if s.name == "__PAGEZERO" or s.vmsize == 0:
                continue
            if s.name == "__LINKEDIT":
                continue
            buf = bytearray(align_up(s.vmsize))
            buf[:len(s.data)] = s.data
            self.segdata[s.name] = (s.vmaddr, buf)

        # apply rebases
        for addr, target in self.macho.rebase_sites:
            self._patch64(addr, target)
        print(f"[load] segments={list(self.segdata)} "
              f"rebases={len(self.macho.rebase_sites)} binds={len(self.macho.bind_sites)} "
              f"imports={len(self.macho.imports)}")

    def _patch64(self, addr, val):
        for name, (base, buf) in self.segdata.items():
            if base <= addr < base + len(buf):
                struct.pack_into("<Q", buf, addr - base, val & 0xFFFFFFFFFFFFFFFF)
                return True
        return False

    def _imports(self):
        # bind sites -> synthetic per-import addresses
        self.impname = {}
        for addr, ordinal, addend in self.macho.bind_sites:
            name = self.macho.imports[ordinal][0]
            slot = IMP_BASE + ordinal * IMP_SLOT
            self.impname[slot] = name
            self._patch64(addr, slot + addend)

        for name, (base, buf) in self.segdata.items():
            self.uc.mem_map(align_down(base), align_up(len(buf)), UC_PROT_ALL)
            self.uc.mem_write(base, bytes(buf))

        nimp = len(self.macho.imports)
        self.uc.mem_map(IMP_BASE, align_up(nimp * IMP_SLOT + 0x1000), UC_PROT_ALL)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_ALL)
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        self.uc.mem_map(SCRATCH, 0x100000, UC_PROT_ALL)
        self.uc.mem_map(GS_BASE, 0x10000, UC_PROT_ALL)
        self.uc.mem_map(RET_MAGIC & ~0xFFF, 0x1000, UC_PROT_ALL)

        # data-import slots need plausible contents
        for slot, name in self.impname.items():
            if name == "___stack_chk_guard":
                self.uc.mem_write(slot, struct.pack("<Q", 0xDEADBEEFCAFEBABE))
            elif name == "_mach_task_self_":
                self.uc.mem_write(slot, struct.pack("<I", 0x103))
            else:
                self.uc.mem_write(slot, b"\x00" * 8)

        self.uc.reg_write(UC_X86_REG_GS_BASE, GS_BASE)

    # ---------------- hooks ----------------
    def _hooks(self):
        nimp = len(self.macho.imports)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_import,
                         begin=IMP_BASE, end=IMP_BASE + nimp * IMP_SLOT)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)
        self.uc.hook_add(UC_HOOK_INSN_INVALID, self._hook_invalid)
        self.uc.hook_add(UC_HOOK_BLOCK, self._hook_block)
        for a in self.RDTSC_SITES:
            self.uc.hook_add(UC_HOOK_CODE, self._hook_rdtsc, begin=a, end=a)
        if self.trace:
            self.uc.hook_add(UC_HOOK_CODE, self._hook_trace,
                             begin=0x100000000, end=0x100300000)

    def _hook_block(self, uc, addr, size, ud):
        self.nblocks += 1
        if self.watch_err is not None and self.err_at is None:
            if uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF == self.watch_err:
                self.err_at = (self.nblocks, addr, list(self.blocks[-8:]))
        self.blocks.append(addr)
        if len(self.blocks) > 400:
            del self.blocks[:200]

    def _hook_rdtsc(self, uc, addr, size, ud):
        # Unicorn's own TSC is not a realistic clock; supply a monotonic one.
        self.rdtsc_hits += 1
        self.tsc += 0x4000 + (self.rdtsc_hits * 977)
        uc.reg_write(UC_X86_REG_RAX, self.tsc & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_RDX, (self.tsc >> 32) & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_RIP, addr + 2)

    def _hook_trace(self, uc, addr, size, ud):
        self.icount += 1
        if self.icount <= self.trace:
            code = uc.mem_read(addr, size)
            for i in self.md.disasm(bytes(code), addr):
                print(f"  {i.address:#011x}  {i.mnemonic:<8} {i.op_str}")

    def _hook_invalid(self, uc, ud):
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"[!!] invalid instruction at {rip:#x}")
        return False

    def _hook_unmapped(self, uc, access, address, size, value, ud):
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"[!!] unmapped {'write' if access in (UC_MEM_WRITE_UNMAPPED,) else 'read'} "
              f"{address:#x} size={size} at rip={rip:#x}")
        return False

    # ---------------- import dispatch ----------------
    def _ret(self, uc, val=0):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RAX, val & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def _hook_import(self, uc, addr, size, ud):
        name = self.impname.get(addr & ~(IMP_SLOT - 1))
        if name is None:
            name = f"<slot {addr:#x}>"
        self.callmap[name] = self.callmap.get(name, 0) + 1
        a0 = uc.reg_read(UC_X86_REG_RDI)
        a1 = uc.reg_read(UC_X86_REG_RSI)
        a2 = uc.reg_read(UC_X86_REG_RDX)

        if name == "_malloc":
            p = self.heap
            self.heap = (self.heap + max(a0, 16) + 0x1F) & ~0xF
            uc.mem_write(p, b"\x00" * min(a0, 0x10000))
            self.log.append(f"malloc({a0}) = {p:#x}")
            return self._ret(uc, p)
        if name in ("_free", "_vm_deallocate"):
            return self._ret(uc, 0)
        if name == "_memcpy" or name == "_memmove":
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
            self.rngstate = (self.rngstate * 6364136223846793005 + 1442695040888963407) & (2**64-1)
            return self._ret(uc, (self.rngstate >> 33) & 0xFFFFFFFF)
        # pthread_once(pred, init) — tail-jump into init so its `ret` lands back
        # at pthread_once's own caller. Track "done" on the Python side.
        if name == "_pthread_once":
            if a0 in self.once_done:
                return self._ret(uc, 0)
            self.once_done.add(a0)
            self.log.append(f"pthread_once(pred={a0:#x}) -> running init {a1:#x}")
            uc.reg_write(UC_X86_REG_RIP, a1)
            return
        # dispatch_once(pred, block): block->invoke(block), invoke at +16
        if name == "_dispatch_once":
            if a0 in self.once_done:
                return self._ret(uc, 0)
            self.once_done.add(a0)
            invoke = struct.unpack("<Q", uc.mem_read(a1 + 16, 8))[0]
            self.log.append(f"dispatch_once(pred={a0:#x}) -> block invoke {invoke:#x}")
            uc.reg_write(UC_X86_REG_RDI, a1)
            uc.reg_write(UC_X86_REG_RIP, invoke)
            return
        if name.startswith("_pthread_rwlock") or name.startswith("_pthread_mutex"):
            return self._ret(uc, 0)
        if name in ("_gettimeofday", "_time"):
            return self._ret(uc, 0)
        if name == "___stack_chk_fail":
            print("[!!] ___stack_chk_fail — stack cookie clobbered")
            uc.emu_stop()
            return
        if name == "__Unwind_Resume":
            print("[!!] _Unwind_Resume — C++ exception escaped")
            uc.emu_stop()
            return

        self.unimpl[name] = self.unimpl.get(name, 0) + 1
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        print(f"[imp] UNIMPLEMENTED {name}(rdi={a0:#x}, rsi={a1:#x}, rdx={a2:#x})  "
              f"<- caller {ret:#x}")
        return self._ret(uc, 0)

    # ---------------- calling ----------------
    def call(self, func, args=(), timeout=0, maxinsn=0):
        uc = self.uc
        rsp = STACK_BASE + STACK_SIZE - 0x10000
        rsp &= ~0xF
        stack_args = list(args[6:])
        if stack_args:
            rsp -= 8 * len(stack_args)
            rsp &= ~0xF
            for i, v in enumerate(stack_args):
                uc.mem_write(rsp + 8 * i, struct.pack("<Q", v))
        rsp -= 8
        uc.mem_write(rsp, struct.pack("<Q", RET_MAGIC))
        uc.reg_write(UC_X86_REG_RSP, rsp)
        regs = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
        for r in regs:
            uc.reg_write(r, 0)
        uc.reg_write(UC_X86_REG_RAX, 0)
        for r, v in zip(regs, args):
            uc.reg_write(r, v)
        self.blocks = []
        self.nblocks = 0
        self.err_at = None
        argstr = ", ".join(f"{a:#x}" for a in args)
        print(f"\n[call] {func:#x}({argstr})")
        try:
            uc.emu_start(func, RET_MAGIC, timeout=timeout, count=maxinsn)
        except UcError as e:
            rip = uc.reg_read(UC_X86_REG_RIP)
            print(f"[err] {e} at rip={rip:#x} after ~{self.icount} traced insns")
            return None
        rax = uc.reg_read(UC_X86_REG_RAX)
        sgn = rax & 0xFFFFFFFF
        sgn = sgn - (1 << 32) if sgn >> 31 else sgn
        print(f"[ret] rax = {rax:#x} (int32 {sgn})  blocks executed = {self.nblocks}")
        print("[path] last blocks: " + " ".join(f"{a:#x}" for a in self.blocks[-14:]))
        if self.err_at:
            n, a, prev = self.err_at
            print(f"[err-origin] rax first == {self.watch_err:#x} at block {n}/{self.nblocks} addr {a:#x}")
            print("[err-origin] preceded by: " + " ".join(f"{x:#x}" for x in prev))
        return rax


def main():
    trace = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    e = Emu(BIN, trace=trace)
    e.watch_err = 0xffff5abe

    # FairPlayHWInfo_ { uint32 IDLength; uint8 ID[20]; }
    hw = SCRATCH
    mac = bytes.fromhex("aabbccddeeff")
    e.uc.mem_write(hw, struct.pack("<I", 6) + mac + b"\x00" * 14)
    ctx_out = SCRATCH + 0x100
    e.uc.mem_write(ctx_out, b"\x00" * 8)
    scpath = SCRATCH + 0x200
    e.uc.mem_write(scpath, b"/Users/Shared/SC Info\x00")
    gctx_out = SCRATCH + 0x300
    e.uc.mem_write(gctx_out, b"\x00" * 8)

    # -[FairPlayContext _setupFPContext] does this first
    e.call(FP_GLOBAL_INIT, (0, hw, scpath, gctx_out),
           timeout=30 * 1000 * 1000, maxinsn=200_000_000)
    gctx = struct.unpack("<Q", e.uc.mem_read(gctx_out, 8))[0]
    print(f"[out] global FairPlay context = {gctx:#x}")

    e.call(SAP_CTX_INIT, (ctx_out, hw), timeout=20 * 1000 * 1000, maxinsn=50_000_000)

    ctx = struct.unpack("<Q", e.uc.mem_read(ctx_out, 8))[0]
    print(f"\n[out] ctx pointer written back = {ctx:#x}")
    print(f"[stat] import calls: {dict(sorted(e.callmap.items(), key=lambda kv: -kv[1]))}")
    if e.unimpl:
        print(f"[stat] UNIMPLEMENTED hit: {dict(sorted(e.unimpl.items(), key=lambda kv: -kv[1]))}")
    for line in e.log[:20]:
        print("   ", line)


if __name__ == "__main__":
    main()
