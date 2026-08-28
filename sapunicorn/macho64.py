"""Mach-O loader for x86_64 and arm64e, with chained fixups + ObjC metadata.

Supports DYLD_CHAINED_PTR_64 (2), _64_OFFSET (6),
ARM64E (1), ARM64E_USERLAND (9), ARM64E_USERLAND24 (12).
"""

import struct
from collections import namedtuple

LC_SEGMENT_64 = 0x19
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_BUILD_VERSION = 0x32

PTR_64 = 2
PTR_64_OFFSET = 6
PTR_ARM64E = 1
PTR_ARM64E_USERLAND = 9
PTR_ARM64E_USERLAND24 = 12
ARM64E_FORMATS = (PTR_ARM64E, PTR_ARM64E_USERLAND, PTR_ARM64E_USERLAND24)
START_NONE = 0xFFFF

Segment = namedtuple("Segment", "name vmaddr vmsize fileoff filesize data")
Section = namedtuple("Section", "segname name addr size offset")


class Image:
    def __init__(self, path):
        self.buf = open(path, "rb").read()
        assert struct.unpack_from("<I", self.buf, 0)[0] == 0xFEEDFACF, "need thin 64-bit Mach-O"
        self.ncmds = struct.unpack_from("<I", self.buf, 16)[0]
        self.segments, self.sections = [], []
        self.chained_off = None
        self.minos = None
        self.sdk = None
        self._parse_cmds()
        self.base = min(s.vmaddr for s in self.segments
                        if s.vmsize and s.name != "__PAGEZERO")
        self.imports, self.binds, self.rebases = [], [], []
        self.ptr_format = None
        self.mem = {}
        self._build_mem()
        if self.chained_off is not None:
            self._parse_fixups()
            for addr, val in self.rebases:
                self.write64(addr, val)

    @staticmethod
    def _ver(v):
        return f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}".rstrip(".0") or "0"

    @property
    def sha256(self):
        import hashlib
        return hashlib.sha256(self.buf).hexdigest()

    # ---------- load commands ----------
    def _parse_cmds(self):
        off = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.buf, off)
            if cmd == LC_SEGMENT_64:
                name = self.buf[off + 8:off + 24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.buf, off + 24)
                nsects = struct.unpack_from("<I", self.buf, off + 64)[0]
                self.segments.append(Segment(name, vmaddr, vmsize, fileoff, filesize,
                                             self.buf[fileoff:fileoff + filesize]))
                so = off + 72
                for _i in range(nsects):
                    sname = self.buf[so:so + 16].rstrip(b"\0").decode()
                    sseg = self.buf[so + 16:so + 32].rstrip(b"\0").decode()
                    addr, size = struct.unpack_from("<QQ", self.buf, so + 32)
                    soff = struct.unpack_from("<I", self.buf, so + 48)[0]
                    self.sections.append(Section(sseg, sname, addr, size, soff))
                    so += 80
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained_off = struct.unpack_from("<I", self.buf, off + 8)[0]
            elif cmd == LC_BUILD_VERSION:
                _plat, minos, sdk = struct.unpack_from("<III", self.buf, off + 8)
                self.minos = self._ver(minos)
                self.sdk = self._ver(sdk)
            off += cmdsize

    # ---------- flat memory ----------
    def _build_mem(self):
        for s in self.segments:
            if s.name in ("__PAGEZERO", "__LINKEDIT") or not s.vmsize:
                continue
            buf = bytearray(s.vmsize)
            buf[:len(s.data)] = s.data
            self.mem[s.name] = (s.vmaddr, buf)

    def _find(self, addr):
        for base, buf in self.mem.values():
            if base <= addr < base + len(buf):
                return base, buf
        return None, None

    def read(self, addr, n):
        base, buf = self._find(addr)
        if buf is None:
            return b""
        return bytes(buf[addr - base:addr - base + n])

    def read64(self, addr):
        d = self.read(addr, 8)
        return struct.unpack("<Q", d)[0] if len(d) == 8 else 0

    def read32(self, addr):
        d = self.read(addr, 4)
        return struct.unpack("<I", d)[0] if len(d) == 4 else 0

    def write64(self, addr, val):
        base, buf = self._find(addr)
        if buf is None:
            return False
        struct.pack_into("<Q", buf, addr - base, val & 0xFFFFFFFFFFFFFFFF)
        return True

    def cstr(self, addr, maxlen=256):
        d = self.read(addr, maxlen)
        i = d.find(b"\0")
        return d[:i if i >= 0 else maxlen].decode("utf-8", "replace")

    def section(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    # ---------- chained fixups ----------
    def _parse_fixups(self):
        b, h = self.buf, self.chained_off
        (_ver, starts_off, imports_off, symbols_off,
         imports_count, imports_format, _sf) = struct.unpack_from("<7I", b, h)
        for i in range(imports_count):
            if imports_format == 1:      # DYLD_CHAINED_IMPORT
                v = struct.unpack_from("<I", b, h + imports_off + i * 4)[0]
                name_off = v >> 9
            elif imports_format == 2:    # ADDEND
                v, _a = struct.unpack_from("<II", b, h + imports_off + i * 8)
                name_off = v >> 9
            else:                        # ADDEND64
                v = struct.unpack_from("<Q", b, h + imports_off + i * 16)[0]
                name_off = v >> 32
            p = h + symbols_off + name_off
            self.imports.append(b[p:b.index(b"\0", p)].decode())

        si = h + starts_off
        seg_count = struct.unpack_from("<I", b, si)[0]
        for so in struct.unpack_from(f"<{seg_count}I", b, si + 4):
            if so == 0:
                continue
            p = si + so
            _size, page_size, pf = struct.unpack_from("<IHH", b, p)
            seg_offset = struct.unpack_from("<Q", b, p + 8)[0]
            page_count = struct.unpack_from("<H", b, p + 20)[0]
            starts = struct.unpack_from(f"<{page_count}H", b, p + 22)
            self.ptr_format = pf
            for pi, ps in enumerate(starts):
                if ps != START_NONE:
                    self._walk(seg_offset + pi * page_size + ps, pf)

    def _walk(self, image_off, pf):
        addr = self.base + image_off
        stride = 8 if pf in ARM64E_FORMATS else 4
        while True:
            raw = self.read64(addr)
            if pf in ARM64E_FORMATS:
                auth = (raw >> 63) & 1
                bind = (raw >> 62) & 1
                nxt = (raw >> 51) & 0x7FF
                if bind:
                    ordinal = raw & (0xFFFFFF if pf == PTR_ARM64E_USERLAND24 else 0xFFFF)
                    addend = 0 if auth else ((raw >> 32) & 0x7FFFF)
                    self.binds.append((addr, ordinal, addend))
                elif auth:
                    target = raw & 0xFFFFFFFF          # offset from base
                    self.rebases.append((addr, self.base + target))
                else:
                    target = raw & 0x7FFFFFFFFFF       # 43 bits
                    high8 = (raw >> 43) & 0xFF
                    val = target if pf == PTR_ARM64E else self.base + target
                    self.rebases.append((addr, val + (high8 << 56)))
            else:
                bind = (raw >> 63) & 1
                nxt = (raw >> 51) & 0xFFF
                if bind:
                    self.binds.append((addr, raw & 0xFFFFFF, (raw >> 24) & 0xFF))
                else:
                    target = raw & 0xFFFFFFFFF
                    high8 = (raw >> 36) & 0xFF
                    val = target if pf == PTR_64 else self.base + target
                    self.rebases.append((addr, val + (high8 << 56)))
            if nxt == 0:
                break
            addr += nxt * stride

    # ---------- ObjC ----------
    def objc_classes(self):
        """yield (class_name, [(method_name, imp_addr), ...])"""
        sec = self.section("__objc_classlist")
        if not sec:
            return
        for i in range(sec.size // 8):
            cls = self.read64(sec.addr + i * 8)
            if not cls:
                continue
            yield self._class(cls)

    def _class(self, cls):
        data = self.read64(cls + 32) & ~7
        name = self.cstr(self.read64(data + 24))
        methods = self._methods(self.read64(data + 32))
        return name, methods

    def _methods(self, ml):
        out = []
        if not ml:
            return out
        entsize_flags = self.read32(ml)
        count = self.read32(ml + 4)
        entsize = entsize_flags & 0xFFFC
        small = bool(entsize_flags & 0x80000000)
        for i in range(min(count, 4096)):
            e = ml + 8 + i * entsize
            if small:
                nameoff = struct.unpack("<i", self.read(e, 4))[0]
                impoff = struct.unpack("<i", self.read(e + 8, 4))[0]
                # `name` is a relative ref to a selector-pointer slot
                selp = e + nameoff
                nm = self.cstr(self.read64(selp))
                imp = (e + 8 + impoff) & 0xFFFFFFFFFFFFFFFF
            else:
                nm = self.cstr(self.read64(e))
                imp = self.read64(e + 16)
            out.append((nm, imp))
        return out
