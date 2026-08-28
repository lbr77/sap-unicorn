"""Minimal Mach-O x86_64 loader with LC_DYLD_CHAINED_FIXUPS support.

Produces a flat memory image (segments at their vmaddr, no slide) with
rebases applied and bind slots redirected to synthetic import addresses.
"""

import struct
from collections import namedtuple

LC_SEGMENT_64 = 0x19
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_SYMTAB = 0x02

DYLD_CHAINED_PTR_64 = 2          # rebase target is an absolute (unslid) vmaddr
DYLD_CHAINED_PTR_64_OFFSET = 6   # rebase target is an offset from the image base
DYLD_CHAINED_PTR_START_NONE = 0xFFFF

Segment = namedtuple("Segment", "name vmaddr vmsize fileoff filesize initprot data")


class MachO:
    def __init__(self, path):
        self.buf = open(path, "rb").read()
        magic = struct.unpack_from("<I", self.buf, 0)[0]
        assert magic == 0xFEEDFACF, f"not a thin 64-bit Mach-O: {magic:#x}"
        (_, _, _, _, self.ncmds, _, _, _) = struct.unpack_from("<IiiIIIII", self.buf, 0)
        self.segments = []
        self.chained_off = None
        self.chained_size = None
        self._parse_cmds()
        self.base = min(s.vmaddr for s in self.segments if s.vmsize and s.name != "__PAGEZERO")
        self.imports = []          # list of symbol names, index = ordinal
        self.bind_sites = []       # (addr, ordinal, addend)
        self.rebase_sites = []     # (addr, target)
        self.ptr_format = None

    def _parse_cmds(self):
        off = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.buf, off)
            if cmd == LC_SEGMENT_64:
                name = self.buf[off + 8:off + 24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.buf, off + 24)
                maxprot, initprot = struct.unpack_from("<ii", self.buf, off + 56)
                data = self.buf[fileoff:fileoff + filesize]
                self.segments.append(Segment(name, vmaddr, vmsize, fileoff, filesize, initprot, data))
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained_off, self.chained_size = struct.unpack_from("<II", self.buf, off + 8)
            off += cmdsize

    # ---- chained fixups -------------------------------------------------
    def parse_fixups(self):
        if self.chained_off is None:
            return
        b = self.buf
        h = self.chained_off
        (fixups_version, starts_offset, imports_offset, symbols_offset,
         imports_count, imports_format, symbols_format) = struct.unpack_from("<7I", b, h)
        assert fixups_version == 0, fixups_version
        assert imports_format == 1, f"unsupported imports_format {imports_format}"

        # imports table
        for i in range(imports_count):
            v = struct.unpack_from("<I", b, h + imports_offset + i * 4)[0]
            lib_ordinal = v & 0xFF
            weak = (v >> 8) & 1
            name_off = v >> 9
            p = h + symbols_offset + name_off
            end = b.index(b"\0", p)
            self.imports.append((b[p:end].decode(), lib_ordinal, weak))

        # starts in image
        si = h + starts_offset
        seg_count = struct.unpack_from("<I", b, si)[0]
        seg_offs = struct.unpack_from(f"<{seg_count}I", b, si + 4)
        for segidx, so in enumerate(seg_offs):
            if so == 0:
                continue
            p = si + so
            size, page_size, ptr_format = struct.unpack_from("<IHH", b, p)
            segment_offset, max_valid_pointer = struct.unpack_from("<QI", b, p + 8)
            page_count = struct.unpack_from("<H", b, p + 20)[0]
            page_starts = struct.unpack_from(f"<{page_count}H", b, p + 22)
            assert ptr_format in (DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET), \
                f"ptr_format {ptr_format} unsupported"
            self.ptr_format = ptr_format
            for pi, ps in enumerate(page_starts):
                if ps == DYLD_CHAINED_PTR_START_NONE:
                    continue
                self._walk_chain(segment_offset + pi * page_size + ps, segidx)

    def _walk_chain(self, image_off, segidx):
        """image_off is an offset from the image base (first segment vmaddr)."""
        seg = None
        addr = self.base + image_off
        for s in self.segments:
            if s.vmaddr <= addr < s.vmaddr + s.vmsize:
                seg = s
                break
        if seg is None:
            return
        while True:
            fo = seg.fileoff + (addr - seg.vmaddr)
            raw = struct.unpack_from("<Q", self.buf, fo)[0]
            bind = (raw >> 63) & 1
            nxt = (raw >> 51) & 0xFFF
            if bind:
                ordinal = raw & 0xFFFFFF
                addend = (raw >> 24) & 0xFF
                self.bind_sites.append((addr, ordinal, addend))
            else:
                target = raw & 0xFFFFFFFFF          # 36 bits
                high8 = (raw >> 36) & 0xFF
                abs_ = target if self.ptr_format == DYLD_CHAINED_PTR_64 else self.base + target
                self.rebase_sites.append((addr, abs_ + (high8 << 56)))
            if nxt == 0:
                break
            addr += nxt * 4
