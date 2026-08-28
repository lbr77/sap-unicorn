"""Derive the SAP entry points from a `commerce` binary.

The addresses are build-specific, so rather than pinning them to one macOS
release we recover them the same way they were found by hand: walk the ObjC
metadata to the SigningSession methods, then take the calls that leave the
daemon's own code and land in the statically linked FairPlay blob.
"""

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

from .macho64 import Image


class LocateError(RuntimeError):
    pass


def _method_ranges(im):
    """imp address -> (name, end address), end taken from the next method."""
    methods = {}
    for cls, sels in im.objc_classes():
        for sel, imp in sels:
            if imp:
                methods[imp] = f"-[{cls} {sel}]"
    ordered = sorted(methods)
    out = {}
    for i, imp in enumerate(ordered):
        end = ordered[i + 1] if i + 1 < len(ordered) else imp + 0x1000
        out[methods[imp]] = (imp, end)
    return out


def _blob_calls(im, md, lo, hi, stub_lo, stub_hi):
    """Direct calls in [lo, hi) that leave the daemon's code for the blob."""
    hits = []
    for ins in md.disasm(im.read(lo, hi - lo), lo):
        if ins.mnemonic != "bl" or not ins.op_str.startswith("#"):
            continue
        target = int(ins.op_str[1:], 16)
        if stub_lo <= target < stub_hi:
            continue
        if lo <= target < hi:            # local branch, not a blob entry
            continue
        hits.append(target)
    return hits


def locate(im):
    """Return {'ctx_init', 'proc_cert', 'sign', 'verify'} for this image."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

    stubs = im.section("__auth_stubs")
    objc_stubs = im.section("__objc_stubs")
    if not stubs or not objc_stubs:
        raise LocateError("expected __auth_stubs and __objc_stubs (arm64e build?)")
    stub_lo = min(stubs.addr, objc_stubs.addr)
    stub_hi = max(stubs.addr + stubs.size, objc_stubs.addr + objc_stubs.size)

    ranges = _method_ranges(im)

    def calls(sel):
        if sel not in ranges:
            raise LocateError(f"method not found in ObjC metadata: {sel}")
        lo, hi = ranges[sel]
        return _blob_calls(im, md, lo, hi, stub_lo, stub_hi)

    open_calls = calls("-[SigningSession _openSessionWithType:withCompletionHandler:]")
    sign_calls = calls("-[SigningSession signData:error:]")
    verify_calls = calls("-[SigningSession processSignature:]")

    # The open path calls context-init once and the handshake twice (once for
    # Apple's certificate, once for Apple's reply).
    handshake = [a for a in open_calls if open_calls.count(a) > 1]
    if not handshake:
        raise LocateError("could not identify the handshake entry point")
    proc_cert = handshake[0]
    ctx_candidates = [a for a in open_calls if a != proc_cert]
    if not ctx_candidates:
        raise LocateError("could not identify the context-init entry point")
    ctx_init = ctx_candidates[0]

    if not sign_calls:
        raise LocateError("could not identify the sign entry point")

    return {
        "ctx_init": ctx_init,
        "proc_cert": proc_cert,
        "sign": sign_calls[0],
        "verify": verify_calls[0] if verify_calls else None,
    }


def locate_path(path):
    return locate(Image(path))
