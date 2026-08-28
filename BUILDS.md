# Pinning a build

## What actually needs pinning

The signer lives in `commerce`, a **plain executable on disk** at

```
/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce
```

It is *not* in the dyld shared cache. The CommerceKit framework dylib is in the
cache, but that is only the XPC shim — it contains no crypto. So the unit to
pin is a **macOS build**, and from it the on-disk `commerce` binary; there is
no need to carry a whole dyld shared cache around.

## Why it matters

Two things are build-specific:

1. **Entry point addresses.** These are no longer hardcoded — `sapunicorn/locate.py`
   recovers them from the ObjC metadata and disassembly of whatever binary you
   supply, and `EmuA64` reports drift against the reference build at load time.
   A macOS upgrade will move the addresses, and that is handled.

2. **Protocol behaviour.** The SAP version (`sign-sap-version`, currently 200),
   the handshake shape, and the host functions the blob calls could all change
   between releases. Nothing detects that automatically; it would surface as a
   handshake failure or a signature Apple rejects.

So: pin a build for reproducibility, but expect a different build to still work.

## Verified

| | |
|---|---|
| macOS | 26.4 (25E246) |
| slice | arm64e |
| `commerce` (thin arm64e) SHA-256 | `b8d99ab12ade93521b4501d5e0f8f4989acce078370990fa0b9565c041941db7` |
| `LC_BUILD_VERSION` minos / sdk | 26.4 / 26.4 |
| entry points | `ctx_init 0x1001108f8`, `proc_cert 0x10007a718`, `sign 0x1000c68ec`, `verify 0x10001fd8c` |
| status | full pipeline: context, both handshake legs, signature |

## Also examined, not verified end to end

| | |
|---|---|
| macOS | 27.0 (26A5368g) |
| `commerce` x86_64 slice SHA-256 | `03b051976f1d952dfd34df5159b2815f4c436c841287dcd352aafb3756534658` |
| `commerce` arm64e slice SHA-256 | `a58184f9617a700f59e2d5e4a3bdac5eaf6cc8cc3f6f6cd5105a96e632b6af93` |
| x86_64 entry points | `ctx_init 0x1000a2180`, `proc_cert 0x10002c580`, `sign 0x1000742a0`, `verify 0x100108450` |
| status | used for the static analysis only; never run to a signature |

## Getting a specific build without a Mac

`tools/extract.py` reads the local install. To pin a build you do not run,
take `commerce` out of an Apple installer or IPSW for that build — it is an
ordinary file inside the CommerceKit framework, so any tool that can mount or
unpack the system volume will do. Then:

```sh
lipo -thin arm64e commerce -output commerce.a64     # or use a Mach-O library
shasum -a 256 commerce.a64
```

Record the hash here when you verify a new build works.

Apple's binary is deliberately not distributed with this repository.
