# sap-unicorn

Running Apple's FairPlay **SAP** (Secure Association Protocol) signer under
[Unicorn](https://www.unicorn-engine.org/), so that an
`X-Apple-ActionSignature` header can be produced on any platform — not just
macOS.

The signing code is an obfuscated, statically linked FairPlay library inside the
macOS `commerce` daemon. This project loads that code into an emulator, drives
the SAP handshake against Apple's servers over plain HTTPS, and then signs
arbitrary payloads locally.

## Status

Working end to end on the arm64e slice:

```
ctx_init                       rc=0     261,784 basic blocks
handshake leg 1 (setup cert)   rc=0     911,512 blocks  -> 354-byte setup buffer
POST -> fpinit.itunes.apple.com          HTTP 200       -> 1428-byte response
handshake leg 2 (response)     rc=0      10,678 blocks  -> session established
sign                           rc=0     155,639 blocks  -> 501-byte signature
```

**Not yet verified:** whether Apple's authentication endpoint accepts the
resulting signature on a real login. The handshake is accepted by Apple's
server and the signature is produced without error, but the final end-to-end
acceptance test needs real credentials and has not been run.

## Why this is possible

The SAP core turns out to need almost nothing from the host:

| | |
|---|---|
| Host functions | `malloc`, `free`, `arc4random`, `gettimeofday`, `pthread_once`, `sysctlbyname`, `__chkstk_darwin` |
| Syscalls | none |
| Filesystem | none |
| XPC / IOKit / Security.framework | none |
| MAC address | passed in as a parameter, not read by the blob |
| Secure Enclave | not involved (only the unrelated Touch ID path uses it) |

The signature is **not** obtained from Apple. The two network legs are a key
agreement; once the session exists, signing is entirely local and offline, and
the payload never leaves the machine.

## Where the code lives

`CKSigningSession` in CommerceKit is a thin XPC shim with no crypto in it. It
forwards to the `com.apple.commerce` LaunchAgent, and the real work happens in
`commerce`'s statically linked FairPlay blob. Four entry points are reachable
from `SigningSession`:

| | arm64e | x86_64 | signature |
|---|---|---|---|
| context init | `0x1001108f8` | `0x1000a2180` | `(&ctx, &hwInfo)` |
| handshake | `0x10007a718` | `0x10002c580` | `(sapVersion, &hwInfo, ctx, buf, len, &out, &outlen, &flag)` |
| **sign** | `0x1000c68ec` | `0x1000742a0` | `(ctx, data, len, &out, &outlen)` |
| verify | `0x10001fd8c` | `0x100108450` | response direction |

`hwInfo` is `FairPlayHWInfo_ { uint32 IDLength; uint8 ID[20] }`, the ID being
the 6-byte primary MAC address. `sapVersion` is 200, from the bag key
`sign-sap-version`.

Addresses are build-specific and are **recovered at load time** by
`sapunicorn/locate.py`, which walks the ObjC metadata to the `SigningSession`
methods and takes the calls that leave the daemon's code for the blob. The
values above are the reference build; drift is reported, not fatal. See
[BUILDS.md](BUILDS.md) for what a macOS upgrade can and cannot break.

## Bag keys

CommerceKit resolves its endpoints through the **versioned** bag at
`https://init.itunes.apple.com/bag.xml?ix=6` (the unversioned `bag.xml` that
ipatool uses does not carry these keys):

| key | value |
|---|---|
| `sign-sap-setup-cert` | `https://s.mzstatic.com/sap/setupCert.plist` |
| `sign-sap-setup` | `https://fpinit.itunes.apple.com/v1/signSapSetup/legacy` |
| `sign-sap-version` | `200` |

The setup certificate is a static, unauthenticated file on Apple's CDN.

## The obfuscation

Control-flow flattening with computed-goto dispatch, not a bytecode VM. Every
basic block ends by folding a `setcc` predicate into a state register, indexing
an `int32` offset table and branching indirectly. There is no central
dispatcher and no interpreter loop — 277k native instructions across 235
functions, with MBA opaque predicates, S-box-style index lookups, a
runtime-mutating global state that doubles as a control-flow integrity check
(sentinel `0x29A0ECA1`), and function pointers stored biased by `-6`/`-2`.

Because the dispatch is computed at runtime, static call-graph analysis stops
after ~23 functions while real execution covers hundreds of thousands of blocks.

## Emulation notes

Three things had to be right, and each looked like a FairPlay error until it
wasn't:

1. **`pthread_once` must return 0.** Tail-jumping into the init routine so its
   `ret` lands back at the caller leaks the init routine's return value out as
   `pthread_once`'s. The blob checks it (`cmp w0, #0`) and bails. Run the init
   with `LR` pointing at a trampoline that forces `x0 = 0`.
2. **The default Unicorn ARM64 CPU model is not enough.** The blob uses
   ARMv8.2-SHA3 (`eor3`); use `UC_CPU_ARM64_MAX`.
3. **`__chkstk_darwin` must not clobber argument registers.** A generic
   "return 0" stub destroys `x0`, i.e. the `ctx` argument.

Pointer authentication is stripped rather than emulated: 11,098 instructions
are rewritten (`braa`→`br`, `blraa`→`blr`, `retab`→`ret`, `pac*`/`aut*`→`nop`).
Signing and authentication are removed together, so pointers stay plain and
PAuth support is not required.

`sysctlbyname("kern.hv_vmm_present")` is a VM-detection probe; returning 0
answers "not virtualised".

## Usage

```sh
pip install -r requirements.txt

# pull the binary off your own Mac (never redistributed here)
python tools/extract.py commerce.a64

# sign something
python sign.py --mac AABBCCDDEEFF --in payload.plist
```

The MAC bound into the SAP session should match the `guid` sent in the login
payload, in case Apple cross-checks them.

As a service (one SAP session per GUID, reused across requests):

```sh
python server.py --binary commerce.a64 --port 8099
curl -s -H 'Accept: base64' --data-binary @payload.plist \
     'http://127.0.0.1:8099/sign?guid=AABBCCDDEEFF'
```

Measured on an M-series Mac: ~2.3 s for the first signature of a GUID (two
network round-trips for the handshake), ~0.11 s for each one after that. See
`integrations/ipatool/` for wiring this into ipatool.

Programmatic use:

```python
from sapunicorn.session import SapSession

s = SapSession(binary="commerce.a64", mac="aabbccddeeff")
sig = s.sign(payload_bytes)      # reuse the session for many signatures
```

## Layout

```
sapunicorn/macho64.py   Mach-O loader: chained fixups (x86_64 + arm64e), ObjC metadata
sapunicorn/locate.py    recovers the SAP entry points from any build
sapunicorn/emu_a64.py   Unicorn harness, PAC stripping, host-function stubs
sapunicorn/session.py   SAP handshake + signing
sign.py                 one-shot CLI
server.py               HTTP signing service
tools/extract.py        pull commerce out of the local system
tools/locate.py         find the SAP entry points on your build
tools/entrypoints.py    every daemon -> blob call edge
tools/disasm.py         arm64 disassembly helper
tools/pacscan.py        survey pointer-authentication usage
integrations/ipatool/   patch making ipatool fetch signatures over HTTP
experimental/           x86_64 loader and harness; reaches the same point but
                        the three fixes above have not been ported to it
```

## Scope

Interoperability research on Apple's own client code, done on hardware the
author owns. No Apple binary is redistributed here — `tools/extract.py` takes
it from your own macOS install, and `.gitignore` keeps it out of the repo.

Related: [ipatool](https://github.com/majd/ipatool) and
[ipatool-sapfix](https://github.com/maksimryabkin/ipatool-sapfix), which reach
the same signer through CommerceKit and therefore only run on macOS.
