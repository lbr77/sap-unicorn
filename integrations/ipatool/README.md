# ipatool integration

Makes [ipatool](https://github.com/majd/ipatool) /
[ipatool-sapfix](https://github.com/maksimryabkin/ipatool-sapfix) fetch its
`X-Apple-ActionSignature` from a `sap-unicorn` server over HTTP instead of from
CommerceKit, which removes the macOS requirement.

Only the login request is affected — it is the only place in ipatool that sets
`SignAction: true`.

## Apply

```sh
cd /path/to/ipatool-sapfix
git apply /path/to/sap-unicorn/integrations/ipatool/0001-fetch-sap-signature-over-http.patch
go build ./...
```

The patch adds `pkg/mescal/signer_remote.go` and changes one line in
`pkg/appstore/appstore.go`:

```diff
 	clientArgs := http.Args{
 		CookieJar:    args.CookieJar,
-		ActionSigner: mescal.Sign,
+		ActionSigner: mescal.Signer(),
 	}
```

`signer_remote.go` carries no build tags, so it compiles everywhere, and
`Signer()` falls back to the existing platform `Sign` when the environment
variable is unset — the native macOS path is untouched.

Verified to apply cleanly against ipatool-sapfix `6fb420d`.

## Use

```sh
# on a machine holding the extracted binary
python server.py --binary commerce.a64 --port 8099

# wherever ipatool runs
export IPATOOL_SAP_SIGNER_URL=http://127.0.0.1:8099
ipatool auth login -e you@example.com -p ...
```

## GUID consistency

The SAP session is bound to a MAC address, and Apple receives that same value
as `guid` inside the signed payload. `signer_remote.go` therefore derives the
GUID with exactly the logic `pkg/util/machine` uses — first interface with a
non-empty hardware address, uppercased, colons stripped — and sends it to the
server, which keeps one session per GUID. Client and payload stay in sync
automatically; nothing needs configuring.

If ipatool runs somewhere without a usable MAC (some containers), give the
container one, or the `guid` in the payload and the SAP session will disagree.

## Status

The server side is tested and working, and the patch is verified to apply. The
Go code itself is **written but never compiled** — no Go toolchain was
available on the machine that produced it, so treat it as a starting point
rather than something known to build.

The remaining unknown for the whole project: whether Apple's authentication
endpoint actually accepts these signatures on a real login. That test needs
real credentials and has not been run.
