# TinyGo WebRTC for MIPS - Findings

## Overview

This project aims to build pion-webrtc with TinyGo for MIPS routers to achieve small binary sizes.

## TinyGo Net Package

TinyGo's `net` package uses a `netdev` abstraction designed for embedded devices (WiFi modules, etc.). For Linux targets, there's no built-in syscall-based netdev implementation.

### Added to TinyGo's net package:

1. **`/home/okecho/tinygo/src/net/udpsock_linux.go`** - ListenUDP using raw syscalls
   - Uses SYS_SOCKET, SYS_BIND, SYS_RECVFROM, SYS_SENDTO
   - Successfully compiled for MIPS (770KB binary in earlier tests)

2. **`/home/okecho/tinygo/src/net/tcpsock_linux.go`** - ListenTCP using raw syscalls
   - Uses SYS_SOCKET, SYS_BIND, SYS_LISTEN, SYS_ACCEPT
   - Mirrors the UDP implementation pattern

3. **`/home/okecho/tinygo/src/net/tlssock.go`** - Added HandshakeContext method
   - Required for ICE's TLS TURN code path to compile
   - Panics at runtime (TLS not fully implemented in TinyGo)

## Pion Patches

### deps/transport/stdnet/
- Added `!tinygo` build constraint to `net.go`
- Created `net_tinygo.go` stub that implements transport.Net interface

### deps/transport/vnet/
- Added `!tinygo` build constraint to all files
- Created `stub_tinygo.go` with stub types (vnet is for testing/simulation)

### deps/mdns/
- Added `!tinygo` build constraint to `config.go`, `conn.go`, `errors.go`, `mdns.go`
- Created `stub_tinygo.go` with:
  - `DefaultAddressIPv4` and `DefaultAddressIPv6` constants
  - `Config` struct
  - `Conn` type with `Query`, `QueryAddr`, `Close` methods
  - `Server` function (returns error)

### deps/ice/
- Added `!tinygo` build constraint to `mdns.go`
- Created `mdns_tinygo.go` with:
  - `MulticastDNSMode` type and constants
  - `generateMulticastDNSName` stub
  - `createMulticastDNS` stub (returns disabled mode)

### deps/dtls/
- Added `!tinygo` build constraint to `cipher_suite_go114.go` (uses tls.CipherSuite)

## Build Results

### ✅ ARM Linux Target - SUCCESS!

```bash
GOOS=linux GOARCH=arm tinygo build -o test-arm .
```

- **Binary size:** 5.7MB
- **Status:** Compiles successfully
- **Why it works:** ARM 32-bit uses pure Go crypto (no assembly optimizations like amd64/arm64)

### ❌ x86_64 Linux Target

```
crypto/aes/cipher_asm.go: linker could not find symbol crypto/aes.encryptBlockAsm
crypto/internal/nistec/p256_asm.go: linker could not find symbol crypto/internal/nistec.p256BigToLittle
... (many more crypto assembly symbols)
```

**Cause:** Go's crypto packages use assembly optimizations on amd64. TinyGo can't link assembly.

**Note:** The build constraint is `//go:build amd64 || arm64 || ppc64 || ppc64le` without checking for `purego` tag.

### ❌ MIPS Linux Target

```
sync/atomic/doc.go: linker could not find symbol __atomic_fetch_add_8
sync/atomic/doc.go: linker could not find symbol __atomic_store_8
```

**Cause:** MIPS 32-bit doesn't have native 64-bit atomic operations. These are provided by libatomic in GCC.

**Workaround attempt:**
```bash
GOOS=linux GOARCH=mips tinygo build -ldflags="-extldflags=-latomic" -o test-mips .
# Error: ld.lld: error: unable to find library -latomic
```

**Solution:** Need MIPS cross-compilation toolchain with libatomic:
```bash
sudo apt install crossbuild-essential-mips  # or similar for your distro
```

## Recommended Path Forward

### Option 1: CGO with mbedTLS

Use TinyGo's CGO support with C crypto libraries:
- mbedTLS for TLS/DTLS crypto
- Requires cross-compilation toolchain for MIPS

Benefits:
- Well-tested, production crypto
- Small binary size (mbedTLS is designed for embedded)
- Hardware acceleration support on some platforms

Challenges:
- Need MIPS cross-compilation setup (`crossbuild-essential-mips`)
- Some TinyGo CGO limitations

### Option 2: Pure Go Crypto Libraries

Replace standard library crypto with pure Go implementations:
- github.com/aead/chacha20 (ChaCha20)
- Custom AES implementation
- Custom elliptic curve implementation

Challenges:
- Performance impact
- Need to ensure security equivalence
- More code to maintain

### Option 3: WebAssembly Path

Build for WASM (browser handles crypto):
- Already working (906KB binary achieved)
- No crypto issues in WASM mode

Limitation: Only works in browser context, not standalone.

## File Modifications Summary

| File | Modification |
|------|-------------|
| TinyGo net/udpsock_linux.go | New - ListenUDP syscalls |
| TinyGo net/tcpsock_linux.go | New - ListenTCP syscalls |
| TinyGo net/tlssock.go | Added HandshakeContext |
| deps/transport/stdnet/net.go | Added !tinygo constraint |
| deps/transport/stdnet/net_tinygo.go | New - TinyGo stub |
| deps/transport/vnet/*.go | Added !tinygo constraint |
| deps/transport/vnet/stub_tinygo.go | New - TinyGo stub |
| deps/mdns/*.go | Added !tinygo constraint |
| deps/mdns/stub_tinygo.go | New - TinyGo stub |
| deps/ice/mdns.go | Added !tinygo constraint |
| deps/ice/mdns_tinygo.go | New - TinyGo stub |
| deps/dtls/cipher_suite_go114.go | Added !tinygo constraint |

## Helper Script

`/tmp/add_constraints.py` - Python script to batch-add build constraints to Go files

## TinyGo Build Info

```
LLVM triple:       x86_64-unknown-linux-musleabihf
build tags:        linux amd64 tinygo purego osusergo math_big_pure_go gc.precise scheduler.tasks serial.none
TinyGo version:    0.34.0
```

Note: TinyGo sets `purego` tag but Go standard library crypto doesn't respect it.

## Summary

| Target | Status | Size | Notes |
|--------|--------|------|-------|
| ARM Linux | ✅ Works | 5.7MB | Uses pure Go crypto |
| MIPS Linux | ❌ Needs libatomic | - | Need cross-toolchain |
| MIPSLE Linux | ❌ Needs libatomic | - | Need cross-toolchain |
| amd64 Linux | ❌ Crypto asm | - | Need pure Go crypto |
| i386 Linux | ❌ Missing syscalls | - | Syscall numbers differ |
| WASM | ❌ Missing ListenUDP | - | Need WASM stubs |

## Next Steps

1. Install MIPS cross-toolchain with libatomic for MIPS builds
2. Consider using CGO with mbedTLS for production crypto
3. Add WASM-specific networking stubs for browser target
4. Consider patching TinyGo's GOROOT to use pure Go crypto on amd64
