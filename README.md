# TinyGo WebRTC MIPS

Build pion/webrtc for MIPS routers with CGO crypto backends.

## Branches

| Branch | Crypto Backend | Status | Binary Size |
|--------|---------------|--------|-------------|
| `master` | Go stdlib | Base | - |
| `cgo-openssl` | OpenSSL | ✅ Working | 4.5MB |
| `cgo-mbedtls` | mbedTLS | ✅ Working | 4.5MB |

## Problem

Go's standard crypto library uses assembly optimizations that:
- TinyGo cannot link on amd64/MIPS
- Cause issues with 64-bit atomics on MIPS32

## Solution

Replace Go crypto with CGO wrappers around native crypto libraries:
- **OpenSSL**: Full-featured, widely available, ~4.5MB static binary
- **mbedTLS**: Lightweight, embedded-friendly, potentially smaller binary

## Quick Start

### Prerequisites
```bash
# Install MIPS cross-compiler
sudo apt install crossbuild-essential-mips

# Clone with submodules
git clone --recursive https://github.com/nonibytes/tinygo-webrtc-mips.git
cd tinygo-webrtc-mips
```

### Build for MIPS (OpenSSL branch)
```bash
git checkout cgo-openssl

# Static binary (4.5MB stripped)
CGO_ENABLED=1 CC=mips-linux-gnu-gcc GOOS=linux GOARCH=mips \
  go build -ldflags="-extldflags=-static" -o webrtc-mips .
mips-linux-gnu-strip webrtc-mips
```

### Build for MIPS (mbedTLS branch)
```bash
git checkout cgo-mbedtls

# Download and cross-compile mbedTLS
cd /tmp && wget https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.5.0.tar.gz -O mbedtls-3.5.0.tar.gz
tar xzf mbedtls-3.5.0.tar.gz && cd mbedtls-3.5.0
CC=mips-linux-gnu-gcc AR=mips-linux-gnu-ar make lib
mkdir -p /tmp/mbedtls-mips/lib /tmp/mbedtls-mips/include
cp library/*.a /tmp/mbedtls-mips/lib/
cp -r include/* /tmp/mbedtls-mips/include/

# Build static binary (4.5MB stripped)
cd /path/to/tinygo-webrtc-mips
CGO_ENABLED=1 CC=mips-linux-gnu-gcc GOOS=linux GOARCH=mips \
  go build -ldflags="-extldflags=-static" -o webrtc-mips .
mips-linux-gnu-strip webrtc-mips
```

## Project Structure

```
tinygo-webrtc-mips/
├── main.go                 # Entry point
├── go.mod                  # Module with replace directives
├── pkg/crypto/
│   ├── openssl/            # OpenSSL CGO wrappers (cgo-openssl branch)
│   └── mbedtls/            # mbedTLS CGO wrappers (cgo-mbedtls branch)
├── deps/                   # Pion submodules (modified with build tags)
│   ├── dtls/
│   ├── srtp/
│   └── ...
├── BUILD.md                # Detailed build instructions
└── CLAUDE.md               # Development notes
```

## Crypto Primitives Implemented

| Primitive | Interface | OpenSSL | mbedTLS |
|-----------|-----------|---------|---------|
| AES-128/256 | `cipher.Block` | ✅ | ✅ |
| AES-GCM | `cipher.AEAD` | ✅ | ✅ |
| AES-CBC | `cipher.BlockMode` | ✅ | ✅ |
| AES-CTR | `cipher.Stream` | ✅ | ✅ |
| ECDH P-256 | custom | ✅ | ✅ |
| ECDH X25519 | custom | ✅ | ❌ |
| SHA-1/256/384/512 | `hash.Hash` | ✅ | ✅ |
| HMAC | `hash.Hash` | ✅ | ✅ |
| CSPRNG | `io.Reader` | ✅ | ✅ |

## Testing

### With QEMU
```bash
sudo apt install qemu-user-static
qemu-mips-static ./webrtc-mips
```

### On Real Hardware
```bash
scp webrtc-mips root@router:/tmp/
ssh root@router '/tmp/webrtc-mips'
```

## License

MIT - See LICENSE file
