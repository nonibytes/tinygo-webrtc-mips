# TinyGo WebRTC MIPS - Build Instructions

Complete guide to building pion-webrtc for MIPS routers using TinyGo and OpenSSL CGO.

## Prerequisites

### 1. Install Go (1.22+)
```bash
# Already installed if you cloned this repo
go version
```

### 2. Install TinyGo
```bash
# Download TinyGo 0.34.0
wget https://github.com/tinygo-org/tinygo/releases/download/v0.34.0/tinygo_0.34.0_amd64.deb -O /tmp/tinygo.deb
sudo dpkg -i /tmp/tinygo.deb

# Verify
tinygo version
```

### 3. Install MIPS Cross-Compiler
```bash
sudo apt install crossbuild-essential-mips

# Verify
mips-linux-gnu-gcc --version
```

### 4. Build OpenSSL for MIPS (Static)
```bash
# Download OpenSSL 3.0.13
cd /tmp
wget https://www.openssl.org/source/openssl-3.0.13.tar.gz
tar xzf openssl-3.0.13.tar.gz
cd openssl-3.0.13

# Configure for MIPS32 static build
./Configure linux-mips32 \
    --cross-compile-prefix=mips-linux-gnu- \
    --prefix=/opt/openssl-mips \
    no-shared no-async no-dso -static

# Build (takes ~5 minutes)
make -j4

# Install (requires sudo for /opt)
sudo make install

# Or install to user directory:
make install DESTDIR=$HOME/openssl-mips-install
```

**Library locations after install:**
- Headers: `/opt/openssl-mips/include/`
- Libraries: `/opt/openssl-mips/lib/libcrypto.a`, `/opt/openssl-mips/lib/libssl.a`

## Building

### Standard Go Build (amd64, for testing)
```bash
cd /path/to/tinygo-webrtc-mips

# Build with system OpenSSL
CGO_ENABLED=1 go build -v -o webrtc-amd64 .

# Test run
./webrtc-amd64
```

### TinyGo Build (amd64, with CGO)
```bash
CGO_ENABLED=1 tinygo build \
    -tags "cgo" \
    -o webrtc-tinygo-amd64 \
    .
```

### Standard Go Cross-Compile for MIPS (Recommended)
```bash
# Dynamic linking (5.3MB)
CGO_ENABLED=1 CC=mips-linux-gnu-gcc GOOS=linux GOARCH=mips \
    go build -v -o webrtc-mips .

# Static linking (6.1MB, recommended for routers)
CGO_ENABLED=1 CC=mips-linux-gnu-gcc GOOS=linux GOARCH=mips \
    go build -ldflags="-extldflags=-static" -o webrtc-mips-static .

# Strip debug symbols (reduces to 4.5MB)
mips-linux-gnu-strip webrtc-mips-static

# Verify binary
file webrtc-mips-static
# Expected: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked...
```

### TinyGo Cross-Compile for MIPS (Experimental)
TinyGo CGO cross-compilation for MIPS has musl header issues. Use standard Go instead.

```bash
# TinyGo amd64 build works
CGO_ENABLED=1 tinygo build -tags "cgo" -o webrtc-tinygo-amd64 .

# MIPS cross-compilation has musl/limits.h conflicts
# Use standard Go cross-compilation above
```

## Project Structure

```
tinygo-webrtc-mips/
├── main.go                 # Entry point
├── go.mod                  # Module with replace directives
├── pkg/crypto/openssl/     # OpenSSL CGO wrappers
│   ├── openssl.go          # Init, errors
│   ├── aes.go              # cipher.Block
│   ├── gcm.go              # cipher.AEAD (AES-GCM)
│   ├── cbc.go              # cipher.BlockMode (AES-CBC)
│   ├── ctr.go              # cipher.Stream (AES-CTR)
│   ├── ecdh.go             # ECDH P-256, P-384, X25519
│   ├── sha.go              # SHA-1/256/384/512
│   ├── hmac.go             # HMAC
│   └── rand.go             # crypto/rand replacement
├── deps/                   # Pion submodules (modified)
│   ├── dtls/               # DTLS with TinyGo support
│   ├── srtp/               # SRTP with TinyGo support
│   └── ...
└── BUILD.md                # This file
```

## Build Tags

The project uses build tags to separate implementations:

| Tag | When Used |
|-----|-----------|
| `!tinygo` | Standard Go builds (uses Go crypto) |
| `tinygo && cgo` | TinyGo builds (uses OpenSSL) |

Files follow the pattern:
- `somefile.go` - Original with `//go:build !tinygo`
- `somefile_tinygo.go` - TinyGo version with `//go:build tinygo && cgo`

## Troubleshooting

### "undefined: encryptBlockAsm"
This means Go's crypto assembly isn't available. Use the TinyGo build with CGO.

### "cannot find -lssl" or "-lcrypto"
OpenSSL libraries not found. Check:
```bash
ls -la /opt/openssl-mips/lib/*.a
```

### OpenSSL deprecation warnings
Normal for OpenSSL 3.0 - uses deprecated EC_KEY API. Build still succeeds.

### "getaddrinfo" warnings during OpenSSL build
Normal for static builds. The crypto functions don't use networking.

## Testing on MIPS

### Using QEMU
```bash
# Install QEMU user-mode emulation
sudo apt install qemu-user-static

# Run MIPS binary
qemu-mips-static ./webrtc-mips
```

### On Real Hardware
```bash
# Copy to router
scp webrtc-mips root@router:/tmp/

# SSH and run
ssh root@router
chmod +x /tmp/webrtc-mips
/tmp/webrtc-mips
```

## Reproducibility Checklist

1. [ ] Go 1.22+ installed
2. [ ] MIPS cross-compiler installed (`sudo apt install crossbuild-essential-mips`)
3. [ ] Submodules initialized (`git submodule update --init`)
4. [ ] On `cgo-openssl` branch
5. [ ] Build: `CGO_ENABLED=1 CC=mips-linux-gnu-gcc GOOS=linux GOARCH=mips go build -ldflags="-extldflags=-static" -o webrtc-mips-static .`
6. [ ] Strip: `mips-linux-gnu-strip webrtc-mips-static`

**Note**: TinyGo and cross-compiled OpenSSL are NOT required for standard Go MIPS builds.

## Version Information

| Component | Version |
|-----------|---------|
| Go | 1.22+ |
| TinyGo | 0.34.0 |
| OpenSSL | 3.0.13 |
| pion/webrtc | v4.0.0 |
| MIPS GCC | 12.4.0 |
