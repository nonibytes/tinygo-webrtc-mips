# TinyGo WebRTC MIPS - Claude Memory

## Current Focus
OpenSSL CGO integration for TinyGo MIPS builds. The `cgo-openssl` branch contains the implementation.

## Project Facts
- **Purpose**: Build pion-webrtc for MIPS routers using TinyGo
- **Problem**: Go's crypto library uses assembly that TinyGo can't link on amd64/MIPS
- **Solution**: OpenSSL via CGO provides crypto primitives
- **Branch**: `cgo-openssl` - main development branch for OpenSSL integration

## Key Files

### OpenSSL Wrapper Package (`pkg/crypto/openssl/`)
| File | Purpose |
|------|---------|
| openssl.go | Init, version check, error handling |
| aes.go | cipher.Block interface |
| gcm.go | cipher.AEAD interface (AES-GCM) |
| cbc.go | cipher.BlockMode (AES-CBC) |
| ctr.go | cipher.Stream (AES-CTR) |
| ecdh.go | ECDH P-256, P-384, X25519 |
| sha.go | SHA-1/256/384/512 |
| hmac.go | HMAC with any hash |
| rand.go | crypto/rand.Reader replacement |

### Modified Pion Files (with build tags)
- `deps/dtls/pkg/crypto/ciphersuite/gcm.go` + `gcm_tinygo.go`
- `deps/dtls/pkg/crypto/ciphersuite/cbc.go` + `cbc_tinygo.go`
- `deps/dtls/pkg/crypto/ciphersuite/ccm.go` + `ccm_tinygo.go`
- `deps/dtls/pkg/crypto/elliptic/elliptic.go` + `elliptic_tinygo.go`
- `deps/dtls/pkg/crypto/prf/prf.go` + `prf_tinygo.go`
- `deps/dtls/pkg/crypto/hash/hash.go` + `hash_tinygo.go`
- `deps/dtls/pkg/crypto/ccm/ccm.go` + `ccm_tinygo.go`
- `deps/srtp/key_derivation.go` + `key_derivation_tinygo.go`
- `deps/srtp/srtp_cipher_aead_aes_gcm.go` + `srtp_cipher_aead_aes_gcm_tinygo.go`
- `deps/srtp/srtp_cipher_aes_cm_hmac_sha1.go` + `srtp_cipher_aes_cm_hmac_sha1_tinygo.go`

## Build Commands

### Standard Go (amd64) - Works
```bash
CGO_ENABLED=1 go build -v .
```

### TinyGo with CGO (when TinyGo is installed)
```bash
CGO_ENABLED=1 tinygo build -tags "cgo" -o webrtc-amd64 .
```

### Cross-compile for MIPS (requires MIPS toolchain + static OpenSSL)
```bash
# Install toolchain
sudo apt install crossbuild-essential-mips gcc-mips-linux-gnu

# Build static OpenSSL for MIPS
./Configure linux-mips32 --cross-compile-prefix=mips-linux-gnu- \
    --prefix=/opt/openssl-mips no-shared no-async no-dso -static
make -j$(nproc) && sudo make install

# Build with TinyGo
CGO_ENABLED=1 \
CC=mips-linux-gnu-gcc \
CGO_CFLAGS="-I/opt/openssl-mips/include" \
CGO_LDFLAGS="-L/opt/openssl-mips/lib -lssl -lcrypto -ldl -lpthread -latomic" \
GOOS=linux GOARCH=mips \
tinygo build -tags "cgo" -o webrtc-mips .
```

## Decisions
- Chose OpenSSL over mbedTLS because it has existing Go bindings
- Using build tags (`//go:build tinygo && cgo`) to separate implementations
- Original files get `//go:build !tinygo` so standard Go builds are unaffected

## Discovered Constraints
- TinyGo needs CGO for OpenSSL
- OpenSSL 3.0 deprecates EC_KEY API (warnings only, still works)
- Submodule changes need to be committed in submodules first

## User Preferences
- Production-ready build priority
- MIPS router deployment target

## Build Results
- **Standard Go MIPS**: 4.5MB static binary ✅
- **TinyGo MIPS**: Has musl header conflicts ❌ (use standard Go instead)
- **Build command**: `CGO_ENABLED=1 CC=mips-linux-gnu-gcc GOOS=linux GOARCH=mips go build -ldflags="-extldflags=-static" -o webrtc-mips-static .`

## Open Questions
- Need to test on real MIPS hardware or QEMU
