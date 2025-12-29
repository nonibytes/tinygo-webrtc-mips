// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

// HMAC-SHA1
static int hmac_sha1(const unsigned char *key, int keylen,
                     const unsigned char *data, int datalen,
                     unsigned char *out, unsigned int *outlen) {
    unsigned char *result = HMAC(EVP_sha1(), key, keylen, data, datalen, out, outlen);
    return result != NULL ? 0 : -1;
}

// HMAC-SHA256
static int hmac_sha256(const unsigned char *key, int keylen,
                       const unsigned char *data, int datalen,
                       unsigned char *out, unsigned int *outlen) {
    unsigned char *result = HMAC(EVP_sha256(), key, keylen, data, datalen, out, outlen);
    return result != NULL ? 0 : -1;
}

// HMAC-SHA384
static int hmac_sha384(const unsigned char *key, int keylen,
                       const unsigned char *data, int datalen,
                       unsigned char *out, unsigned int *outlen) {
    unsigned char *result = HMAC(EVP_sha384(), key, keylen, data, datalen, out, outlen);
    return result != NULL ? 0 : -1;
}

// HMAC-SHA512
static int hmac_sha512(const unsigned char *key, int keylen,
                       const unsigned char *data, int datalen,
                       unsigned char *out, unsigned int *outlen) {
    unsigned char *result = HMAC(EVP_sha512(), key, keylen, data, datalen, out, outlen);
    return result != NULL ? 0 : -1;
}
*/
import "C"
import (
	"hash"
	"unsafe"
)

// HashType represents the hash algorithm to use
type HashType int

const (
	HashSHA1 HashType = iota
	HashSHA256
	HashSHA384
	HashSHA512
)

// hmacState implements hash.Hash for HMAC
type hmacState struct {
	key      []byte
	data     []byte
	hashType HashType
	size     int
}

// NewHMAC creates a new HMAC hash.Hash
func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	if err := Init(); err != nil {
		panic("openssl/hmac: init failed: " + err.Error())
	}

	// Determine hash type by calling h() and checking size
	testHash := h()
	size := testHash.Size()

	var hashType HashType
	switch size {
	case SHA1Size:
		hashType = HashSHA1
	case SHA256Size:
		hashType = HashSHA256
	case SHA384Size:
		hashType = HashSHA384
	case SHA512Size:
		hashType = HashSHA512
	default:
		panic("openssl/hmac: unsupported hash size")
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &hmacState{
		key:      keyCopy,
		hashType: hashType,
		size:     size,
	}
}

// NewHMACWithType creates HMAC with explicit hash type
func NewHMACWithType(hashType HashType, key []byte) hash.Hash {
	if err := Init(); err != nil {
		panic("openssl/hmac: init failed: " + err.Error())
	}

	var size int
	switch hashType {
	case HashSHA1:
		size = SHA1Size
	case HashSHA256:
		size = SHA256Size
	case HashSHA384:
		size = SHA384Size
	case HashSHA512:
		size = SHA512Size
	default:
		panic("openssl/hmac: unsupported hash type")
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &hmacState{
		key:      keyCopy,
		hashType: hashType,
		size:     size,
	}
}

func (h *hmacState) Write(p []byte) (n int, err error) {
	h.data = append(h.data, p...)
	return len(p), nil
}

func (h *hmacState) Sum(b []byte) []byte {
	clearErrors()

	out := make([]byte, h.size)
	var outlen C.uint

	var keyPtr, dataPtr *C.uchar
	if len(h.key) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&h.key[0]))
	}
	if len(h.data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&h.data[0]))
	}

	var ret C.int
	switch h.hashType {
	case HashSHA1:
		ret = C.hmac_sha1(keyPtr, C.int(len(h.key)), dataPtr, C.int(len(h.data)),
			(*C.uchar)(unsafe.Pointer(&out[0])), &outlen)
	case HashSHA256:
		ret = C.hmac_sha256(keyPtr, C.int(len(h.key)), dataPtr, C.int(len(h.data)),
			(*C.uchar)(unsafe.Pointer(&out[0])), &outlen)
	case HashSHA384:
		ret = C.hmac_sha384(keyPtr, C.int(len(h.key)), dataPtr, C.int(len(h.data)),
			(*C.uchar)(unsafe.Pointer(&out[0])), &outlen)
	case HashSHA512:
		ret = C.hmac_sha512(keyPtr, C.int(len(h.key)), dataPtr, C.int(len(h.data)),
			(*C.uchar)(unsafe.Pointer(&out[0])), &outlen)
	}

	if ret != 0 {
		panic("openssl/hmac: HMAC failed: " + getError().Error())
	}

	return append(b, out[:outlen]...)
}

func (h *hmacState) Reset() {
	h.data = h.data[:0]
}

func (h *hmacState) Size() int {
	return h.size
}

func (h *hmacState) BlockSize() int {
	switch h.hashType {
	case HashSHA1, HashSHA256:
		return 64
	case HashSHA384, HashSHA512:
		return 128
	default:
		return 64
	}
}

// HMACSHA1 computes HMAC-SHA1 directly
func HMACSHA1(key, data []byte) []byte {
	h := NewHMACWithType(HashSHA1, key)
	h.Write(data)
	return h.Sum(nil)
}

// HMACSHA256 computes HMAC-SHA256 directly
func HMACSHA256(key, data []byte) []byte {
	h := NewHMACWithType(HashSHA256, key)
	h.Write(data)
	return h.Sum(nil)
}
