// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
#include <mbedtls/md.h>
#include <stdlib.h>
#include <string.h>

// HMAC computation
static int hmac_compute(mbedtls_md_type_t md_type,
                        const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t input_len,
                        unsigned char *output) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) return -1;

    return mbedtls_md_hmac(md_info, key, keylen, input, input_len, output);
}

// Get hash output size
static int get_md_size(mbedtls_md_type_t md_type) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
    if (md_info == NULL) return 0;
    return mbedtls_md_get_size(md_info);
}
*/
import "C"
import (
	"hash"
	"unsafe"
)

// hmacHash implements hash.Hash for HMAC
type hmacHash struct {
	hashType HashType
	key      []byte
	data     []byte
}

// NewHMAC creates a new HMAC hash with the given hash function and key
func NewHMAC(h func() hash.Hash, key []byte) hash.Hash {
	// Determine hash type from the function
	testHash := h()
	var hashType HashType
	switch testHash.Size() {
	case SHA1Size:
		hashType = HashSHA1
	case SHA256Size:
		hashType = HashSHA256
	case SHA384Size:
		hashType = HashSHA384
	case SHA512Size:
		hashType = HashSHA512
	default:
		panic("mbedtls: unsupported hash type for HMAC")
	}

	return NewHMACWithType(hashType, key)
}

// NewHMACWithType creates a new HMAC with explicit hash type
func NewHMACWithType(hashType HashType, key []byte) hash.Hash {
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &hmacHash{
		hashType: hashType,
		key:      keyCopy,
	}
}

func (h *hmacHash) getMdType() C.mbedtls_md_type_t {
	switch h.hashType {
	case HashSHA1:
		return C.MBEDTLS_MD_SHA1
	case HashSHA256:
		return C.MBEDTLS_MD_SHA256
	case HashSHA384:
		return C.MBEDTLS_MD_SHA384
	case HashSHA512:
		return C.MBEDTLS_MD_SHA512
	}
	return C.MBEDTLS_MD_NONE
}

func (h *hmacHash) Write(p []byte) (n int, err error) {
	h.data = append(h.data, p...)
	return len(p), nil
}

func (h *hmacHash) Sum(b []byte) []byte {
	mdType := h.getMdType()
	size := int(C.get_md_size(mdType))
	output := make([]byte, size)

	var inputPtr, keyPtr *C.uchar
	if len(h.data) > 0 {
		inputPtr = (*C.uchar)(unsafe.Pointer(&h.data[0]))
	}
	if len(h.key) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&h.key[0]))
	}

	ret := C.hmac_compute(
		mdType,
		keyPtr,
		C.size_t(len(h.key)),
		inputPtr,
		C.size_t(len(h.data)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
	)
	if ret != 0 {
		panic("mbedtls: HMAC computation failed")
	}

	return append(b, output...)
}

func (h *hmacHash) Reset() {
	h.data = nil
}

func (h *hmacHash) Size() int {
	return int(C.get_md_size(h.getMdType()))
}

func (h *hmacHash) BlockSize() int {
	switch h.hashType {
	case HashSHA1, HashSHA256:
		return 64
	case HashSHA384, HashSHA512:
		return 128
	}
	return 0
}
