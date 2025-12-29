// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <stdlib.h>
#include <string.h>

// SHA-1
static void sha1_sum(const unsigned char *input, size_t len, unsigned char *output) {
    mbedtls_sha1(input, len, output);
}

// SHA-256
static void sha256_sum(const unsigned char *input, size_t len, unsigned char *output) {
    mbedtls_sha256(input, len, output, 0);
}

// SHA-384
static void sha384_sum(const unsigned char *input, size_t len, unsigned char *output) {
    mbedtls_sha512(input, len, output, 1);
}

// SHA-512
static void sha512_sum(const unsigned char *input, size_t len, unsigned char *output) {
    mbedtls_sha512(input, len, output, 0);
}
*/
import "C"
import (
	"hash"
	"unsafe"
)

// Hash type constants
type HashType int

const (
	HashSHA1 HashType = iota
	HashSHA256
	HashSHA384
	HashSHA512
)

// Hash sizes
const (
	SHA1Size   = 20
	SHA256Size = 32
	SHA384Size = 48
	SHA512Size = 64
)

// shaHash implements hash.Hash
type shaHash struct {
	hashType HashType
	data     []byte
}

// NewSHA1 creates a new SHA-1 hash
func NewSHA1() hash.Hash {
	return &shaHash{hashType: HashSHA1}
}

// NewSHA256 creates a new SHA-256 hash
func NewSHA256() hash.Hash {
	return &shaHash{hashType: HashSHA256}
}

// NewSHA384 creates a new SHA-384 hash
func NewSHA384() hash.Hash {
	return &shaHash{hashType: HashSHA384}
}

// NewSHA512 creates a new SHA-512 hash
func NewSHA512() hash.Hash {
	return &shaHash{hashType: HashSHA512}
}

func (h *shaHash) Write(p []byte) (n int, err error) {
	h.data = append(h.data, p...)
	return len(p), nil
}

func (h *shaHash) Sum(b []byte) []byte {
	var output []byte
	var inputPtr *C.uchar

	if len(h.data) > 0 {
		inputPtr = (*C.uchar)(unsafe.Pointer(&h.data[0]))
	}

	switch h.hashType {
	case HashSHA1:
		output = make([]byte, SHA1Size)
		C.sha1_sum(inputPtr, C.size_t(len(h.data)), (*C.uchar)(unsafe.Pointer(&output[0])))
	case HashSHA256:
		output = make([]byte, SHA256Size)
		C.sha256_sum(inputPtr, C.size_t(len(h.data)), (*C.uchar)(unsafe.Pointer(&output[0])))
	case HashSHA384:
		output = make([]byte, SHA384Size)
		C.sha384_sum(inputPtr, C.size_t(len(h.data)), (*C.uchar)(unsafe.Pointer(&output[0])))
	case HashSHA512:
		output = make([]byte, SHA512Size)
		C.sha512_sum(inputPtr, C.size_t(len(h.data)), (*C.uchar)(unsafe.Pointer(&output[0])))
	}

	return append(b, output...)
}

func (h *shaHash) Reset() {
	h.data = nil
}

func (h *shaHash) Size() int {
	switch h.hashType {
	case HashSHA1:
		return SHA1Size
	case HashSHA256:
		return SHA256Size
	case HashSHA384:
		return SHA384Size
	case HashSHA512:
		return SHA512Size
	}
	return 0
}

func (h *shaHash) BlockSize() int {
	switch h.hashType {
	case HashSHA1, HashSHA256:
		return 64
	case HashSHA384, HashSHA512:
		return 128
	}
	return 0
}

// Sum256 returns the SHA-256 checksum of the data
func Sum256(data []byte) [32]byte {
	var result [32]byte
	var inputPtr *C.uchar
	if len(data) > 0 {
		inputPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	C.sha256_sum(inputPtr, C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&result[0])))
	return result
}

// Sum384 returns the SHA-384 checksum of the data
func Sum384(data []byte) [48]byte {
	var result [48]byte
	var inputPtr *C.uchar
	if len(data) > 0 {
		inputPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	C.sha384_sum(inputPtr, C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&result[0])))
	return result
}

// Sum512 returns the SHA-512 checksum of the data
func Sum512(data []byte) [64]byte {
	var result [64]byte
	var inputPtr *C.uchar
	if len(data) > 0 {
		inputPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}
	C.sha512_sum(inputPtr, C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&result[0])))
	return result
}
