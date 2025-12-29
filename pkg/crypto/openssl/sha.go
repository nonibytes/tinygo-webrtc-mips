// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/evp.h>
#include <string.h>

// SHA-1 hash
static int sha1_sum(const unsigned char *data, size_t len, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned int outlen;
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

// SHA-256 hash
static int sha256_sum(const unsigned char *data, size_t len, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned int outlen;
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

// SHA-384 hash
static int sha384_sum(const unsigned char *data, size_t len, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned int outlen;
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

// SHA-512 hash
static int sha512_sum(const unsigned char *data, size_t len, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned int outlen;
    if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}
*/
import "C"
import (
	"hash"
	"unsafe"
)

// Hash sizes
const (
	SHA1Size   = 20
	SHA256Size = 32
	SHA384Size = 48
	SHA512Size = 64
)

// SHA1Sum computes SHA-1 hash
func SHA1Sum(data []byte) [SHA1Size]byte {
	var out [SHA1Size]byte

	if err := Init(); err != nil {
		panic("openssl/sha: init failed: " + err.Error())
	}

	clearErrors()

	var dataPtr *C.uchar
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}

	ret := C.sha1_sum(dataPtr, C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		panic("openssl/sha: SHA1 failed: " + getError().Error())
	}

	return out
}

// SHA256Sum computes SHA-256 hash
func SHA256Sum(data []byte) [SHA256Size]byte {
	var out [SHA256Size]byte

	if err := Init(); err != nil {
		panic("openssl/sha: init failed: " + err.Error())
	}

	clearErrors()

	var dataPtr *C.uchar
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}

	ret := C.sha256_sum(dataPtr, C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		panic("openssl/sha: SHA256 failed: " + getError().Error())
	}

	return out
}

// SHA384Sum computes SHA-384 hash
func SHA384Sum(data []byte) [SHA384Size]byte {
	var out [SHA384Size]byte

	if err := Init(); err != nil {
		panic("openssl/sha: init failed: " + err.Error())
	}

	clearErrors()

	var dataPtr *C.uchar
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}

	ret := C.sha384_sum(dataPtr, C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		panic("openssl/sha: SHA384 failed: " + getError().Error())
	}

	return out
}

// SHA512Sum computes SHA-512 hash
func SHA512Sum(data []byte) [SHA512Size]byte {
	var out [SHA512Size]byte

	if err := Init(); err != nil {
		panic("openssl/sha: init failed: " + err.Error())
	}

	clearErrors()

	var dataPtr *C.uchar
	if len(data) > 0 {
		dataPtr = (*C.uchar)(unsafe.Pointer(&data[0]))
	}

	ret := C.sha512_sum(dataPtr, C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&out[0])))
	if ret != 0 {
		panic("openssl/sha: SHA512 failed: " + getError().Error())
	}

	return out
}

// sha256Hash implements hash.Hash for SHA-256
type sha256Hash struct {
	data []byte
}

// NewSHA256 creates a new SHA-256 hash.Hash
func NewSHA256() hash.Hash {
	return &sha256Hash{}
}

func (h *sha256Hash) Write(p []byte) (n int, err error) {
	h.data = append(h.data, p...)
	return len(p), nil
}

func (h *sha256Hash) Sum(b []byte) []byte {
	sum := SHA256Sum(h.data)
	return append(b, sum[:]...)
}

func (h *sha256Hash) Reset() {
	h.data = h.data[:0]
}

func (h *sha256Hash) Size() int {
	return SHA256Size
}

func (h *sha256Hash) BlockSize() int {
	return 64
}

// sha1Hash implements hash.Hash for SHA-1
type sha1Hash struct {
	data []byte
}

// NewSHA1 creates a new SHA-1 hash.Hash
func NewSHA1() hash.Hash {
	return &sha1Hash{}
}

func (h *sha1Hash) Write(p []byte) (n int, err error) {
	h.data = append(h.data, p...)
	return len(p), nil
}

func (h *sha1Hash) Sum(b []byte) []byte {
	sum := SHA1Sum(h.data)
	return append(b, sum[:]...)
}

func (h *sha1Hash) Reset() {
	h.data = h.data[:0]
}

func (h *sha1Hash) Size() int {
	return SHA1Size
}

func (h *sha1Hash) BlockSize() int {
	return 64
}

// sha384Hash implements hash.Hash for SHA-384
type sha384Hash struct {
	data []byte
}

// NewSHA384 creates a new SHA-384 hash.Hash
func NewSHA384() hash.Hash {
	return &sha384Hash{}
}

func (h *sha384Hash) Write(p []byte) (n int, err error) {
	h.data = append(h.data, p...)
	return len(p), nil
}

func (h *sha384Hash) Sum(b []byte) []byte {
	sum := SHA384Sum(h.data)
	return append(b, sum[:]...)
}

func (h *sha384Hash) Reset() {
	h.data = h.data[:0]
}

func (h *sha384Hash) Size() int {
	return SHA384Size
}

func (h *sha384Hash) BlockSize() int {
	return 128
}
