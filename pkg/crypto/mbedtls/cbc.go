// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
#include <mbedtls/aes.h>
#include <stdlib.h>
#include <string.h>

// CBC encrypt
static int aes_cbc_encrypt(const unsigned char *key, int keylen,
                           unsigned char *iv,
                           const unsigned char *input, size_t input_len,
                           unsigned char *output) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(&ctx, key, keylen * 8);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return ret;
    }

    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, input_len, iv, input, output);
    mbedtls_aes_free(&ctx);
    return ret;
}

// CBC decrypt
static int aes_cbc_decrypt(const unsigned char *key, int keylen,
                           unsigned char *iv,
                           const unsigned char *input, size_t input_len,
                           unsigned char *output) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_dec(&ctx, key, keylen * 8);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return ret;
    }

    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, input_len, iv, input, output);
    mbedtls_aes_free(&ctx);
    return ret;
}
*/
import "C"
import (
	"crypto/cipher"
	"fmt"
	"unsafe"
)

// cbcEncrypter implements cipher.BlockMode for CBC encryption
type cbcEncrypter struct {
	key    []byte
	keyLen int
	iv     []byte
}

// cbcDecrypter implements cipher.BlockMode for CBC decryption
type cbcDecrypter struct {
	key    []byte
	keyLen int
	iv     []byte
}

// NewCBCEncrypter creates a new CBC encrypter
func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		panic("mbedtls: NewCBCEncrypter requires mbedtls aesBlock")
	}
	if len(iv) != aesBlockSize {
		panic("mbedtls: IV length must equal block size")
	}

	ivCopy := make([]byte, aesBlockSize)
	copy(ivCopy, iv)

	return &cbcEncrypter{
		key:    aesBlock.key,
		keyLen: aesBlock.keyLen,
		iv:     ivCopy,
	}
}

// NewCBCDecrypter creates a new CBC decrypter
func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		panic("mbedtls: NewCBCDecrypter requires mbedtls aesBlock")
	}
	if len(iv) != aesBlockSize {
		panic("mbedtls: IV length must equal block size")
	}

	ivCopy := make([]byte, aesBlockSize)
	copy(ivCopy, iv)

	return &cbcDecrypter{
		key:    aesBlock.key,
		keyLen: aesBlock.keyLen,
		iv:     ivCopy,
	}
}

func (c *cbcEncrypter) BlockSize() int {
	return aesBlockSize
}

func (c *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%aesBlockSize != 0 {
		panic("mbedtls: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("mbedtls: output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	// Make a copy of IV since mbedTLS modifies it
	iv := make([]byte, aesBlockSize)
	copy(iv, c.iv)

	ret := C.aes_cbc_encrypt(
		(*C.uchar)(unsafe.Pointer(&c.key[0])),
		C.int(c.keyLen),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		C.size_t(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)
	if ret != 0 {
		panic(fmt.Sprintf("mbedtls: CBC encrypt failed: %d", ret))
	}

	// Update IV for next call
	copy(c.iv, dst[len(dst)-aesBlockSize:])
}

func (c *cbcDecrypter) BlockSize() int {
	return aesBlockSize
}

func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%aesBlockSize != 0 {
		panic("mbedtls: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("mbedtls: output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	// Save last block for next IV
	nextIV := make([]byte, aesBlockSize)
	copy(nextIV, src[len(src)-aesBlockSize:])

	// Make a copy of IV since mbedTLS modifies it
	iv := make([]byte, aesBlockSize)
	copy(iv, c.iv)

	ret := C.aes_cbc_decrypt(
		(*C.uchar)(unsafe.Pointer(&c.key[0])),
		C.int(c.keyLen),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		C.size_t(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)
	if ret != 0 {
		panic(fmt.Sprintf("mbedtls: CBC decrypt failed: %d", ret))
	}

	// Update IV for next call
	copy(c.iv, nextIV)
}
