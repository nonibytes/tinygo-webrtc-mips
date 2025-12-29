// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/evp.h>
#include <string.h>

// AES-CBC encrypt
static int aes_cbc_encrypt(const unsigned char *key, int keylen,
                           const unsigned char *iv,
                           const unsigned char *plaintext, int plainlen,
                           unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher;
    switch (keylen) {
        case 16: cipher = EVP_aes_128_cbc(); break;
        case 24: cipher = EVP_aes_192_cbc(); break;
        case 32: cipher = EVP_aes_256_cbc(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return -1;
    }

    // Disable padding - we handle it ourselves
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Disable padding again after init
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plainlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int cipherlen = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipherlen += len;

    EVP_CIPHER_CTX_free(ctx);
    return cipherlen;
}

// AES-CBC decrypt
static int aes_cbc_decrypt(const unsigned char *key, int keylen,
                           const unsigned char *iv,
                           const unsigned char *ciphertext, int cipherlen,
                           unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher;
    switch (keylen) {
        case 16: cipher = EVP_aes_128_cbc(); break;
        case 24: cipher = EVP_aes_192_cbc(); break;
        case 32: cipher = EVP_aes_256_cbc(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return -1;
    }

    // Disable padding - we handle it ourselves
    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Disable padding again after init
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipherlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int plainlen = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plainlen += len;

    EVP_CIPHER_CTX_free(ctx);
    return plainlen;
}
*/
import "C"
import (
	"crypto/cipher"
	"errors"
	"unsafe"
)

var ErrCBCFailed = errors.New("openssl/cbc: operation failed")

// cbcEncrypter implements cipher.BlockMode for CBC encryption
type cbcEncrypter struct {
	key []byte
	iv  []byte
}

// cbcDecrypter implements cipher.BlockMode for CBC decryption
type cbcDecrypter struct {
	key []byte
	iv  []byte
}

// NewCBCEncrypter creates a CBC encrypter
func NewCBCEncrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		panic("openssl/cbc: block must be *aesBlock from openssl.NewCipher")
	}

	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	return &cbcEncrypter{
		key: aesBlock.key,
		iv:  ivCopy,
	}
}

// NewCBCDecrypter creates a CBC decrypter
func NewCBCDecrypter(block cipher.Block, iv []byte) cipher.BlockMode {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		panic("openssl/cbc: block must be *aesBlock from openssl.NewCipher")
	}

	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	return &cbcDecrypter{
		key: aesBlock.key,
		iv:  ivCopy,
	}
}

func (c *cbcEncrypter) BlockSize() int {
	return 16
}

func (c *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%16 != 0 {
		panic("openssl/cbc: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("openssl/cbc: output smaller than input")
	}

	if len(src) == 0 {
		return
	}

	clearErrors()

	ret := C.aes_cbc_encrypt(
		(*C.uchar)(unsafe.Pointer(&c.key[0])),
		C.int(len(c.key)),
		(*C.uchar)(unsafe.Pointer(&c.iv[0])),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		C.int(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)

	if ret < 0 {
		panic("openssl/cbc: encrypt failed: " + getError().Error())
	}

	// Update IV to last ciphertext block for chaining
	copy(c.iv, dst[len(src)-16:])
}

// SetIV allows setting a new IV (for DTLS CBC mode)
func (c *cbcEncrypter) SetIV(iv []byte) {
	copy(c.iv, iv)
}

func (c *cbcDecrypter) BlockSize() int {
	return 16
}

func (c *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%16 != 0 {
		panic("openssl/cbc: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("openssl/cbc: output smaller than input")
	}

	if len(src) == 0 {
		return
	}

	// Save the last block before decryption for IV update
	lastBlock := make([]byte, 16)
	copy(lastBlock, src[len(src)-16:])

	clearErrors()

	ret := C.aes_cbc_decrypt(
		(*C.uchar)(unsafe.Pointer(&c.key[0])),
		C.int(len(c.key)),
		(*C.uchar)(unsafe.Pointer(&c.iv[0])),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		C.int(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)

	if ret < 0 {
		panic("openssl/cbc: decrypt failed: " + getError().Error())
	}

	// Update IV to last ciphertext block for chaining
	copy(c.iv, lastBlock)
}

// SetIV allows setting a new IV (for DTLS CBC mode)
func (c *cbcDecrypter) SetIV(iv []byte) {
	copy(c.iv, iv)
}
