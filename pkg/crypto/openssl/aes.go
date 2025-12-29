// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>

// AES block encryption using EVP (Electronic Codebook mode for single block)
static int aes_encrypt_block(const unsigned char *key, int keylen,
                             const unsigned char *in, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher;
    switch (keylen) {
        case 16: cipher = EVP_aes_128_ecb(); break;
        case 24: cipher = EVP_aes_192_ecb(); break;
        case 32: cipher = EVP_aes_256_ecb(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return -1;
    }

    int outlen = 0;
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Disable padding for single block operations
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, out, &outlen, in, 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// AES block decryption using EVP
static int aes_decrypt_block(const unsigned char *key, int keylen,
                             const unsigned char *in, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher;
    switch (keylen) {
        case 16: cipher = EVP_aes_128_ecb(); break;
        case 24: cipher = EVP_aes_192_ecb(); break;
        case 32: cipher = EVP_aes_256_ecb(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return -1;
    }

    int outlen = 0;
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Disable padding for single block operations
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, out, &outlen, in, 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
*/
import "C"
import (
	"crypto/cipher"
	"errors"
	"unsafe"
)

const aesBlockSize = 16

// Errors
var (
	ErrInvalidKeySize = errors.New("openssl/aes: invalid key size")
)

// aesBlock implements cipher.Block using OpenSSL
type aesBlock struct {
	key    []byte
	keyLen int
}

// NewCipher creates a new AES cipher.Block using OpenSSL
// Key length must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
func NewCipher(key []byte) (cipher.Block, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	k := len(key)
	switch k {
	case 16, 24, 32:
		// valid key sizes
	default:
		return nil, ErrInvalidKeySize
	}

	// Make a copy of the key
	keyCopy := make([]byte, k)
	copy(keyCopy, key)

	return &aesBlock{
		key:    keyCopy,
		keyLen: k,
	}, nil
}

// BlockSize returns the AES block size (always 16 bytes)
func (b *aesBlock) BlockSize() int {
	return aesBlockSize
}

// Encrypt encrypts a single 16-byte block
func (b *aesBlock) Encrypt(dst, src []byte) {
	if len(src) < aesBlockSize {
		panic("openssl/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("openssl/aes: output not full block")
	}

	clearErrors()
	ret := C.aes_encrypt_block(
		(*C.uchar)(unsafe.Pointer(&b.key[0])),
		C.int(b.keyLen),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)
	if ret != 0 {
		panic("openssl/aes: encryption failed: " + getError().Error())
	}
}

// Decrypt decrypts a single 16-byte block
func (b *aesBlock) Decrypt(dst, src []byte) {
	if len(src) < aesBlockSize {
		panic("openssl/aes: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("openssl/aes: output not full block")
	}

	clearErrors()
	ret := C.aes_decrypt_block(
		(*C.uchar)(unsafe.Pointer(&b.key[0])),
		C.int(b.keyLen),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)
	if ret != 0 {
		panic("openssl/aes: decryption failed: " + getError().Error())
	}
}
