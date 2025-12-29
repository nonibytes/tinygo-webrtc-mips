// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>

// GCM encrypt with authentication
static int aes_gcm_seal(const unsigned char *key, int keylen,
                        const unsigned char *nonce, int noncelen,
                        const unsigned char *plaintext, int plainlen,
                        const unsigned char *aad, int aadlen,
                        unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher;
    switch (keylen) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return -1;
    }

    int len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, noncelen, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Add AAD (Additional Authenticated Data)
    if (aadlen > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Encrypt plaintext
    if (plainlen > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plainlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// GCM decrypt with authentication
static int aes_gcm_open(const unsigned char *key, int keylen,
                        const unsigned char *nonce, int noncelen,
                        const unsigned char *ciphertext, int cipherlen,
                        const unsigned char *aad, int aadlen,
                        const unsigned char *tag,
                        unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher;
    switch (keylen) {
        case 16: cipher = EVP_aes_128_gcm(); break;
        case 24: cipher = EVP_aes_192_gcm(); break;
        case 32: cipher = EVP_aes_256_gcm(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return -1;
    }

    int len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, noncelen, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Add AAD
    if (aadlen > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Decrypt ciphertext
    if (cipherlen > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipherlen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Verify tag
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -2; // Authentication failed
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

const (
	gcmTagSize       = 16
	gcmStandardNonce = 12
)

var (
	ErrAuthFailed    = errors.New("openssl/gcm: authentication failed")
	ErrInvalidNonce  = errors.New("openssl/gcm: invalid nonce size")
	ErrShortCipher   = errors.New("openssl/gcm: ciphertext too short")
)

// gcmAEAD implements cipher.AEAD using OpenSSL AES-GCM
type gcmAEAD struct {
	key       []byte
	keyLen    int
	nonceSize int
}

// NewGCM creates a new AES-GCM cipher.AEAD
// The block must be an *aesBlock created by NewCipher
func NewGCM(block cipher.Block) (cipher.AEAD, error) {
	return NewGCMWithNonceSize(block, gcmStandardNonce)
}

// NewGCMWithNonceSize creates a new AES-GCM with custom nonce size
func NewGCMWithNonceSize(block cipher.Block, nonceSize int) (cipher.AEAD, error) {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		return nil, errors.New("openssl/gcm: block must be *aesBlock from openssl.NewCipher")
	}

	return &gcmAEAD{
		key:       aesBlock.key,
		keyLen:    aesBlock.keyLen,
		nonceSize: nonceSize,
	}, nil
}

// NonceSize returns the nonce size
func (g *gcmAEAD) NonceSize() int {
	return g.nonceSize
}

// Overhead returns the tag size (16 bytes for GCM)
func (g *gcmAEAD) Overhead() int {
	return gcmTagSize
}

// Seal encrypts and authenticates plaintext, authenticates additionalData,
// and appends the result to dst
func (g *gcmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("openssl/gcm: incorrect nonce length")
	}

	clearErrors()

	// Allocate output: ciphertext (same length as plaintext) + tag
	ret := make([]byte, len(plaintext)+gcmTagSize)
	ciphertext := ret[:len(plaintext)]
	tag := ret[len(plaintext):]

	var noncePtr, plaintextPtr, aadPtr *C.uchar
	if len(nonce) > 0 {
		noncePtr = (*C.uchar)(unsafe.Pointer(&nonce[0]))
	}
	if len(plaintext) > 0 {
		plaintextPtr = (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	}
	if len(additionalData) > 0 {
		aadPtr = (*C.uchar)(unsafe.Pointer(&additionalData[0]))
	}

	var ciphertextPtr *C.uchar
	if len(ciphertext) > 0 {
		ciphertextPtr = (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	}

	result := C.aes_gcm_seal(
		(*C.uchar)(unsafe.Pointer(&g.key[0])),
		C.int(g.keyLen),
		noncePtr,
		C.int(len(nonce)),
		plaintextPtr,
		C.int(len(plaintext)),
		aadPtr,
		C.int(len(additionalData)),
		ciphertextPtr,
		(*C.uchar)(unsafe.Pointer(&tag[0])),
	)

	if result != 0 {
		panic("openssl/gcm: seal failed: " + getError().Error())
	}

	return append(dst, ret...)
}

// Open decrypts and authenticates ciphertext, authenticates additionalData,
// and appends the result to dst
func (g *gcmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		return nil, ErrInvalidNonce
	}

	if len(ciphertext) < gcmTagSize {
		return nil, ErrShortCipher
	}

	clearErrors()

	// Split ciphertext and tag
	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	// Allocate output
	plaintext := make([]byte, len(ciphertext))

	var noncePtr, ciphertextPtr, aadPtr, plaintextPtr *C.uchar
	if len(nonce) > 0 {
		noncePtr = (*C.uchar)(unsafe.Pointer(&nonce[0]))
	}
	if len(ciphertext) > 0 {
		ciphertextPtr = (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
		plaintextPtr = (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	}
	if len(additionalData) > 0 {
		aadPtr = (*C.uchar)(unsafe.Pointer(&additionalData[0]))
	}

	result := C.aes_gcm_open(
		(*C.uchar)(unsafe.Pointer(&g.key[0])),
		C.int(g.keyLen),
		noncePtr,
		C.int(len(nonce)),
		ciphertextPtr,
		C.int(len(ciphertext)),
		aadPtr,
		C.int(len(additionalData)),
		(*C.uchar)(unsafe.Pointer(&tag[0])),
		plaintextPtr,
	)

	if result == -2 {
		return nil, ErrAuthFailed
	}
	if result != 0 {
		return nil, getError()
	}

	return append(dst, plaintext...), nil
}
