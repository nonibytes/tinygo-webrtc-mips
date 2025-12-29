// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
#include <mbedtls/gcm.h>
#include <stdlib.h>
#include <string.h>

// GCM encrypt with authentication
static int gcm_encrypt(const unsigned char *key, int keylen,
                       const unsigned char *iv, size_t iv_len,
                       const unsigned char *aad, size_t aad_len,
                       const unsigned char *input, size_t input_len,
                       unsigned char *output,
                       unsigned char *tag, size_t tag_len) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keylen * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return ret;
    }

    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT,
                                     input_len, iv, iv_len,
                                     aad, aad_len,
                                     input, output,
                                     tag_len, tag);

    mbedtls_gcm_free(&ctx);
    return ret;
}

// GCM decrypt with authentication
static int gcm_decrypt(const unsigned char *key, int keylen,
                       const unsigned char *iv, size_t iv_len,
                       const unsigned char *aad, size_t aad_len,
                       const unsigned char *input, size_t input_len,
                       unsigned char *output,
                       const unsigned char *tag, size_t tag_len) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keylen * 8);
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        return ret;
    }

    ret = mbedtls_gcm_auth_decrypt(&ctx, input_len, iv, iv_len,
                                    aad, aad_len,
                                    tag, tag_len,
                                    input, output);

    mbedtls_gcm_free(&ctx);
    return ret;
}
*/
import "C"
import (
	"crypto/cipher"
	"errors"
	"fmt"
	"unsafe"
)

const (
	gcmTagSize   = 16
	gcmNonceSize = 12
)

// gcmAEAD implements cipher.AEAD using mbedTLS GCM
type gcmAEAD struct {
	key       []byte
	keyLen    int
	nonceSize int
}

// NewGCM creates a new GCM cipher.AEAD from a cipher.Block
func NewGCM(block cipher.Block) (cipher.AEAD, error) {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		return nil, errors.New("mbedtls: NewGCM requires mbedtls aesBlock")
	}

	return &gcmAEAD{
		key:       aesBlock.key,
		keyLen:    aesBlock.keyLen,
		nonceSize: gcmNonceSize,
	}, nil
}

// NewGCMWithNonceSize creates a new GCM with custom nonce size
func NewGCMWithNonceSize(block cipher.Block, nonceSize int) (cipher.AEAD, error) {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		return nil, errors.New("mbedtls: NewGCMWithNonceSize requires mbedtls aesBlock")
	}

	return &gcmAEAD{
		key:       aesBlock.key,
		keyLen:    aesBlock.keyLen,
		nonceSize: nonceSize,
	}, nil
}

func (g *gcmAEAD) NonceSize() int {
	return g.nonceSize
}

func (g *gcmAEAD) Overhead() int {
	return gcmTagSize
}

func (g *gcmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic(fmt.Sprintf("mbedtls: incorrect nonce length: %d", len(nonce)))
	}

	// Allocate output: ciphertext + tag
	ret := make([]byte, len(plaintext)+gcmTagSize)
	ciphertext := ret[:len(plaintext)]
	tag := ret[len(plaintext):]

	var inputPtr, aadPtr *C.uchar
	if len(plaintext) > 0 {
		inputPtr = (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	}
	if len(additionalData) > 0 {
		aadPtr = (*C.uchar)(unsafe.Pointer(&additionalData[0]))
	}

	var ciphertextPtr *C.uchar
	if len(ciphertext) > 0 {
		ciphertextPtr = (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	}

	result := C.gcm_encrypt(
		(*C.uchar)(unsafe.Pointer(&g.key[0])),
		C.int(g.keyLen),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.size_t(len(nonce)),
		aadPtr,
		C.size_t(len(additionalData)),
		inputPtr,
		C.size_t(len(plaintext)),
		ciphertextPtr,
		(*C.uchar)(unsafe.Pointer(&tag[0])),
		C.size_t(gcmTagSize),
	)

	if result != 0 {
		panic(fmt.Sprintf("mbedtls: GCM encrypt failed: %d", result))
	}

	if dst != nil {
		return append(dst, ret...)
	}
	return ret
}

func (g *gcmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		return nil, fmt.Errorf("mbedtls: incorrect nonce length: %d", len(nonce))
	}

	if len(ciphertext) < gcmTagSize {
		return nil, errors.New("mbedtls: ciphertext too short")
	}

	// Split ciphertext and tag
	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	// Allocate output
	plaintext := make([]byte, len(ciphertext))

	var inputPtr, outputPtr, aadPtr *C.uchar
	if len(ciphertext) > 0 {
		inputPtr = (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
		outputPtr = (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	}
	if len(additionalData) > 0 {
		aadPtr = (*C.uchar)(unsafe.Pointer(&additionalData[0]))
	}

	result := C.gcm_decrypt(
		(*C.uchar)(unsafe.Pointer(&g.key[0])),
		C.int(g.keyLen),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		C.size_t(len(nonce)),
		aadPtr,
		C.size_t(len(additionalData)),
		inputPtr,
		C.size_t(len(ciphertext)),
		outputPtr,
		(*C.uchar)(unsafe.Pointer(&tag[0])),
		C.size_t(gcmTagSize),
	)

	if result != 0 {
		return nil, errors.New("mbedtls: GCM authentication failed")
	}

	if dst != nil {
		return append(dst, plaintext...), nil
	}
	return plaintext, nil
}
