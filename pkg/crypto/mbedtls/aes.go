// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
#include <mbedtls/aes.h>
#include <stdlib.h>
#include <string.h>

// AES block encrypt (ECB mode, single block)
static int aes_encrypt_block(const unsigned char *key, int keylen,
                              const unsigned char *input, unsigned char *output) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(&ctx, key, keylen * 8);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return ret;
    }

    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input, output);
    mbedtls_aes_free(&ctx);
    return ret;
}

// AES block decrypt (ECB mode, single block)
static int aes_decrypt_block(const unsigned char *key, int keylen,
                              const unsigned char *input, unsigned char *output) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_dec(&ctx, key, keylen * 8);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return ret;
    }

    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, input, output);
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

const aesBlockSize = 16

// aesBlock implements cipher.Block using mbedTLS
type aesBlock struct {
	key    []byte
	keyLen int
}

// NewCipher creates a new AES cipher.Block
func NewCipher(key []byte) (cipher.Block, error) {
	keyLen := len(key)
	switch keyLen {
	case 16, 24, 32:
		// Valid AES key sizes
	default:
		return nil, fmt.Errorf("mbedtls: invalid key size %d", keyLen)
	}

	// Make a copy of the key
	keyCopy := make([]byte, keyLen)
	copy(keyCopy, key)

	return &aesBlock{
		key:    keyCopy,
		keyLen: keyLen,
	}, nil
}

func (b *aesBlock) BlockSize() int {
	return aesBlockSize
}

func (b *aesBlock) Encrypt(dst, src []byte) {
	if len(src) < aesBlockSize {
		panic("mbedtls: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("mbedtls: output not full block")
	}

	ret := C.aes_encrypt_block(
		(*C.uchar)(unsafe.Pointer(&b.key[0])),
		C.int(b.keyLen),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)
	if ret != 0 {
		panic(fmt.Sprintf("mbedtls: AES encrypt failed: %d", ret))
	}
}

func (b *aesBlock) Decrypt(dst, src []byte) {
	if len(src) < aesBlockSize {
		panic("mbedtls: input not full block")
	}
	if len(dst) < aesBlockSize {
		panic("mbedtls: output not full block")
	}

	ret := C.aes_decrypt_block(
		(*C.uchar)(unsafe.Pointer(&b.key[0])),
		C.int(b.keyLen),
		(*C.uchar)(unsafe.Pointer(&src[0])),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)
	if ret != 0 {
		panic(fmt.Sprintf("mbedtls: AES decrypt failed: %d", ret))
	}
}
