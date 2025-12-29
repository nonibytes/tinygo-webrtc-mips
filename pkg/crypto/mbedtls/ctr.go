// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
#include <mbedtls/aes.h>
#include <stdlib.h>
#include <string.h>

// CTR mode encryption/decryption (same operation)
static int aes_ctr_crypt(const unsigned char *key, int keylen,
                         unsigned char *nonce_counter,
                         unsigned char *stream_block,
                         size_t *nc_off,
                         const unsigned char *input, size_t input_len,
                         unsigned char *output) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(&ctx, key, keylen * 8);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return ret;
    }

    ret = mbedtls_aes_crypt_ctr(&ctx, input_len, nc_off, nonce_counter, stream_block, input, output);
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

// ctrStream implements cipher.Stream for AES-CTR
type ctrStream struct {
	key          []byte
	keyLen       int
	nonceCounter [16]byte
	streamBlock  [16]byte
	ncOff        C.size_t
}

// NewCTR creates a new CTR mode cipher.Stream
func NewCTR(block cipher.Block, iv []byte) cipher.Stream {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		panic("mbedtls: NewCTR requires mbedtls aesBlock")
	}
	if len(iv) != aesBlockSize {
		panic("mbedtls: IV length must equal block size")
	}

	s := &ctrStream{
		key:    aesBlock.key,
		keyLen: aesBlock.keyLen,
	}
	copy(s.nonceCounter[:], iv)

	return s
}

func (s *ctrStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("mbedtls: output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	ret := C.aes_ctr_crypt(
		(*C.uchar)(unsafe.Pointer(&s.key[0])),
		C.int(s.keyLen),
		(*C.uchar)(unsafe.Pointer(&s.nonceCounter[0])),
		(*C.uchar)(unsafe.Pointer(&s.streamBlock[0])),
		&s.ncOff,
		(*C.uchar)(unsafe.Pointer(&src[0])),
		C.size_t(len(src)),
		(*C.uchar)(unsafe.Pointer(&dst[0])),
	)
	if ret != 0 {
		panic(fmt.Sprintf("mbedtls: CTR crypt failed: %d", ret))
	}
}
