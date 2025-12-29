// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/evp.h>

// AES-CTR encrypt/decrypt (same operation for CTR mode)
static int aes_ctr_xor(const unsigned char *key, int keylen,
                       const unsigned char *iv,
                       const unsigned char *input, int inputlen,
                       unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher;
    switch (keylen) {
        case 16: cipher = EVP_aes_128_ctr(); break;
        case 24: cipher = EVP_aes_192_ctr(); break;
        case 32: cipher = EVP_aes_256_ctr(); break;
        default:
            EVP_CIPHER_CTX_free(ctx);
            return -1;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    if (EVP_EncryptUpdate(ctx, output, &len, input, inputlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int outlen = len;
    if (EVP_EncryptFinal_ex(ctx, output + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    outlen += len;

    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}
*/
import "C"
import (
	"crypto/cipher"
	"encoding/binary"
	"unsafe"
)

// ctrStream implements cipher.Stream for AES-CTR
type ctrStream struct {
	key     []byte
	counter []byte
	block   []byte // keystream block
	offset  int    // offset into current block
}

// NewCTR creates a new AES-CTR cipher.Stream
func NewCTR(block cipher.Block, iv []byte) cipher.Stream {
	aesBlock, ok := block.(*aesBlock)
	if !ok {
		panic("openssl/ctr: block must be *aesBlock from openssl.NewCipher")
	}

	counterCopy := make([]byte, len(iv))
	copy(counterCopy, iv)

	return &ctrStream{
		key:     aesBlock.key,
		counter: counterCopy,
		block:   make([]byte, 16),
		offset:  16, // Force generating new block on first use
	}
}

func (c *ctrStream) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("openssl/ctr: output smaller than input")
	}

	for i := 0; i < len(src); {
		// Generate new keystream block if needed
		if c.offset >= 16 {
			c.generateBlock()
			c.offset = 0
			c.incrementCounter()
		}

		// XOR with keystream
		n := len(src) - i
		if n > 16-c.offset {
			n = 16 - c.offset
		}

		for j := 0; j < n; j++ {
			dst[i+j] = src[i+j] ^ c.block[c.offset+j]
		}

		i += n
		c.offset += n
	}
}

func (c *ctrStream) generateBlock() {
	clearErrors()

	ret := C.aes_ctr_xor(
		(*C.uchar)(unsafe.Pointer(&c.key[0])),
		C.int(len(c.key)),
		(*C.uchar)(unsafe.Pointer(&c.counter[0])),
		(*C.uchar)(unsafe.Pointer(&c.counter[0])), // Encrypt the counter itself
		C.int(0), // We just need the keystream for one block
		(*C.uchar)(unsafe.Pointer(&c.block[0])),
	)

	// Actually, for generating keystream, encrypt zeros
	zeros := make([]byte, 16)
	ret = C.aes_ctr_xor(
		(*C.uchar)(unsafe.Pointer(&c.key[0])),
		C.int(len(c.key)),
		(*C.uchar)(unsafe.Pointer(&c.counter[0])),
		(*C.uchar)(unsafe.Pointer(&zeros[0])),
		C.int(16),
		(*C.uchar)(unsafe.Pointer(&c.block[0])),
	)

	if ret < 0 {
		panic("openssl/ctr: generate block failed: " + getError().Error())
	}
}

func (c *ctrStream) incrementCounter() {
	// Increment the counter (big-endian)
	for i := len(c.counter) - 1; i >= 0; i-- {
		c.counter[i]++
		if c.counter[i] != 0 {
			break
		}
	}
}

// CTREncrypt encrypts/decrypts data directly using AES-CTR (same operation)
func CTREncrypt(key, iv, data []byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	clearErrors()

	output := make([]byte, len(data))

	if len(data) == 0 {
		return output, nil
	}

	ret := C.aes_ctr_xor(
		(*C.uchar)(unsafe.Pointer(&key[0])),
		C.int(len(key)),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.int(len(data)),
		(*C.uchar)(unsafe.Pointer(&output[0])),
	)

	if ret < 0 {
		return nil, getError()
	}

	return output, nil
}

// CTRDecrypt is the same as CTREncrypt for CTR mode
func CTRDecrypt(key, iv, data []byte) ([]byte, error) {
	return CTREncrypt(key, iv, data)
}

// SRTP key derivation helper - generates key material using AES-CM (Counter Mode)
func SRTPKeyDerivation(masterKey, masterSalt []byte, label byte, indexOverKdr uint64, outLen int) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	// Create the IV for key derivation
	// IV = (master_salt << 16) XOR (label || 0 || index/kdr)
	iv := make([]byte, 16)
	copy(iv, masterSalt)

	// XOR with (label << 48)
	iv[7] ^= label

	// XOR with index/kdr (48-bit value)
	indexBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(indexBytes, indexOverKdr)
	for i := 0; i < 6; i++ {
		iv[8+i] ^= indexBytes[2+i]
	}

	// Generate keystream
	output := make([]byte, outLen)
	zeros := make([]byte, outLen)

	if outLen == 0 {
		return output, nil
	}

	clearErrors()

	ret := C.aes_ctr_xor(
		(*C.uchar)(unsafe.Pointer(&masterKey[0])),
		C.int(len(masterKey)),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		(*C.uchar)(unsafe.Pointer(&zeros[0])),
		C.int(outLen),
		(*C.uchar)(unsafe.Pointer(&output[0])),
	)

	if ret < 0 {
		return nil, getError()
	}

	return output, nil
}
