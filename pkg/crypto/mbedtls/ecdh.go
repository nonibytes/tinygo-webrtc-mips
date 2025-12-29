// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <stdlib.h>
#include <string.h>

extern int mbedtls_random_bytes(unsigned char *buf, size_t len);

// Random function for mbedTLS
static int rng_func(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    return mbedtls_random_bytes(buf, len);
}

// Generate ECDH keypair for P-256
static int ecdh_generate_p256(unsigned char *priv_key, size_t *priv_len,
                               unsigned char *pub_key, size_t *pub_len) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);

    int ret = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    ret = mbedtls_ecdh_gen_public(&ctx.ctx.mbed_ecdh.grp,
                                   &ctx.ctx.mbed_ecdh.d,
                                   &ctx.ctx.mbed_ecdh.Q,
                                   rng_func, NULL);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Export private key (32 bytes for P-256)
    ret = mbedtls_mpi_write_binary(&ctx.ctx.mbed_ecdh.d, priv_key, 32);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }
    *priv_len = 32;

    // Export public key (uncompressed: 04 || X || Y = 65 bytes)
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&ctx.ctx.mbed_ecdh.grp,
                                          &ctx.ctx.mbed_ecdh.Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen, pub_key, 65);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }
    *pub_len = olen;

    mbedtls_ecdh_free(&ctx);
    return 0;
}

// Generate ECDH keypair for P-384
static int ecdh_generate_p384(unsigned char *priv_key, size_t *priv_len,
                               unsigned char *pub_key, size_t *pub_len) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);

    int ret = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP384R1);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    ret = mbedtls_ecdh_gen_public(&ctx.ctx.mbed_ecdh.grp,
                                   &ctx.ctx.mbed_ecdh.d,
                                   &ctx.ctx.mbed_ecdh.Q,
                                   rng_func, NULL);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Export private key (48 bytes for P-384)
    ret = mbedtls_mpi_write_binary(&ctx.ctx.mbed_ecdh.d, priv_key, 48);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }
    *priv_len = 48;

    // Export public key (uncompressed: 04 || X || Y = 97 bytes)
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&ctx.ctx.mbed_ecdh.grp,
                                          &ctx.ctx.mbed_ecdh.Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen, pub_key, 97);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }
    *pub_len = olen;

    mbedtls_ecdh_free(&ctx);
    return 0;
}

// Compute ECDH shared secret for P-256
static int ecdh_compute_p256(const unsigned char *priv_key, size_t priv_len,
                              const unsigned char *peer_pub, size_t peer_pub_len,
                              unsigned char *secret, size_t *secret_len) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);

    int ret = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Import private key
    ret = mbedtls_mpi_read_binary(&ctx.ctx.mbed_ecdh.d, priv_key, priv_len);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Import peer's public key
    ret = mbedtls_ecp_point_read_binary(&ctx.ctx.mbed_ecdh.grp,
                                         &ctx.ctx.mbed_ecdh.Qp,
                                         peer_pub, peer_pub_len);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Compute shared secret
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);

    ret = mbedtls_ecdh_compute_shared(&ctx.ctx.mbed_ecdh.grp, &z,
                                       &ctx.ctx.mbed_ecdh.Qp,
                                       &ctx.ctx.mbed_ecdh.d,
                                       rng_func, NULL);
    if (ret != 0) {
        mbedtls_mpi_free(&z);
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Export shared secret (32 bytes for P-256)
    ret = mbedtls_mpi_write_binary(&z, secret, 32);
    *secret_len = 32;

    mbedtls_mpi_free(&z);
    mbedtls_ecdh_free(&ctx);
    return ret;
}

// Compute ECDH shared secret for P-384
static int ecdh_compute_p384(const unsigned char *priv_key, size_t priv_len,
                              const unsigned char *peer_pub, size_t peer_pub_len,
                              unsigned char *secret, size_t *secret_len) {
    mbedtls_ecdh_context ctx;
    mbedtls_ecdh_init(&ctx);

    int ret = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP384R1);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Import private key
    ret = mbedtls_mpi_read_binary(&ctx.ctx.mbed_ecdh.d, priv_key, priv_len);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Import peer's public key
    ret = mbedtls_ecp_point_read_binary(&ctx.ctx.mbed_ecdh.grp,
                                         &ctx.ctx.mbed_ecdh.Qp,
                                         peer_pub, peer_pub_len);
    if (ret != 0) {
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Compute shared secret
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);

    ret = mbedtls_ecdh_compute_shared(&ctx.ctx.mbed_ecdh.grp, &z,
                                       &ctx.ctx.mbed_ecdh.Qp,
                                       &ctx.ctx.mbed_ecdh.d,
                                       rng_func, NULL);
    if (ret != 0) {
        mbedtls_mpi_free(&z);
        mbedtls_ecdh_free(&ctx);
        return ret;
    }

    // Export shared secret (48 bytes for P-384)
    ret = mbedtls_mpi_write_binary(&z, secret, 48);
    *secret_len = 48;

    mbedtls_mpi_free(&z);
    mbedtls_ecdh_free(&ctx);
    return ret;
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// CurveType represents the elliptic curve type
type CurveType int

const (
	CurveP256 CurveType = iota
	CurveP384
	CurveX25519 // Note: X25519 requires mbedTLS 2.x with MBEDTLS_ECDH_VARIANT_EVEREST
)

// ECDHKeypair holds an ECDH key pair
type ECDHKeypair struct {
	Curve      CurveType
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateECDHKeypair generates a new ECDH key pair for the specified curve
func GenerateECDHKeypair(curve CurveType) (*ECDHKeypair, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	var privKey, pubKey []byte
	var privLen, pubLen C.size_t

	switch curve {
	case CurveP256:
		privKey = make([]byte, 32)
		pubKey = make([]byte, 65)
		ret := C.ecdh_generate_p256(
			(*C.uchar)(unsafe.Pointer(&privKey[0])), &privLen,
			(*C.uchar)(unsafe.Pointer(&pubKey[0])), &pubLen,
		)
		if ret != 0 {
			return nil, getError(int(ret))
		}
		privKey = privKey[:privLen]
		pubKey = pubKey[:pubLen]

	case CurveP384:
		privKey = make([]byte, 48)
		pubKey = make([]byte, 97)
		ret := C.ecdh_generate_p384(
			(*C.uchar)(unsafe.Pointer(&privKey[0])), &privLen,
			(*C.uchar)(unsafe.Pointer(&pubKey[0])), &pubLen,
		)
		if ret != 0 {
			return nil, getError(int(ret))
		}
		privKey = privKey[:privLen]
		pubKey = pubKey[:pubLen]

	case CurveX25519:
		return nil, errors.New("mbedtls: X25519 not supported in this build")

	default:
		return nil, errors.New("mbedtls: unsupported curve")
	}

	return &ECDHKeypair{
		Curve:      curve,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// ECDH computes the shared secret with the peer's public key
func (kp *ECDHKeypair) ECDH(peerPublicKey []byte) ([]byte, error) {
	var secret []byte
	var secretLen C.size_t

	switch kp.Curve {
	case CurveP256:
		secret = make([]byte, 32)
		ret := C.ecdh_compute_p256(
			(*C.uchar)(unsafe.Pointer(&kp.PrivateKey[0])), C.size_t(len(kp.PrivateKey)),
			(*C.uchar)(unsafe.Pointer(&peerPublicKey[0])), C.size_t(len(peerPublicKey)),
			(*C.uchar)(unsafe.Pointer(&secret[0])), &secretLen,
		)
		if ret != 0 {
			return nil, getError(int(ret))
		}
		return secret[:secretLen], nil

	case CurveP384:
		secret = make([]byte, 48)
		ret := C.ecdh_compute_p384(
			(*C.uchar)(unsafe.Pointer(&kp.PrivateKey[0])), C.size_t(len(kp.PrivateKey)),
			(*C.uchar)(unsafe.Pointer(&peerPublicKey[0])), C.size_t(len(peerPublicKey)),
			(*C.uchar)(unsafe.Pointer(&secret[0])), &secretLen,
		)
		if ret != 0 {
			return nil, getError(int(ret))
		}
		return secret[:secretLen], nil

	default:
		return nil, errors.New("mbedtls: unsupported curve for ECDH")
	}
}
