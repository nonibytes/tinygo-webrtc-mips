// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>

// Generate ECDH keypair for P-256
static int ecdh_p256_keygen(unsigned char *privkey, int *privkey_len,
                            unsigned char *pubkey, int *pubkey_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    // Get private key (32 bytes for P-256)
    size_t len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, privkey, &len) != 1) {
        // Fallback: use BN extraction
        BIGNUM *priv_bn = NULL;
        if (EVP_PKEY_get_bn_param(pkey, "priv", &priv_bn) != 1) {
            EVP_PKEY_free(pkey);
            return -1;
        }
        *privkey_len = BN_bn2binpad(priv_bn, privkey, 32);
        BN_free(priv_bn);
    } else {
        *privkey_len = (int)len;
    }

    // Get public key (uncompressed: 04 || X || Y = 65 bytes)
    len = 65;
    if (EVP_PKEY_get_octet_string_param(pkey, "encoded-pub-key", pubkey, 65, &len) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *pubkey_len = (int)len;

    EVP_PKEY_free(pkey);
    return 0;
}

// Generate ECDH keypair for P-384
static int ecdh_p384_keygen(unsigned char *privkey, int *privkey_len,
                            unsigned char *pubkey, int *pubkey_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    // Get private key (48 bytes for P-384)
    BIGNUM *priv_bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, "priv", &priv_bn) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *privkey_len = BN_bn2binpad(priv_bn, privkey, 48);
    BN_free(priv_bn);

    // Get public key (uncompressed: 04 || X || Y = 97 bytes)
    size_t len = 97;
    if (EVP_PKEY_get_octet_string_param(pkey, "encoded-pub-key", pubkey, 97, &len) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *pubkey_len = (int)len;

    EVP_PKEY_free(pkey);
    return 0;
}

// Generate X25519 keypair
static int ecdh_x25519_keygen(unsigned char *privkey, int *privkey_len,
                              unsigned char *pubkey, int *pubkey_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    // Get private key (32 bytes)
    size_t len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, privkey, &len) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *privkey_len = (int)len;

    // Get public key (32 bytes)
    len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &len) != 1) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    *pubkey_len = (int)len;

    EVP_PKEY_free(pkey);
    return 0;
}

// ECDH shared secret for P-256
static int ecdh_p256_derive(const unsigned char *privkey, int privkey_len,
                            const unsigned char *peer_pubkey, int peer_pubkey_len,
                            unsigned char *secret, int *secret_len) {
    // Create private key from raw bytes
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_EC, NULL, privkey, privkey_len);
    if (!pkey) {
        // Fallback: create from EC_KEY
        EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!eckey) return -1;

        BIGNUM *priv_bn = BN_bin2bn(privkey, privkey_len, NULL);
        if (!priv_bn) {
            EC_KEY_free(eckey);
            return -1;
        }
        if (EC_KEY_set_private_key(eckey, priv_bn) != 1) {
            BN_free(priv_bn);
            EC_KEY_free(eckey);
            return -1;
        }
        BN_free(priv_bn);

        pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, eckey) != 1) {
            EC_KEY_free(eckey);
            if (pkey) EVP_PKEY_free(pkey);
            return -1;
        }
    }

    // Create peer public key
    EVP_PKEY *peer_pkey = EVP_PKEY_new();
    if (!peer_pkey) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    EC_KEY *peer_eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!peer_eckey) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    const EC_GROUP *group = EC_KEY_get0_group(peer_eckey);
    EC_POINT *point = EC_POINT_new(group);
    if (!point) {
        EC_KEY_free(peer_eckey);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EC_POINT_oct2point(group, point, peer_pubkey, peer_pubkey_len, NULL) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(peer_eckey);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EC_KEY_set_public_key(peer_eckey, point) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(peer_eckey);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }
    EC_POINT_free(point);

    if (EVP_PKEY_assign_EC_KEY(peer_pkey, peer_eckey) != 1) {
        EC_KEY_free(peer_eckey);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Derive shared secret
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    size_t len = 32;
    if (EVP_PKEY_derive(ctx, secret, &len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }
    *secret_len = (int)len;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(pkey);
    return 0;
}

// ECDH shared secret for X25519
static int ecdh_x25519_derive(const unsigned char *privkey, int privkey_len,
                              const unsigned char *peer_pubkey, int peer_pubkey_len,
                              unsigned char *secret, int *secret_len) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, privkey, privkey_len);
    if (!pkey) return -1;

    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pubkey, peer_pubkey_len);
    if (!peer_pkey) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }

    size_t len = 32;
    if (EVP_PKEY_derive(ctx, secret, &len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);
        return -1;
    }
    *secret_len = (int)len;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(pkey);
    return 0;
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Curve types
type CurveType int

const (
	CurveP256 CurveType = iota
	CurveP384
	CurveX25519
)

// Key sizes
const (
	P256PrivKeySize = 32
	P256PubKeySize  = 65 // Uncompressed: 04 || X || Y
	P384PrivKeySize = 48
	P384PubKeySize  = 97
	X25519KeySize   = 32
)

var (
	ErrKeygenFailed = errors.New("openssl/ecdh: key generation failed")
	ErrDeriveFailed = errors.New("openssl/ecdh: key derivation failed")
)

// ECDHKeypair represents an ECDH key pair
type ECDHKeypair struct {
	Curve      CurveType
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateECDHKeypair generates a new ECDH keypair for the specified curve
func GenerateECDHKeypair(curve CurveType) (*ECDHKeypair, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	clearErrors()

	var privkey, pubkey []byte
	var privkeyLen, pubkeyLen C.int

	switch curve {
	case CurveP256:
		privkey = make([]byte, P256PrivKeySize)
		pubkey = make([]byte, P256PubKeySize)
		ret := C.ecdh_p256_keygen(
			(*C.uchar)(unsafe.Pointer(&privkey[0])), &privkeyLen,
			(*C.uchar)(unsafe.Pointer(&pubkey[0])), &pubkeyLen,
		)
		if ret != 0 {
			return nil, ErrKeygenFailed
		}
		privkey = privkey[:privkeyLen]
		pubkey = pubkey[:pubkeyLen]

	case CurveP384:
		privkey = make([]byte, P384PrivKeySize)
		pubkey = make([]byte, P384PubKeySize)
		ret := C.ecdh_p384_keygen(
			(*C.uchar)(unsafe.Pointer(&privkey[0])), &privkeyLen,
			(*C.uchar)(unsafe.Pointer(&pubkey[0])), &pubkeyLen,
		)
		if ret != 0 {
			return nil, ErrKeygenFailed
		}
		privkey = privkey[:privkeyLen]
		pubkey = pubkey[:pubkeyLen]

	case CurveX25519:
		privkey = make([]byte, X25519KeySize)
		pubkey = make([]byte, X25519KeySize)
		ret := C.ecdh_x25519_keygen(
			(*C.uchar)(unsafe.Pointer(&privkey[0])), &privkeyLen,
			(*C.uchar)(unsafe.Pointer(&pubkey[0])), &pubkeyLen,
		)
		if ret != 0 {
			return nil, ErrKeygenFailed
		}
		privkey = privkey[:privkeyLen]
		pubkey = pubkey[:pubkeyLen]

	default:
		return nil, errors.New("openssl/ecdh: unsupported curve")
	}

	return &ECDHKeypair{
		Curve:      curve,
		PrivateKey: privkey,
		PublicKey:  pubkey,
	}, nil
}

// ECDH computes the shared secret using this keypair and peer's public key
func (kp *ECDHKeypair) ECDH(peerPublicKey []byte) ([]byte, error) {
	if err := Init(); err != nil {
		return nil, err
	}

	clearErrors()

	var secret []byte
	var secretLen C.int

	switch kp.Curve {
	case CurveP256:
		secret = make([]byte, 32)
		ret := C.ecdh_p256_derive(
			(*C.uchar)(unsafe.Pointer(&kp.PrivateKey[0])), C.int(len(kp.PrivateKey)),
			(*C.uchar)(unsafe.Pointer(&peerPublicKey[0])), C.int(len(peerPublicKey)),
			(*C.uchar)(unsafe.Pointer(&secret[0])), &secretLen,
		)
		if ret != 0 {
			return nil, ErrDeriveFailed
		}

	case CurveX25519:
		secret = make([]byte, 32)
		ret := C.ecdh_x25519_derive(
			(*C.uchar)(unsafe.Pointer(&kp.PrivateKey[0])), C.int(len(kp.PrivateKey)),
			(*C.uchar)(unsafe.Pointer(&peerPublicKey[0])), C.int(len(peerPublicKey)),
			(*C.uchar)(unsafe.Pointer(&secret[0])), &secretLen,
		)
		if ret != 0 {
			return nil, ErrDeriveFailed
		}

	default:
		return nil, errors.New("openssl/ecdh: unsupported curve for derivation")
	}

	return secret[:secretLen], nil
}
