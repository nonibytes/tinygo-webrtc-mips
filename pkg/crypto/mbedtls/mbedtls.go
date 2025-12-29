// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

// Package mbedtls provides mbedTLS-backed crypto implementations for TinyGo
package mbedtls

/*
#cgo CFLAGS: -I/tmp/mbedtls-mips/include
#cgo LDFLAGS: -L/tmp/mbedtls-mips/lib -lmbedtls -lmbedcrypto -lmbedx509
#include <mbedtls/version.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <stdlib.h>
#include <string.h>

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static int initialized = 0;

static int mbedtls_init_rng(void) {
    if (initialized) return 0;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "tinygo_webrtc";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers));
    if (ret == 0) {
        initialized = 1;
    }
    return ret;
}

static int mbedtls_random_bytes(unsigned char *buf, size_t len) {
    if (!initialized) {
        int ret = mbedtls_init_rng();
        if (ret != 0) return ret;
    }
    return mbedtls_ctr_drbg_random(&ctr_drbg, buf, len);
}

static void mbedtls_get_error_string(int ret, char *buf, size_t len) {
    mbedtls_strerror(ret, buf, len);
}

static const char* mbedtls_get_version(void) {
    return MBEDTLS_VERSION_STRING;
}
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var (
	initOnce sync.Once
	initErr  error
)

// ErrMbedTLS represents an mbedTLS error
var ErrMbedTLS = errors.New("mbedtls error")

// Init initializes mbedTLS. Safe to call multiple times.
func Init() error {
	initOnce.Do(func() {
		ret := C.mbedtls_init_rng()
		if ret != 0 {
			initErr = getError(int(ret))
		}
	})
	return initErr
}

// Version returns the mbedTLS version string
func Version() string {
	return C.GoString(C.mbedtls_get_version())
}

// getError converts an mbedTLS error code to a Go error
func getError(ret int) error {
	if ret == 0 {
		return nil
	}

	buf := make([]byte, 256)
	C.mbedtls_get_error_string(C.int(ret), (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))

	// Find null terminator
	for i, b := range buf {
		if b == 0 {
			return fmt.Errorf("%w: %s (code %d)", ErrMbedTLS, string(buf[:i]), ret)
		}
	}
	return fmt.Errorf("%w: code %d", ErrMbedTLS, ret)
}
