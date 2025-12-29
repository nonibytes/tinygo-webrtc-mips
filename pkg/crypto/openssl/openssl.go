// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

// Package openssl provides OpenSSL-backed crypto implementations for TinyGo
package openssl

/*
#cgo LDFLAGS: -lssl -lcrypto
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <stdlib.h>

static void openssl_init(void) {
    // OpenSSL 1.1.0+ auto-initializes, but we call this for compatibility
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
}

static const char* openssl_version(void) {
    return OpenSSL_version(OPENSSL_VERSION);
}

static unsigned long openssl_get_error(void) {
    return ERR_get_error();
}

static void openssl_error_string(unsigned long e, char* buf, size_t len) {
    ERR_error_string_n(e, buf, len);
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

// ErrOpenSSL represents an OpenSSL error
var ErrOpenSSL = errors.New("openssl error")

// Init initializes OpenSSL. Safe to call multiple times.
func Init() error {
	initOnce.Do(func() {
		C.openssl_init()
	})
	return initErr
}

// Version returns the OpenSSL version string
func Version() string {
	return C.GoString(C.openssl_version())
}

// getError returns the last OpenSSL error as a Go error
func getError() error {
	errCode := C.openssl_get_error()
	if errCode == 0 {
		return nil
	}

	buf := make([]byte, 256)
	C.openssl_error_string(errCode, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))

	// Find null terminator
	for i, b := range buf {
		if b == 0 {
			return fmt.Errorf("%w: %s", ErrOpenSSL, string(buf[:i]))
		}
	}
	return fmt.Errorf("%w: %s", ErrOpenSSL, string(buf))
}

// clearErrors clears the OpenSSL error queue
func clearErrors() {
	for C.openssl_get_error() != 0 {
		// drain error queue
	}
}
