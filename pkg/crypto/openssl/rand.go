// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package openssl

/*
#include <openssl/rand.h>

static int rand_bytes(unsigned char *buf, int num) {
    return RAND_bytes(buf, num);
}
*/
import "C"
import (
	"errors"
	"io"
	"unsafe"
)

// randReader implements io.Reader using OpenSSL RAND_bytes
type randReader struct{}

// Reader is a global random number generator using OpenSSL
var Reader io.Reader = &randReader{}

// ErrRandFailed indicates RAND_bytes failed
var ErrRandFailed = errors.New("openssl/rand: RAND_bytes failed")

func (r *randReader) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	if err := Init(); err != nil {
		return 0, err
	}

	clearErrors()

	ret := C.rand_bytes((*C.uchar)(unsafe.Pointer(&b[0])), C.int(len(b)))
	if ret != 1 {
		return 0, ErrRandFailed
	}

	return len(b), nil
}

// Read fills b with cryptographically secure random bytes
func Read(b []byte) (n int, err error) {
	return Reader.Read(b)
}
