// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build cgo
// +build cgo

package mbedtls

/*
extern int mbedtls_random_bytes(unsigned char *buf, size_t len);
*/
import "C"
import (
	"io"
	"unsafe"
)

// randReader implements io.Reader using mbedTLS CTR-DRBG
type randReader struct{}

// Reader is a global random number generator using mbedTLS
var Reader io.Reader = &randReader{}

func (r *randReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	if err := Init(); err != nil {
		return 0, err
	}

	ret := C.mbedtls_random_bytes((*C.uchar)(unsafe.Pointer(&p[0])), C.size_t(len(p)))
	if ret != 0 {
		return 0, getError(int(ret))
	}

	return len(p), nil
}

// Read fills the byte slice with random data
func Read(b []byte) (n int, err error) {
	return Reader.Read(b)
}
