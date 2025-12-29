//go:build linux
// +build linux

package netdev

import (
	_ "unsafe" // for go:linkname
)

// useNetdev is linked to the internal net.useNetdev function
//go:linkname useNetdev net.useNetdev
func useNetdev(dev interface{})

func init() {
	// Register the Linux netdev with TinyGo's net package
	useNetdev(NewLinuxNetdev())
}
