//go:build ignore
// +build ignore

package main

import (
	"fmt"

	_ "github.com/nonibytes/tinygo-webrtc-mips/netdev"
)

func main() {
	fmt.Println("Testing Linux netdev...")
	fmt.Println("Netdev registered successfully!")
}
