package main

import (
	"fmt"

	"github.com/pion/webrtc/v4"
)

func main() {
	fmt.Println("TinyGo WebRTC MIPS Test")

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		fmt.Printf("Failed to create peer connection: %v\n", err)
		return
	}
	defer pc.Close()

	fmt.Println("WebRTC peer connection created successfully!")
}
