package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pion/webrtc/v4"
)

const htmlPage = `<!DOCTYPE html>
<html>
<head>
    <title>WebRTC Audio Test</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        button { padding: 10px 20px; margin: 5px; font-size: 16px; cursor: pointer; }
        #status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .info { background: #cce5ff; color: #004085; }
        #localAudio, #remoteAudio { width: 100%; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>WebRTC Audio Echo Test</h1>
    <p>This tests the MIPS WebRTC binary by echoing your microphone audio back to you.</p>

    <div id="status" class="info">Click "Start Test" to begin</div>

    <button id="startBtn" onclick="startTest()">Start Test</button>
    <button id="stopBtn" onclick="stopTest()" disabled>Stop Test</button>

    <h3>Remote Audio (Echo from MIPS)</h3>
    <audio id="remoteAudio" autoplay controls></audio>

    <h3>Connection Stats</h3>
    <pre id="stats"></pre>

    <script>
        let pc = null;
        let localStream = null;

        function setStatus(msg, type) {
            const status = document.getElementById('status');
            status.textContent = msg;
            status.className = type;
        }

        async function startTest() {
            try {
                setStatus('Requesting microphone access...', 'info');

                // Get microphone
                localStream = await navigator.mediaDevices.getUserMedia({
                    audio: true,
                    video: false
                });

                setStatus('Creating peer connection...', 'info');

                // Create peer connection
                pc = new RTCPeerConnection({
                    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
                });

                // Add audio track
                localStream.getTracks().forEach(track => {
                    pc.addTrack(track, localStream);
                });

                // Handle remote audio
                pc.ontrack = (event) => {
                    console.log('Got remote track:', event.track.kind);
                    document.getElementById('remoteAudio').srcObject = event.streams[0];
                    setStatus('Audio connected! You should hear your echo.', 'success');
                };

                pc.oniceconnectionstatechange = () => {
                    console.log('ICE state:', pc.iceConnectionState);
                    if (pc.iceConnectionState === 'connected') {
                        setStatus('Connected! Audio streaming...', 'success');
                        updateStats();
                    } else if (pc.iceConnectionState === 'failed') {
                        setStatus('Connection failed', 'error');
                    }
                };

                // Create offer
                setStatus('Creating offer...', 'info');
                const offer = await pc.createOffer();
                await pc.setLocalDescription(offer);

                // Wait for ICE gathering
                await new Promise(resolve => {
                    if (pc.iceGatheringState === 'complete') {
                        resolve();
                    } else {
                        pc.onicegatheringstatechange = () => {
                            if (pc.iceGatheringState === 'complete') resolve();
                        };
                        // Timeout after 3 seconds
                        setTimeout(resolve, 3000);
                    }
                });

                setStatus('Sending offer to server...', 'info');

                // Send to server
                const response = await fetch('/offer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sdp: pc.localDescription.sdp, type: pc.localDescription.type })
                });

                if (!response.ok) {
                    throw new Error('Server error: ' + response.status);
                }

                const answer = await response.json();
                setStatus('Got answer, connecting...', 'info');

                await pc.setRemoteDescription(new RTCSessionDescription(answer));

                document.getElementById('startBtn').disabled = true;
                document.getElementById('stopBtn').disabled = false;

            } catch (err) {
                setStatus('Error: ' + err.message, 'error');
                console.error(err);
            }
        }

        function stopTest() {
            if (localStream) {
                localStream.getTracks().forEach(track => track.stop());
            }
            if (pc) {
                pc.close();
            }
            document.getElementById('remoteAudio').srcObject = null;
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            setStatus('Stopped', 'info');
        }

        function updateStats() {
            if (!pc) return;
            pc.getStats().then(stats => {
                let output = '';
                stats.forEach(report => {
                    if (report.type === 'inbound-rtp' && report.kind === 'audio') {
                        output += 'Inbound Audio:\n';
                        output += '  Packets: ' + report.packetsReceived + '\n';
                        output += '  Bytes: ' + report.bytesReceived + '\n';
                    }
                    if (report.type === 'outbound-rtp' && report.kind === 'audio') {
                        output += 'Outbound Audio:\n';
                        output += '  Packets: ' + report.packetsSent + '\n';
                        output += '  Bytes: ' + report.bytesSent + '\n';
                    }
                });
                document.getElementById('stats').textContent = output || 'Gathering stats...';
            });
            setTimeout(updateStats, 1000);
        }
    </script>
</body>
</html>`

func main() {
	fmt.Println("WebRTC Audio Echo Server")
	fmt.Println("Open http://localhost:8080 in your browser")
	fmt.Println("Press Ctrl+C to stop")

	// Serve HTML page
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlPage))
	})

	// Handle WebRTC offer
	http.HandleFunc("/offer", handleOffer)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func handleOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	// Read offer
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var offer webrtc.SessionDescription
	if err := json.Unmarshal(body, &offer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Received offer from browser")

	// Create peer connection
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Echo audio back - when we receive a track, send it back
	pc.OnTrack(func(remoteTrack *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		fmt.Printf("Got remote track: %s (codec: %s)\n", remoteTrack.Kind(), remoteTrack.Codec().MimeType)

		// Create a local track to send back (echo)
		localTrack, err := webrtc.NewTrackLocalStaticRTP(
			remoteTrack.Codec().RTPCodecCapability,
			"audio-echo",
			"echo-stream",
		)
		if err != nil {
			fmt.Printf("Failed to create local track: %v\n", err)
			return
		}

		// Add the track to send back
		_, err = pc.AddTrack(localTrack)
		if err != nil {
			fmt.Printf("Failed to add track: %v\n", err)
			return
		}

		// Read from remote and write to local (echo)
		go func() {
			buf := make([]byte, 1500)
			for {
				n, _, err := remoteTrack.Read(buf)
				if err != nil {
					fmt.Printf("Track read error: %v\n", err)
					return
				}
				if _, err = localTrack.Write(buf[:n]); err != nil {
					fmt.Printf("Track write error: %v\n", err)
					return
				}
			}
		}()
	})

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		fmt.Printf("ICE Connection State: %s\n", state.String())
	})

	// Set remote description
	if err := pc.SetRemoteDescription(offer); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create answer
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set local description
	if err := pc.SetLocalDescription(answer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Wait for ICE gathering
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	select {
	case <-gatherComplete:
	case <-time.After(5 * time.Second):
		fmt.Println("ICE gathering timeout, proceeding anyway")
	}

	// Send answer
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pc.LocalDescription())

	fmt.Println("Sent answer to browser")
}
