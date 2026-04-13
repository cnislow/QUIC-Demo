package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
	wt "github.com/quic-go/webtransport-go"
)

func main() {
	certFile := "../wt-cert.pem"
	keyFile := "../wt-key.pem"

	// Load cert and build tls.Config explicitly (matching the webtransport-go
	// interop test pattern) rather than using ListenAndServeTLS. This ensures
	// the Leaf field is populated so we can derive the hash, and avoids any
	// internal tls.Config reconstruction that ListenAndServeTLS does.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal(err)
	}
	tlsCert.Leaf = leaf

	certHash := sha256.Sum256(leaf.Raw)
	log.Printf("Cert SHA-256: %s", hex.EncodeToString(certHash[:]))

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("HTTP/3 request:", r.Proto, r.URL.Path)
		w.Write([]byte("WebTransport server running\n"))
	})

	var wtServer *wt.Server

	mux.HandleFunc("/wt/", func(w http.ResponseWriter, r *http.Request) {
		log.Println("WebTransport upgrade attempt from", r.RemoteAddr)

		session, err := wtServer.Upgrade(w, r)
		if err != nil {
			log.Println("Upgrade error:", err)
			return
		}

		log.Println("WebTransport session established")
		go handleSession(session)
	})

	wtServer = &wt.Server{
		H3: http3.Server{
			Addr:      ":4433",
			Handler:   mux,
			TLSConfig: tlsConf,
		},
		// Allow cross-origin connections (our static server is on :8443,
		// the QUIC server is on :4433 — different ports = different origins).
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	log.Println("Starting HTTP/3 + WebTransport server on :4433")
	log.Fatal(wtServer.ListenAndServe())
}

func handleSession(sess *wt.Session) {
	// Immediately open a server-initiated unidirectional stream and stream video.
	go streamVideo(sess)

	// Accept browser-initiated unidirectional streams (camera upload).
	go acceptCameraStreams(sess)

	ctx := context.Background()
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			log.Println("AcceptStream error:", err)
			return
		}
		go handleStream(stream)
	}
}

// acceptCameraStreams loops accepting browser-initiated unidirectional streams
// and spawns a goroutine to drain each one.
func acceptCameraStreams(sess *wt.Session) {
	ctx := context.Background()
	for {
		stream, err := sess.AcceptUniStream(ctx)
		if err != nil {
			log.Println("AcceptUniStream error:", err)
			return
		}
		log.Println("Camera: browser-initiated unidirectional stream accepted")
		go receiveCameraStream(stream)
	}
}

// receiveCameraStream reads the binary-framed camera data sent by the browser,
// logs each frame header, and discards the payload.
//
// Frame wire format (same as writeFrame / Sub-step A):
//
//	[4 B BE] frame_number
//	[8 B BE] timestamp_microseconds
//	[1 B   ] frame_type  (0x01 = keyframe, 0x00 = delta)
//	[4 B BE] payload_length
//	[N B   ] payload (Annex B H.264 data — discarded)
func receiveCameraStream(stream *wt.ReceiveStream) {
	const hdrSize = 17
	var hdr [hdrSize]byte
	var totalFrames int
	var totalBytes int64

	for {
		if _, err := io.ReadFull(stream, hdr[:]); err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Println("Camera: header read error:", err)
			}
			break
		}

		frameNum := binary.BigEndian.Uint32(hdr[0:4])
		timestamp := binary.BigEndian.Uint64(hdr[4:12])
		frameType := hdr[12]
		payloadLen := binary.BigEndian.Uint32(hdr[13:17])

		frameTypeName := "delta"
		if frameType == 0x01 {
			frameTypeName = "keyframe"
		}
		log.Printf("Camera: frame=%d type=%s timestamp=%dµs payload=%dB",
			frameNum, frameTypeName, timestamp, payloadLen)

		n, err := io.CopyN(io.Discard, stream, int64(payloadLen))
		totalFrames++
		totalBytes += hdrSize + n

		if err != nil {
			if err != io.EOF {
				log.Println("Camera: payload discard error:", err)
			}
			break
		}
	}

	log.Printf("Camera: stream closed — %d frames, %d bytes total", totalFrames, totalBytes)
}

// streamVideo opens a unidirectional send stream and pushes a pre-encoded
// H.264 Annex B file (test.264) to the browser at ~30 fps.
func streamVideo(sess *wt.Session) {
	ctx := context.Background()

	stream, err := sess.OpenUniStreamSync(ctx)
	if err != nil {
		log.Println("Video: OpenUniStreamSync error:", err)
		return
	}
	defer stream.Close()

	log.Println("Video: unidirectional stream opened")

	data, err := os.ReadFile("test.264")
	if err != nil {
		log.Println("Video: cannot read test.264:", err)
		return
	}

	nals := parseNALUnits(data)
	log.Printf("Video: parsed %d NAL units from test.264", len(nals))

	// Separate SPS / PPS from slice NALs. Only the first SPS and PPS are
	// kept; subsequent ones embedded before IDR frames are skipped because
	// the browser will use the initial pair to configure the decoder.
	var sps, pps []byte
	var videoNALs [][]byte

	for _, nal := range nals {
		if len(nal) == 0 {
			continue
		}
		nalType := nal[0] & 0x1F
		switch {
		case nalType == 7 && sps == nil:
			sps = nal
		case nalType == 8 && pps == nil:
			pps = nal
		case nalType >= 1 && nalType <= 5:
			// Slice NALs: non-IDR (1), partition A/B/C (2-4), IDR (5).
			videoNALs = append(videoNALs, nal)
		// Skip SEI (6), AUD (9), and other non-slice NAL types.
		}
	}

	if sps == nil || pps == nil {
		log.Println("Video: SPS or PPS not found in test.264")
		return
	}
	log.Printf("Video: SPS=%d B, PPS=%d B, video NALs=%d", len(sps), len(pps), len(videoNALs))

	// Send SPS first, then PPS. The browser uses frame_number 0 and 1 to
	// identify these and construct the AVCDecoderConfigurationRecord.
	if err := writeFrame(stream, 0, 0, 0x00, sps); err != nil {
		log.Println("Video: send SPS error:", err)
		return
	}
	if err := writeFrame(stream, 1, 0, 0x00, pps); err != nil {
		log.Println("Video: send PPS error:", err)
		return
	}
	log.Println("Video: SPS and PPS sent")

	// Stream video frames paced at exactly 30 fps.
	ticker := time.NewTicker(time.Second / 30)
	defer ticker.Stop()

	for i, nal := range videoNALs {
		<-ticker.C

		nalType := nal[0] & 0x1F
		frameType := byte(0x00)
		if nalType == 5 { // IDR slice → keyframe
			frameType = 0x01
		}

		frameNum := uint32(i + 2)                  // 0 and 1 are SPS/PPS
		timestamp := uint64(i) * 1_000_000 / 30    // µs from stream start

		if err := writeFrame(stream, frameNum, timestamp, frameType, nal); err != nil {
			log.Printf("Video: send frame %d error: %v", frameNum, err)
			return
		}
		if i == 0 {
			log.Printf("Video: first video NAL sent (NAL type=%d, frameType=0x%02x)", nalType, frameType)
		}
	}

	log.Println("Video: stream complete")
}

// writeFrame serialises one frame onto w using the binary framing format:
//
//	[4 B BE] frame_number
//	[8 B BE] timestamp_microseconds
//	[1 B   ] frame_type  (0x01 = keyframe, 0x00 = delta)
//	[4 B BE] payload_length
//	[N B   ] payload
func writeFrame(w io.Writer, frameNum uint32, timestamp uint64, frameType byte, payload []byte) error {
	var hdr [17]byte
	binary.BigEndian.PutUint32(hdr[0:4], frameNum)
	binary.BigEndian.PutUint64(hdr[4:12], timestamp)
	hdr[12] = frameType
	binary.BigEndian.PutUint32(hdr[13:17], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// parseNALUnits splits an H.264 Annex B byte stream into individual NAL unit
// payloads (without start codes). It handles both 3-byte (00 00 01) and
// 4-byte (00 00 00 01) start codes and strips trailing zero bytes that are
// part of the byte-stream syntax rather than the NAL unit itself.
func parseNALUnits(data []byte) [][]byte {
	type startCode struct{ pos, length int }
	var scs []startCode

	for i := 0; i < len(data); i++ {
		if i+4 <= len(data) && data[i] == 0 && data[i+1] == 0 && data[i+2] == 0 && data[i+3] == 1 {
			scs = append(scs, startCode{i, 4})
			i += 3 // skip to byte after start code on next iteration
		} else if i+3 <= len(data) && data[i] == 0 && data[i+1] == 0 && data[i+2] == 1 {
			scs = append(scs, startCode{i, 3})
			i += 2
		}
	}

	nals := make([][]byte, 0, len(scs))
	for idx, sc := range scs {
		nalStart := sc.pos + sc.length
		nalEnd := len(data)
		if idx+1 < len(scs) {
			nalEnd = scs[idx+1].pos
			// Strip trailing zero bytes that are part of the next start code
			// prefix rather than meaningful NAL data (RBSP trailing bytes are
			// always non-zero because of the mandatory stop bit).
			for nalEnd > nalStart && data[nalEnd-1] == 0 {
				nalEnd--
			}
		}
		if nalStart < nalEnd {
			nal := make([]byte, nalEnd-nalStart)
			copy(nal, data[nalStart:nalEnd])
			nals = append(nals, nal)
		}
	}
	return nals
}

func handleStream(stream *wt.Stream) {
	defer stream.Close()

	buf := make([]byte, 4096)

	for {
		n, err := stream.Read(buf)
		if n > 0 {
			msg := string(buf[:n])
			log.Println("Received:", msg)
			if _, werr := stream.Write([]byte("echo: " + msg)); werr != nil {
				log.Println("Write error:", werr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Println("Read error:", err)
			}
			return
		}
	}
}
