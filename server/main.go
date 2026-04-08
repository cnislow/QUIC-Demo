package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"

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
