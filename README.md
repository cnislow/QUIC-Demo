# quic-demo

A WebTransport demo over HTTP/3 (QUIC) with three concurrent streams on a single connection:

- **Server → Browser:** Go server streams a pre-encoded H.264 file over a server-initiated unidirectional stream. The browser decodes it with WebCodecs and renders it to a canvas.
- **Browser → Server:** The browser captures live camera video, encodes it with WebCodecs (H.264 Annex B), and ships the encoded frames over a browser-initiated unidirectional stream. The server accepts, logs each frame header, and discards the payload.
- **Bidirectional echo:** A bidi stream for testing round-trip messaging.

```
Browser (localhost:8443)
  └── WebTransport over QUIC
        └── Go server (127.0.0.1:4433)
              ├── → unidirectional stream (server-initiated): H.264 video frames (30 fps)
              ├── ← unidirectional stream (browser-initiated): encoded camera frames
              └── ↔ bidirectional stream: echo: Hello QUIC!
```

## Prerequisites

- **Go 1.23+**
- **OpenSSL** (for cert generation — ships with macOS via Homebrew or the system)
- **mkcert** (for the static server's HTTPS cert)
- **ffmpeg** (for generating the test video — `brew install ffmpeg`)
- **Chrome** (WebTransport and WebCodecs require a Chromium-based browser)

Install mkcert if you don't have it:

```bash
brew install mkcert
mkcert -install   # installs the local CA into your system trust store
```

## Setup

### 1. Clone and install dependencies

```bash
git clone <repo-url>
cd quic-demo
go mod download
```

### 2. Generate the test video

The server streams `server/test.264` — a raw H.264 Annex B bitstream. Generate a 10-second test clip using ffmpeg:

```bash
ffmpeg -f lavfi -i testsrc=duration=10:size=640x480:rate=30 \
       -c:v libx264 -profile:v baseline -level 3.0 \
       -x264-params "annexb=1" -an \
       server/test.264
```

Flags explained:
- `-f lavfi -i testsrc=...` — generates a synthetic test card (no input file needed)
- `-profile:v baseline -level 3.0` — matches the `avc1.42E01E` codec string hardcoded in the browser client; other profiles will fail to decode
- `-x264-params "annexb=1"` — ensures the output uses Annex B start codes (`00 00 00 01`) rather than AVCC length-prefixed format, which is what the Go parser expects
- `-an` — strips audio (WebCodecs video-only path)

`test.264` is git-ignored. Re-run this command any time you want a fresh clip, or substitute any other Annex B H.264 baseline file at that path.

### 3. Generate the static server cert (mkcert)

The static server runs over HTTPS so Chrome will serve the page in a secure context. mkcert creates a cert your browser trusts for regular HTTPS.

```bash
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1
```

This writes `cert.pem` and `key.pem` to the project root. `static-server/main.go` reads them from `../cert.pem` and `../key.pem`.

### 4. Generate the WebTransport cert

The QUIC server needs its own short-lived cert. Chrome's WebTransport stack uses a separate certificate verifier (`serverCertificateHashes`) that **does not** use the system trust store — even mkcert certs won't work here. Instead, we pin the cert's SHA-256 fingerprint directly in the client JavaScript.

Chrome enforces that this cert has a validity of **14 days or less**, which is why it's separate from the mkcert cert.

```bash
chmod +x gen-cert.sh  # only needed once after a fresh clone
./gen-cert.sh # execute this standalone command on subsequent runs
```

This generates `wt-cert.pem` / `wt-key.pem` and patches the fingerprint in `static/client.js` automatically.

> **Note:** `wt-cert.pem` expires every 14 days. Re-run `./gen-cert.sh` and restart the QUIC server when it does.

## Running

Open two terminal tabs from the project root:

**Terminal 1 — QUIC server (WebTransport on UDP :4433)**

```bash
cd server && go run main.go
```

Expected output:
```
Cert SHA-256: <hex fingerprint>
Starting HTTP/3 + WebTransport server on :4433
```

**Terminal 2 — Static file server (HTTPS on :8443)**

```bash
cd static-server && go run main.go
```

Expected output:
```
Serving static files on https://localhost:8443
```

## Using the demo

1. Open Chrome and navigate to **`https://localhost:8443`**
2. If prompted, accept the certificate warning for the static server (only needed once after a fresh mkcert install)
3. Click **Connect** — status changes to "Connected!" and the server immediately begins streaming video
4. The canvas starts rendering decoded H.264 frames within a second or two
5. Click **Send Message** to test the echo stream — you should see `Received: echo: Hello QUIC!` in the log

### Camera upload (browser → server)

6. Click **Start Camera** — the browser prompts for camera permission, then:
   - The small preview element shows the live camera feed
   - A browser-initiated unidirectional stream opens on the existing WebTransport connection
   - A `VideoEncoder` (H.264 Baseline, 640×480, 1 Mbps, Annex B) encodes incoming frames
   - Each encoded chunk is framed with a 17-byte binary header and written to the stream
   - The server logs each received frame: number, type (keyframe/delta), timestamp, and payload size
7. Click **Stop Camera** to stop the track, flush the encoder, and close the stream. The server logs a summary of total frames and bytes received.

The camera upload uses the same binary framing format as the server-to-browser video stream:

```
[4 B BE] frame_number
[8 B BE] timestamp_microseconds
[1 B   ] frame_type  (0x01 = keyframe, 0x00 = delta)
[4 B BE] payload_length
[N B   ] H.264 Annex B payload
```

> **Note:** The WebTransport session stays open after `test.264` finishes playing. Only the server-initiated unidirectional stream closes; the camera upload stream and echo stream remain fully functional.

## Project structure

```
quic-demo/
├── server/
│   ├── main.go          # HTTP/3 + WebTransport server (UDP :4433)
│   └── test.264         # Pre-encoded H.264 Annex B clip (git-ignored)
├── static-server/
│   └── main.go          # HTTPS static file server (:8443)
├── static/
│   ├── index.html       # Demo UI (canvas, echo controls, camera controls)
│   └── client.js        # WebTransport client: video decode + camera encode + echo stream
├── gen-cert.sh          # Generates wt-cert.pem and patches client.js hash
├── cert.pem / key.pem   # mkcert cert for the static server (git-ignored)
├── wt-cert.pem / wt-key.pem  # Short-lived ECDSA cert for QUIC (git-ignored)
├── go.mod
└── go.sum
```

## Why two separate certs?

| | Static server cert | QUIC server cert |
|---|---|---|
| **Tool** | mkcert | openssl (ECDSA P-256) |
| **Validity** | ~2 years | 14 days max |
| **Trust** | System CA store | Pinned via `serverCertificateHashes` |
| **Port** | TCP :8443 | UDP :4433 |

Chrome's WebTransport implementation verifies QUIC server certificates through its own internal fingerprint verifier, which bypasses the OS trust store entirely. The only supported path for local development is to pin the certificate's SHA-256 hash using the `serverCertificateHashes` WebTransport option — and Chrome requires the cert to have at most 14 days validity for this to work.

## Add to .gitignore

```
cert.pem
key.pem
wt-cert.pem
wt-key.pem
```
