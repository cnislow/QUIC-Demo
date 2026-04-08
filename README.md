# quic-demo

A minimal WebTransport echo demo over HTTP/3 (QUIC). A browser connects to a Go server, opens a bidirectional stream, sends a message, and receives it echoed back.

```
Browser (localhost:8443)
  └── WebTransport over QUIC
        └── Go server (127.0.0.1:4433)
              └── echo: Hello QUIC!
```

## Prerequisites

- **Go 1.23+**
- **OpenSSL** (for cert generation — ships with macOS via Homebrew or the system)
- **mkcert** (for the static server's HTTPS cert)
- **Chrome** (WebTransport requires a Chromium-based browser)

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

### 2. Generate the static server cert (mkcert)

The static server runs over HTTPS so Chrome will serve the page in a secure context. mkcert creates a cert your browser trusts for regular HTTPS.

```bash
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1
```

This writes `cert.pem` and `key.pem` to the project root. `static-server/main.go` reads them from `../cert.pem` and `../key.pem`.

### 3. Generate the WebTransport cert

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
3. Click **Connect** — status should change to "Connected!"
4. Click **Send Message** — you should see `Received: echo: Hello QUIC!`

## Project structure

```
quic-demo/
├── server/
│   └── main.go          # HTTP/3 + WebTransport echo server (UDP :4433)
├── static-server/
│   └── main.go          # HTTPS static file server (:8443)
├── static/
│   ├── index.html       # Demo UI
│   └── client.js        # WebTransport browser client
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
