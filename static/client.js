const logEl = document.getElementById("log");
const statusEl = document.getElementById("status");
const connectBtn = document.getElementById("connectBtn");
const sendBtn = document.getElementById("sendBtn");

let transport;
let bidiStream;
let writer;

function log(msg) {
  console.log(msg);
  logEl.textContent += msg + "\n";
}

// SHA-256 fingerprint of wt-cert.pem as a byte array.
// Must be regenerated when the cert rotates (every 14 days).
// Run: ./gen-cert.sh  — it updates this array automatically.
const CERT_HASH_BYTES = new Uint8Array([
  0xaf, 0x7a, 0x8c, 0x9e, 0xb1, 0xab, 0x4d, 0x15,
  0xb2, 0xd4, 0xc3, 0xa3, 0x7a, 0xe0, 0xa5, 0x39,
  0xd9, 0x46, 0xcb, 0xe7, 0x10, 0x13, 0x1d, 0x3b,
  0x9d, 0xa7, 0x7a, 0x7f, 0x1f, 0xc9, 0xec, 0x4d
]);

connectBtn.onclick = async () => {
  try {
    statusEl.textContent = "Connecting...";
    log("Connecting to WebTransport server...");

    // Connect to 127.0.0.1 (not localhost) — matches the webtransport-go
    // interop test, which uses IP address for serverCertificateHashes.
    transport = new WebTransport("https://127.0.0.1:4433/wt/", {
      serverCertificateHashes: [{
        algorithm: "sha-256",
        value: CERT_HASH_BYTES
      }]
    });

    await transport.ready;
    statusEl.textContent = "Connected!";
    log("Connected!");

    bidiStream = await transport.createBidirectionalStream();
    const reader = bidiStream.readable.getReader();
    writer = bidiStream.writable.getWriter();

    sendBtn.disabled = false;

    (async () => {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        log("Received: " + new TextDecoder().decode(value));
      }
    })();

  } catch (err) {
    statusEl.textContent = "Connection failed";
    log("Error: " + err);
  }
};

sendBtn.onclick = async () => {
  if (!writer) return;
  const msg = "Hello QUIC!";
  log("Sending: " + msg);
  await writer.write(new TextEncoder().encode(msg));
};
