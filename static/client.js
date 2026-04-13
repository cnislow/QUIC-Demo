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

// ---------------------------------------------------------------------------
// AVCDecoderConfigurationRecord builder
//
// This is the binary structure that VideoDecoderConfig.description expects
// for avc1.* codecs. It encodes the SPS and PPS NAL units that tell the
// decoder the resolution, profile, and level of the stream.
//
// Format (ISO 14496-15 §5.3.3.1):
//   1 B  configurationVersion = 1
//   1 B  AVCProfileIndication  (= sps[1])
//   1 B  profile_compatibility (= sps[2])
//   1 B  AVCLevelIndication    (= sps[3])
//   1 B  0xFF  (reserved 6 bits + lengthSizeMinusOne = 3 → 4-byte AVCC lengths)
//   1 B  0xE1  (reserved 3 bits + numSPS = 1)
//   2 B  SPS length (big-endian)
//   N B  SPS NAL data
//   1 B  numPPS = 1
//   2 B  PPS length (big-endian)
//   M B  PPS NAL data
// ---------------------------------------------------------------------------
function buildAVCConfig(sps, pps) {
  const buf = new Uint8Array(11 + sps.length + pps.length);
  const view = new DataView(buf.buffer);
  let o = 0;
  buf[o++] = 1;           // configurationVersion
  buf[o++] = sps[1];     // AVCProfileIndication
  buf[o++] = sps[2];     // profile_compatibility
  buf[o++] = sps[3];     // AVCLevelIndication
  buf[o++] = 0xFF;        // reserved(6) | lengthSizeMinusOne(2) = 0b11111111
  buf[o++] = 0xE1;        // reserved(3) | numSPS(5) = 0b11100001
  view.setUint16(o, sps.length, false); o += 2;
  buf.set(sps, o); o += sps.length;
  buf[o++] = 1;           // numPPS
  view.setUint16(o, pps.length, false); o += 2;
  buf.set(pps, o);
  return buf;
}

function initVideoDecoder(sps, pps) {
  const canvas = document.getElementById("videoCanvas");
  const ctx = canvas.getContext("2d");
  const description = buildAVCConfig(sps, pps);

  const decoder = new VideoDecoder({
    output(frame) {
      ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
      frame.close();
    },
    error(e) {
      console.error("VideoDecoder error:", e);
      log("VideoDecoder error: " + e);
    },
  });

  decoder.configure({
    codec: "avc1.42E01E",
    description: description,   // Uint8Array is a valid BufferSource
    optimizeForLatency: true,
  });

  log("VideoDecoder initialized");
  return decoder;
}

// ---------------------------------------------------------------------------
// Unidirectional stream listener — called once after transport.ready.
// The server opens exactly one such stream and streams video on it.
// ---------------------------------------------------------------------------
function listenForVideoStreams(transport) {
  const reader = transport.incomingUnidirectionalStreams.getReader();

  (async () => {
    try {
      while (true) {
        const { value: stream, done } = await reader.read();
        if (done) break;
        log("Incoming unidirectional stream opened");
        handleVideoStream(stream).catch(e => log("Video stream error: " + e));
      }
    } catch (e) {
      log("incomingUnidirectionalStreams error: " + e);
    }
  })();
}

// ---------------------------------------------------------------------------
// Binary frame parser
//
// Wire format per frame (see server/main.go writeFrame):
//   [4 B BE] frame_number
//   [8 B BE] timestamp_microseconds
//   [1 B   ] frame_type  (0x01 keyframe, 0x00 delta)
//   [4 B BE] payload_length
//   [N B   ] NAL unit data (no Annex B start code)
//
// The first two frames (frame_number 0 and 1) carry the SPS and PPS NAL
// units. Once both are received we build the AVCDecoderConfigurationRecord
// and initialise the VideoDecoder. Subsequent frames are fed directly.
//
// Payload data is rewrapped in AVCC format (4-byte big-endian length prefix)
// before being passed to VideoDecoder.decode(), which is what avc1.* expects.
// ---------------------------------------------------------------------------
async function handleVideoStream(stream) {
  const reader = stream.getReader();

  // Accumulation buffer — stream chunks may not align with frame boundaries.
  let buffer = new Uint8Array(0);

  let spsData = null;
  let ppsData = null;
  let decoder = null;
  let firstVideoFrame = true;

  const HEADER_SIZE = 17; // 4 + 8 + 1 + 4

  function appendBuffer(chunk) {
    const next = new Uint8Array(buffer.length + chunk.length);
    next.set(buffer, 0);
    next.set(chunk, buffer.length);
    buffer = next;
  }

  while (true) {
    const { value: chunk, done } = await reader.read();
    if (done) {
      log("Video stream closed by server");
      break;
    }
    appendBuffer(chunk);

    // Drain as many complete frames as the buffer holds.
    while (buffer.length >= HEADER_SIZE) {
      const view = new DataView(buffer.buffer);
      const frameNum  = view.getUint32(0, false);
      const tsHi      = view.getUint32(4, false);
      const tsLo      = view.getUint32(8, false);
      const timestamp = tsHi * 4294967296 + tsLo; // µs; safe as Number for <~4 hours
      const frameType = buffer[12];
      const payloadLen = view.getUint32(13, false);

      if (buffer.length < HEADER_SIZE + payloadLen) break; // wait for more data

      const payload = buffer.slice(HEADER_SIZE, HEADER_SIZE + payloadLen);
      buffer = buffer.slice(HEADER_SIZE + payloadLen);

      if (frameNum === 0) {
        spsData = payload;
        log(`SPS received: ${payload.length} bytes`);

      } else if (frameNum === 1) {
        ppsData = payload;
        log(`PPS received: ${payload.length} bytes`);
        decoder = initVideoDecoder(spsData, ppsData);

      } else {
        if (!decoder) continue;

        if (firstVideoFrame) {
          log(`First video frame received (frame=${frameNum}, type=${frameType === 0x01 ? "key" : "delta"})`);
          firstVideoFrame = false;
        }

        // Wrap the raw NAL payload in AVCC format: [4-byte-BE-length][NAL data].
        // VideoDecoder configured with avc1.* expects AVCC, not Annex B.
        const avcc = new Uint8Array(4 + payload.length);
        new DataView(avcc.buffer).setUint32(0, payload.length, false);
        avcc.set(payload, 4);

        try {
          decoder.decode(new EncodedVideoChunk({
            type: frameType === 0x01 ? "key" : "delta",
            timestamp,
            data: avcc,
          }));
        } catch (e) {
          log(`Decode error (frame ${frameNum}): ${e}`);
        }
      }
    }
  }

  if (decoder) {
    await decoder.flush();
    decoder.close();
  }
}

// ---------------------------------------------------------------------------
// Connect button — establishes the WebTransport session, starts the video
// listener, and opens the existing bidirectional echo stream.
// ---------------------------------------------------------------------------
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
    log("Listening for incoming video stream...");

    // Start listening for the server-initiated unidirectional video stream.
    listenForVideoStreams(transport);

    // Open the bidirectional echo stream (existing demo).
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
