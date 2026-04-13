const logEl = document.getElementById("log");
const statusEl = document.getElementById("status");
const connectBtn = document.getElementById("connectBtn");
const sendBtn = document.getElementById("sendBtn");
const startCameraBtn = document.getElementById("startCameraBtn");
const stopCameraBtn = document.getElementById("stopCameraBtn");
const cameraPreview = document.getElementById("cameraPreview");

let transport;
let bidiStream;
let writer;

// Camera / encoder state
let cameraStream = null;
let videoEncoder = null;
let cameraUniWriter = null;
let encoderOutputCount = 0;

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
// Reads the 1-byte stream-type tag from each incoming stream and dispatches:
//   0x01 → file playback (handleVideoStream)
//   0x02 → live relay    (handleRelayStream)
// ---------------------------------------------------------------------------
function listenForVideoStreams(transport) {
  const reader = transport.incomingUnidirectionalStreams.getReader();

  (async () => {
    try {
      while (true) {
        const { value: stream, done } = await reader.read();
        if (done) break;
        log("Incoming unidirectional stream opened");
        dispatchStream(stream).catch(e => log("Stream dispatch error: " + e));
      }
    } catch (e) {
      log("incomingUnidirectionalStreams error: " + e);
    }
  })();
}

// Reads the first byte of a stream to determine its type, then hands off the
// stream reader and any leftover bytes to the appropriate handler.
async function dispatchStream(stream) {
  const reader = stream.getReader();

  // Accumulate until we have at least 1 byte (first chunk may be empty).
  let buffer = new Uint8Array(0);
  while (buffer.length < 1) {
    const { value, done } = await reader.read();
    if (done) return;
    const next = new Uint8Array(buffer.length + value.length);
    next.set(buffer, 0);
    next.set(value, buffer.length);
    buffer = next;
  }

  const streamType = buffer[0];
  const remainder = buffer.slice(1);

  if (streamType === 0x01) {
    log("Stream type: 0x01 — file playback");
    handleVideoStream(reader, remainder).catch(e => log("Video stream error: " + e));
  } else if (streamType === 0x02) {
    log("Stream type: 0x02 — QUIC relay");
    handleRelayStream(reader, remainder).catch(e => log("Relay stream error: " + e));
  } else {
    log("Unknown stream type: 0x" + streamType.toString(16));
  }
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
async function handleVideoStream(reader, initialData) {
  // Accumulation buffer — stream chunks may not align with frame boundaries.
  // Seed with any bytes already consumed while reading the stream-type tag.
  let buffer = initialData || new Uint8Array(0);

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
// Relay stream handler — receives frames relayed by the server from the
// browser's own camera upload and renders them to the relay canvas.
//
// The relay payload is raw Annex B H.264 data (same format the camera encoder
// outputs). The VideoDecoder is configured without a description so it
// self-initializes from the in-band SPS/PPS NAL units inside keyframes.
// ---------------------------------------------------------------------------
function initRelayDecoder() {
  const canvas = document.getElementById("relayCanvas");
  const ctx = canvas.getContext("2d");

  const decoder = new VideoDecoder({
    output(frame) {
      ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
      frame.close();
    },
    error(e) {
      console.error("Relay VideoDecoder error:", e);
    },
  });

  decoder.configure({
    codec: "avc1.42E01E",
    width: 640,
    height: 480,
    optimizeForLatency: true,
  });

  return decoder;
}

async function handleRelayStream(reader, initialData) {
  console.log("Relay stream opened — initializing relay decoder");
  log("Relay stream opened");

  let buffer = initialData || new Uint8Array(0);
  const decoder = initRelayDecoder();
  const HEADER_SIZE = 17;
  let firstFrame = true;

  function appendBuffer(chunk) {
    const next = new Uint8Array(buffer.length + chunk.length);
    next.set(buffer, 0);
    next.set(chunk, buffer.length);
    buffer = next;
  }

  while (true) {
    const { value: chunk, done } = await reader.read();
    if (done) {
      log("Relay stream closed by server");
      break;
    }
    appendBuffer(chunk);

    while (buffer.length >= HEADER_SIZE) {
      const view = new DataView(buffer.buffer);
      const frameNum   = view.getUint32(0, false);
      const tsHi       = view.getUint32(4, false);
      const tsLo       = view.getUint32(8, false);
      const timestamp  = tsHi * 4294967296 + tsLo;
      const frameType  = buffer[12];
      const payloadLen = view.getUint32(13, false);

      if (buffer.length < HEADER_SIZE + payloadLen) break;

      const payload = buffer.slice(HEADER_SIZE, HEADER_SIZE + payloadLen);
      buffer = buffer.slice(HEADER_SIZE + payloadLen);

      if (firstFrame) {
        log(`Relay: first frame received (frame=${frameNum}, type=${frameType === 0x01 ? "key" : "delta"})`);
        firstFrame = false;
      }

      try {
        decoder.decode(new EncodedVideoChunk({
          type: frameType === 0x01 ? "key" : "delta",
          timestamp,
          data: payload,
        }));
      } catch (e) {
        console.error(`Relay decode error (frame ${frameNum}):`, e);
      }
    }
  }

  if (decoder) {
    await decoder.flush();
    decoder.close();
  }
}

// ---------------------------------------------------------------------------
// Camera capture, VideoEncoder, and browser-initiated unidirectional stream
//
// Wire format per frame (matches server writeFrame / Sub-step A header):
//   [4 B BE] frame_number
//   [8 B BE] timestamp_microseconds  (from EncodedVideoChunk.timestamp)
//   [1 B   ] frame_type  (0x01 keyframe, 0x00 delta)
//   [4 B BE] payload_length
//   [N B   ] Annex B encoded data
// ---------------------------------------------------------------------------
async function sendEncodedChunk(chunk, frameNum) {
  if (!cameraUniWriter) return;

  const payload = new Uint8Array(chunk.byteLength);
  chunk.copyTo(payload);

  const header = new Uint8Array(17);
  const view = new DataView(header.buffer);
  view.setUint32(0, frameNum, false);
  view.setBigUint64(4, BigInt(chunk.timestamp), false);
  header[12] = chunk.type === "key" ? 0x01 : 0x00;
  view.setUint32(13, payload.length, false);

  const packet = new Uint8Array(17 + payload.length);
  packet.set(header, 0);
  packet.set(payload, 17);

  await cameraUniWriter.write(packet);

  if (frameNum === 0) {
    log("First camera frame encoded and sent");
  }
  if (chunk.type === "key") {
    log(`Keyframe sent (frame=${frameNum}, ${payload.length} B)`);
  }
}

startCameraBtn.onclick = async () => {
  startCameraBtn.disabled = true;

  try {
    log("Requesting camera access...");
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { width: 640, height: 480 },
      audio: false,
    });
    cameraPreview.srcObject = cameraStream;
    log("Camera started");

    // Open a browser-initiated unidirectional stream on the existing transport.
    const uniStream = await transport.createUnidirectionalStream();
    cameraUniWriter = uniStream.getWriter();
    log("Camera upload stream opened");

    // Initialise encoder.
    encoderOutputCount = 0;
    videoEncoder = new VideoEncoder({
      output(chunk, _metadata) {
        const frameNum = encoderOutputCount++;
        sendEncodedChunk(chunk, frameNum).catch(e => log("Send chunk error: " + e));
      },
      error(e) {
        log("VideoEncoder error: " + e);
      },
    });

    videoEncoder.configure({
      codec: "avc1.42E01E",      // H.264 Baseline
      width: 640,
      height: 480,
      bitrate: 1_000_000,        // 1 Mbps
      framerate: 30,
      latencyMode: "realtime",
      avc: { format: "annexb" }, // raw Annex B NAL units
    });
    log("VideoEncoder initialized");

    // Pull VideoFrame objects from the camera track via MediaStreamTrackProcessor.
    const track = cameraStream.getVideoTracks()[0];
    const processor = new MediaStreamTrackProcessor({ track });
    const frameReader = processor.readable.getReader();

    stopCameraBtn.disabled = false;

    // Feed frames to the encoder until the track ends or stopCamera() is called.
    let inputFrameCount = 0;
    (async () => {
      try {
        while (true) {
          const { value: frame, done } = await frameReader.read();
          if (done) break;

          const isKeyFrame = inputFrameCount % 60 === 0;
          if (isKeyFrame) {
            log(`Keyframe requested at input frame ${inputFrameCount}`);
          }

          videoEncoder.encode(frame, { keyFrame: isKeyFrame });
          frame.close(); // free GPU memory immediately
          inputFrameCount++;
        }
      } catch (e) {
        if (e.name !== "AbortError") {
          log("Frame read error: " + e);
        }
      }
    })();

  } catch (err) {
    log("Camera error: " + err);
    startCameraBtn.disabled = false;
  }
};

stopCameraBtn.onclick = async () => {
  stopCameraBtn.disabled = true;

  // Stop the media track (causes the processor reader to finish).
  if (cameraStream) {
    cameraStream.getTracks().forEach(t => t.stop());
    cameraStream = null;
    cameraPreview.srcObject = null;
  }

  // Flush pending encoder output before closing.
  if (videoEncoder && videoEncoder.state !== "closed") {
    try {
      await videoEncoder.flush();
    } catch (e) {
      log("Encoder flush error: " + e);
    }
    videoEncoder.close();
    videoEncoder = null;
  }

  // Close the stream to signal EOF to the server.
  if (cameraUniWriter) {
    try {
      await cameraUniWriter.close();
    } catch (e) {
      log("Stream close error: " + e);
    }
    cameraUniWriter = null;
  }

  log(`Camera stopped. Encoded ${encoderOutputCount} frames total.`);
  startCameraBtn.disabled = false;
};

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

    // Camera only needs the transport — enable it as soon as we're connected.
    startCameraBtn.disabled = false;

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
