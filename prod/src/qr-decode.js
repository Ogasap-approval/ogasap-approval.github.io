// QR decoding for browsers WITHOUT the Chromium-only BarcodeDetector API.
//
// WHY: BarcodeDetector is not implemented in WebKit, and on iOS every browser
// (Safari, Chrome, Edge, Firefox) is required to use WebKit — so iOS Chrome is a
// Safari skin and lacks BarcodeDetector identically. getUserMedia DOES work on
// iOS, so only the decode step is missing. This module supplies that step with a
// vendored pure-JS decoder (./vendor/jsqr.js), reading pixels from a <canvas>.
//
// createImageDataQrDetector() returns a detector with the same shape app.js
// expects from a native BarcodeDetector instance — `await detect(video)` →
// array of `{ rawValue }` — so scanQrFrame() consumes either interchangeably.

import jsQR from "./vendor/jsqr.js";

// ---------------------------------------------------------------------------
// Pure decode (no DOM; exercised directly by node tests)
// ---------------------------------------------------------------------------

/**
 * Decode a single QR code from raw RGBA pixels.
 *
 * @param {{data: Uint8ClampedArray, width: number, height: number}} image
 *   RGBA pixel buffer, e.g. the result of CanvasRenderingContext2D.getImageData.
 * @param {object} [options]
 * @param {"dontInvert"|"onlyInvert"|"attemptBoth"|"invertFirst"} [options.inversionAttempts]
 *   The app only ever scans its own dark-on-light QR codes (rendered by
 *   qr-encode.js), so "dontInvert" is both sufficient and the fastest choice for
 *   the live per-frame scan loop.
 * @returns {string|null} the decoded text, or null when no QR is found.
 */
export function decodeQrFromImageData(image, { inversionAttempts = "dontInvert" } = {}) {
  if (!image || !image.width || !image.height) {
    return null;
  }
  const result = jsQR(image.data, image.width, image.height, { inversionAttempts });
  return result ? result.data : null;
}

// ---------------------------------------------------------------------------
// BarcodeDetector-shaped fallback detector (browser-only)
// ---------------------------------------------------------------------------

// Upper bound for the decoded square's side (px). The decode square is normally
// just the camera frame's SHORTER edge (see below); this cap only bites for
// genuinely oversized sensors (e.g. a 4K capture) so jsQR — a software decoder
// whose cost scales with pixel count — never has to chew a multi-megapixel
// frame. 1280 keeps a dense (~150-module) enrollment code well above jsQR's
// pixels-per-module floor even after the cap.
export const MAX_DECODE_EDGE = 1280;

/**
 * Build a fallback QR detector that decodes frames from a <video> by drawing
 * them to an offscreen 2D canvas and running the vendored decoder. The returned
 * object mirrors the slice of the BarcodeDetector interface app.js uses:
 * `await detector.detect(video)` resolves to an array of `{ rawValue }`.
 *
 * It decodes a CENTERED SQUARE crop of the frame (side = the shorter edge), not
 * the whole frame. The viewfinder shows the camera with `object-fit: cover` on a
 * 4:3 box and a centered guide (`.qr-frame`, inset 18%), so the QR the user
 * aligns always sits in this central square. Cropping to it drops the
 * off-screen long-edge margins — fewer pixels AND much less background for
 * jsQR's finder-pattern locator, which raises the per-frame hit rate (the real
 * reason WebKit/iOS scanning felt like it "eventually" caught the code) — while
 * keeping the QR at FULL resolution, so dense enrollment codes do not regress.
 * Crucially this does not shrink the short edge the way a longest-edge downscale
 * would in portrait. Only an oversized square (side > maxDecodeEdge) is scaled
 * down, to the cap.
 *
 * @param {object} [options]
 * @param {Document} [options.document] document used to create the scratch
 *   canvas; defaults to the global `document`.
 * @param {number} [options.maxDecodeEdge] cap for the decoded square's side, px.
 * @returns {{detect: (video: HTMLVideoElement) => Promise<Array<{rawValue: string}>>}}
 */
export function createImageDataQrDetector({ document: doc = globalThis.document, maxDecodeEdge = MAX_DECODE_EDGE } = {}) {
  let canvas = null;
  let ctx = null;

  return {
    async detect(video) {
      const sourceWidth = video?.videoWidth ?? 0;
      const sourceHeight = video?.videoHeight ?? 0;
      // The stream may not have produced a frame yet (videoWidth === 0). Return
      // no codes so scanQrFrame() simply tries again on its next tick.
      if (!sourceWidth || !sourceHeight) {
        return [];
      }
      // Centered square crop of the shorter edge; downscaled only if it exceeds
      // the cap (never upscaled).
      const side = Math.min(sourceWidth, sourceHeight);
      const sx = Math.round((sourceWidth - side) / 2);
      const sy = Math.round((sourceHeight - side) / 2);
      const dim = Math.min(side, maxDecodeEdge);
      if (!canvas) {
        canvas = doc.createElement("canvas");
        // willReadFrequently keeps getImageData on the fast (software) path,
        // which matters for the repeated per-frame reads of the scan loop.
        ctx = canvas.getContext("2d", { willReadFrequently: true });
      }
      if (canvas.width !== dim || canvas.height !== dim) {
        canvas.width = dim;
        canvas.height = dim;
      }
      // Crop the centered source square and (only if oversized) scale it to dim.
      ctx.drawImage(video, sx, sy, side, side, 0, 0, dim, dim);
      const rawValue = decodeQrFromImageData(ctx.getImageData(0, 0, dim, dim));
      return rawValue ? [{ rawValue }] : [];
    }
  };
}

// ---------------------------------------------------------------------------
// Detector selection (browser capabilities injected so it is node-testable)
// ---------------------------------------------------------------------------

/**
 * Choose a QR detector for the current browser. Prefers the native (Chromium)
 * BarcodeDetector when it actually supports QR — it offloads decoding to the
 * platform — and otherwise returns the vendored canvas+jsQR fallback used by
 * WebKit/iOS (Safari and every iOS browser, which are all WebKit). A genuinely
 * absent camera is the only hard failure: without getUserMedia even the
 * fallback has no frames to read.
 *
 * Browser globals are passed in rather than read directly so every branch is
 * unit-testable without a DOM. app.js supplies the real ones.
 *
 * @param {object} caps
 * @param {boolean} caps.hasCamera whether navigator.mediaDevices.getUserMedia exists.
 * @param {(new (opts: object) => {detect: Function})|null} [caps.BarcodeDetector]
 *   the native BarcodeDetector constructor, or null/undefined when absent.
 * @param {() => {detect: Function}} [caps.createFallback] builds the fallback
 *   detector; defaults to createImageDataQrDetector().
 * @returns {Promise<{detect: Function}>}
 */
export async function createQrDetector({ hasCamera, BarcodeDetector = null, createFallback = () => createImageDataQrDetector() }) {
  if (!hasCamera) {
    throw new Error("Camera access is unavailable in this browser. Use Enroll Package.");
  }
  if (BarcodeDetector) {
    const supported = await BarcodeDetector.getSupportedFormats?.();
    if (!supported || supported.includes("qr_code")) {
      return new BarcodeDetector({ formats: ["qr_code"] });
    }
  }
  return createFallback();
}
