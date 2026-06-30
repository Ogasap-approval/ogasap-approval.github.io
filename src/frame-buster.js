// Clickjacking guard (issue #24).
//
// LIMITATION: GitHub Pages serves static files and cannot emit HTTP response
// headers, so `Content-Security-Policy: frame-ancestors` / `X-Frame-Options`
// are unavailable, and `frame-ancestors` is ignored when delivered via a
// <meta http-equiv> CSP. The page-level CSP in index.html/kernel.html
// therefore cannot stop the document from being framed.
//
// RECOMMENDED REAL FIX: serve `Content-Security-Policy: frame-ancestors 'none'`
// (or an allow-list) from a host that can set response headers, in addition to
// this script.
//
// This module is a defence-in-depth JS frame-buster: if the document is framed
// by a non-same-origin ancestor it blanks the page and tries to break out of
// the frame. Same-origin framing is allowed because the approval shell
// (index.html) legitimately embeds the approval kernel (kernel.html) from the
// same origin.

export function shouldBlockFraming(win) {
  if (!win) {
    return false;
  }
  const top = win.top;
  const self = win.self;
  if (!top || top === self) {
    return false; // not framed
  }
  try {
    // Throws for a cross-origin ancestor; resolves only when same-origin.
    return top.location.origin !== self.location.origin;
  } catch {
    return true; // opaque cross-origin embedder
  }
}

export function enforceFramingPolicy(win, doc) {
  if (!shouldBlockFraming(win)) {
    return false;
  }
  if (doc?.documentElement) {
    try {
      doc.documentElement.replaceChildren();
    } catch {
      // ignore
    }
    try {
      doc.documentElement.style.setProperty("display", "none", "important");
    } catch {
      // ignore
    }
  }
  try {
    win.top.location = win.self.location.href; // attempt to break out of the frame
  } catch {
    // ignore: cross-origin top is not navigable from here
  }
  try {
    win.stop?.();
  } catch {
    // ignore
  }
  return true;
}

if (typeof window !== "undefined") {
  enforceFramingPolicy(window, typeof document !== "undefined" ? document : undefined);
}
