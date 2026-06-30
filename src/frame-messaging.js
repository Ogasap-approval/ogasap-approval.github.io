// Pure postMessage trust predicate shared by the kernel iframe and (logically)
// the app shell. A message is only trusted when it comes from the expected
// window handle, from the expected origin, and carries the expected
// `source` discriminator. Pulling this out keeps the origin check (issue #25)
// behaviourally testable in node without a DOM (see test/frame-messaging.test.mjs).
export function isTrustedFrameMessage(event, { source, origin, kind } = {}) {
  if (!event || typeof event !== "object") {
    return false;
  }
  if (source !== undefined && event.source !== source) {
    return false;
  }
  if (event.origin !== origin) {
    return false;
  }
  return event.data?.source === kind;
}
