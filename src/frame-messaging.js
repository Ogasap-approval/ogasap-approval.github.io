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

// Latest-wins for messages whose handling awaits: `begin()` on arrival, and after any await apply only
// if `isCurrent(token)`. Without it an older "state" whose bundle validation finishes last would
// overwrite a newer one, bringing back a bundle the shell had already removed.
export function createLatestOnly() {
  let latest = 0;
  return {
    begin() {
      latest += 1;
      return latest;
    },
    isCurrent(token) {
      return token === latest;
    }
  };
}
