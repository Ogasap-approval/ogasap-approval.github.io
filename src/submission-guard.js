// What the app shell does while an approval is being submitted, kept free of the DOM so it is tested as
// behaviour: it stops its own polling out of the way, and it keeps the screen from locking.
//
// WHY THE POLL HAS TO STOP. The server answers an approval only after it has combined and checked every
// signature the phone sent, one after another on one event loop. On 2026-09-15 that POST took 25.7s, and
// the same phone sent 12 backend-auth nonce requests and 13 signed GETs while it waited: every one of them
// is another threshold signature the same server has to produce, on the same loop, and together they added
// about 8.5s. The shell did try to stop — its "started" handler cleared the timer — but a poll that was
// already in flight re-armed the timer in its `finally`, and from then on the loop simply kept going.

/**
 * A self-rescheduling poll that can be paused.
 *
 *   run({ scheduled })  the poll itself. `scheduled` is true when the timer fired, false for a direct call.
 *                       Return `false` to skip rescheduling (nothing to poll with yet).
 *   canSchedule()       checked whenever the timer would be armed; false leaves it disarmed.
 *
 * While paused NOTHING arms the timer and nothing runs — not a direct call, not a queued follow-up, and not
 * the `finally` of a run that was already in flight when the pause began. `resume()` polls again only if
 * something was held back.
 */
export function createPollScheduler({
  run,
  intervalMs,
  canSchedule = () => true,
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (handle) => clearTimeout(handle)
}) {
  let timer = 0;
  let inFlight = false;
  let queued = false;
  let paused = false;
  let heldBack = false;

  function clear() {
    if (timer) {
      clearTimer(timer);
      timer = 0;
    }
  }

  function schedule(delayMs = intervalMs) {
    clear();
    if (paused) {
      heldBack = true;
      return false;
    }
    if (!canSchedule()) {
      return false;
    }
    timer = setTimer(() => {
      timer = 0;
      runNow({ scheduled: true });
    }, delayMs);
    return true;
  }

  async function runNow({ queueIfBusy = false, scheduled = false } = {}) {
    if (paused) {
      heldBack = true;
      return;
    }
    if (inFlight) {
      if (queueIfBusy) {
        queued = true;
      }
      return;
    }
    clear();
    inFlight = true;
    let reschedule = true;
    try {
      reschedule = (await run({ scheduled })) !== false;
    } finally {
      inFlight = false;
      if (paused) {
        // THE BUG THIS REPLACES. This run started before the pause; its end must not restart the loop.
        queued = false;
        heldBack = true;
      } else if (queued) {
        queued = false;
        runNow();
      } else if (reschedule) {
        schedule();
      }
    }
  }

  return {
    runNow,
    schedule,
    clear,
    // Drop the timer and any queued follow-up without pausing: the app lock, a reset.
    cancel() {
      clear();
      queued = false;
    },
    pause() {
      if (timer || inFlight || queued) {
        // The loop was alive; resume() must bring it back rather than leave it dead.
        heldBack = true;
      }
      paused = true;
      clear();
      queued = false;
    },
    resume(delayMs = intervalMs) {
      if (!paused) {
        return false;
      }
      paused = false;
      const due = heldBack;
      heldBack = false;
      return due ? schedule(delayMs) : false;
    },
    get paused() {
      return paused;
    },
    get inFlight() {
      return inFlight;
    },
    get armed() {
      return Boolean(timer);
    },
    get queued() {
      return queued;
    }
  };
}

/**
 * A Screen Wake Lock held for as long as something is `hold()`-ing it.
 *
 * The phone's auto-lock can be 30 seconds, shorter than an approval takes today, and a lock that fires in the
 * middle of one is exactly what the submission screen asks the holder not to do. The browser releases a
 * wake lock whenever the page is hidden, so it is re-requested each time the page is visible again while
 * still wanted.
 *
 * Silent everywhere it cannot work: no API (iOS home-screen apps before 18.4, older browsers), a refusal
 * (battery saver, permissions policy), a page that is not visible. The screen still says what it says; this
 * only removes one way of ending up in the case it warns about.
 */
export function createScreenWakeLock({
  getWakeLock = () => globalThis.navigator?.wakeLock,
  isVisible = () => globalThis.document?.visibilityState === "visible"
} = {}) {
  let wanted = false;
  let sentinel = null;
  let requesting = null;

  function held() {
    return Boolean(sentinel && sentinel.released !== true);
  }

  async function acquire() {
    if (!wanted || held() || requesting) {
      return requesting ?? undefined;
    }
    const wakeLock = getWakeLock();
    if (typeof wakeLock?.request !== "function" || !isVisible()) {
      return undefined;
    }
    const attempt = (async () => {
      try {
        const lock = await wakeLock.request("screen");
        if (!wanted) {
          // Released while the request was pending: give it straight back.
          await lock?.release?.().catch?.(() => {});
          return;
        }
        sentinel = lock;
        lock?.addEventListener?.("release", () => {
          if (sentinel === lock) {
            sentinel = null;
          }
        });
      } catch {
        // Refused or unavailable in this context. Degrade silently.
      }
    })();
    requesting = attempt;
    try {
      await attempt;
    } finally {
      if (requesting === attempt) {
        requesting = null;
      }
    }
    return undefined;
  }

  return {
    get supported() {
      return typeof getWakeLock()?.request === "function";
    },
    get held() {
      return held();
    },
    hold() {
      wanted = true;
      return acquire();
    },
    release() {
      wanted = false;
      const lock = sentinel;
      sentinel = null;
      if (lock && lock.released !== true) {
        return Promise.resolve(lock.release?.()).catch(() => {});
      }
      return Promise.resolve();
    },
    // Wire to `visibilitychange`. A no-op unless still wanted and visible again.
    handleVisibilityChange() {
      return acquire();
    }
  };
}
