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

// RENEW BANK ACCESS BEFORE THE FIRST APPROVAL OF A SESSION.
//
// The Nordea access token lives about an hour, and only an unlocked phone can renew it: the service holds
// two of the three shares the renewal needs. So a holder who opens the app, approves and closes it within a
// few seconds used to approve against a dead token — the renewal was only looked for on the poll's TIMED
// ticks, the approval paused the poll, and on 2026-10-18 the holder had left by the time the first check
// ran. The service held the bundle (nofipa-payments #62) and it went out three hours later, after a second
// approval, when somebody next opened the app.
//
// So the shell checks on EVERY poll, timed or not, and it holds Approve from the moment a share is
// installed until a check has PROVED there is nothing left for this phone to sign. "The check finished" is
// not proof: a fetch can fail, a chain can pause on a backoff, a mint can throw. Only the answers below are.

export const BANK_ACCESS_HOLD_MS = 20_000;
// A pass this old is not joined: whatever it is waiting on is not going to answer, and polling must go on.
export const BANK_ACCESS_PASS_JOIN_MS = 30_000;

// The service's positive "no phone signature is wanted now": its flow found nothing to request at the
// holder-present threshold, or it renewed without one.
const NOTHING_TO_SIGN = new Set(["ready", "refreshed_server_side"]);

/**
 * What the FINAL check of a pass proves.
 *
 *   "ok"             the service said there is nothing for a phone to sign.
 *   "not_designated" an empty answer: this phone cannot renew (it is not a designated approver, or the
 *                    service's automatic flow is off), so holding it would help nobody. The service always
 *                    gives a designated approver a reason when it sends no request — a failed mint says
 *                    "mint_failed" — so an empty body cannot be a renewal that went wrong.
 *   "unconfirmed"    everything else, in this order: no answer, a request still pending, any other reason.
 */
export function classifyBankAccess(result) {
  if (!result || result.fetched !== true || result.current === false) return "unconfirmed";
  if (result.hasRequest) return "unconfirmed";
  const progress = result.flowProgress ?? null;
  if (NOTHING_TO_SIGN.has(result.suppression) && (!progress || progress.state === "ready")) return "ok";
  if (!progress && !result.suppression) return "not_designated";
  return "unconfirmed";
}

/**
 * One admin pass at a time, owned by a context generation, and the Approve hold that goes with it.
 *
 *   runPass({ isCurrent, onAutoSignable })  one renewal pass; resolves to the FINAL check's result
 *                                            ({ fetched, current, hasRequest, suppression, flowProgress }).
 *                                            `isCurrent()` goes false once the pass is superseded, and the
 *                                            pass must not sign or submit anything after that.
 *   onChange()                               the published state changed; re-send it to the kernel.
 *
 *   state   "renewing"     Approve is held.
 *           "unconfirmed"  a hold ran out without proof; Approve is back, with a warning.
 *           "ok"           nothing to wait for.
 *
 * Releasing a hold never cancels a request already sent: a pass whose hold ran out keeps running, and
 * if it ends in proof it still clears "unconfirmed" to "ok". Only a SUPERSEDED pass (a newer pass, a
 * new context, cancelPasses, invalidate) has its answer ignored.
 */
export function createBankAccessGuard({
  runPass,
  onChange = () => {},
  now = () => Date.now(),
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (handle) => clearTimeout(handle),
  holdMs = BANK_ACCESS_HOLD_MS,
  joinMs = BANK_ACCESS_PASS_JOIN_MS
}) {
  let generation = 0;
  let pass = null; // { generation, startedAt, promise }
  let hold = null; // { generation, timer }
  let outcome = "ok";

  function publish(previous) {
    if (current() !== previous) onChange();
  }

  function current() {
    return hold ? "renewing" : outcome;
  }

  function endHold() {
    if (hold) {
      clearTimer(hold.timer);
      hold = null;
    }
  }

  function startHold() {
    endHold();
    const owner = { generation, timer: 0 };
    owner.timer = setTimer(() => {
      if (hold !== owner) return;
      const previous = current();
      hold = null;
      outcome = "unconfirmed";
      publish(previous);
    }, holdMs);
    hold = owner;
  }

  function settle(owner, result) {
    if (pass !== owner) return; // superseded or invalidated: its answer means nothing now
    pass = null;
    const previous = current();
    const verdict = classifyBankAccess(result);
    if (verdict === "unconfirmed") {
      // A hold stays until proof or its cap; the next poll runs another pass. Without a hold, a
      // previously confirmed state is left alone — one failed background check is not news.
      return;
    }
    if (hold?.generation === owner.generation) endHold();
    outcome = "ok";
    publish(previous);
  }

  return {
    // A new share is about to be installed. Call it synchronously right before the assignment, so that
    // every state the kernel is sent from then on already carries the hold.
    beginContext() {
      const previous = current();
      generation += 1;
      pass = null;
      outcome = "ok";
      startHold();
      publish(previous);
    },
    // Something is about to replace the share but may still be cancelled (a reset awaiting WebAuthn, an
    // enrollment validating its package): stop every pass now, and keep the hold and the warning, because
    // if the operation is abandoned the share on screen is still the one they were protecting.
    cancelPasses() {
      generation += 1;
      pass = null;
      if (hold) hold.generation = generation;
    },
    // The share is gone (lock, reset done): drop the pass and the hold.
    invalidate() {
      const previous = current();
      generation += 1;
      pass = null;
      endHold();
      outcome = "ok";
      publish(previous);
    },
    // Called on every poll run. Joins a young pass of this generation, or starts one.
    poll() {
      if (pass && pass.generation === generation && now() - pass.startedAt < joinMs) {
        return pass.promise;
      }
      const owner = { generation, startedAt: now(), promise: null };
      pass = owner;
      const isCurrent = () => pass === owner;
      const onAutoSignable = () => {
        // A later request about to be signed: hold Approve until it settles (or the cap). Not after a cap
        // has already run out unproven: the hold is spent, and re-arming it on every retry of the same
        // failing request would disable Approve for 20 s out of every few. Only proof (-> "ok") or a new
        // context earns a fresh hold.
        if (!isCurrent() || hold || outcome === "unconfirmed") return;
        const previous = current();
        startHold();
        publish(previous);
      };
      owner.promise = Promise.resolve()
        .then(() => runPass({ isCurrent, onAutoSignable }))
        .catch(() => null)
        .then((result) => settle(owner, result));
      return owner.promise;
    },
    get state() {
      return current();
    },
    get generation() {
      return generation;
    }
  };
}

// A pending-admin-request GET that never answers would otherwise stall the pass, and with it the renewal,
// for as long as the socket stays open. Abandoning a READ is safe: the controller treats it as a failed
// fetch, and a late answer is simply dropped. (The admin POST is not wrapped: once it is sent its outcome
// is uncertain, and pretending it was cancelled would be worse than waiting for it.)
export const ADMIN_FETCH_TIMEOUT_MS = 15_000;

export function withTimeout(promise, ms, { setTimer = (fn, delay) => setTimeout(fn, delay), clearTimer = (handle) => clearTimeout(handle) } = {}) {
  let handle = 0;
  const timeout = new Promise((_resolve, reject) => {
    handle = setTimer(() => reject(new Error("timed out")), ms);
  });
  return Promise.race([Promise.resolve(promise), timeout]).finally(() => clearTimer(handle));
}

/**
 * One renewal pass over the real admin-request controller: refresh, sign what may be signed unattended,
 * then check once more — that last answer is what the guard classifies, because a chain ending "paused"
 * can mean done or backing off, and only the service can say which.
 *
 * A running chain belongs to the pass that started it. A pass that has been superseded (a lock, a new
 * context, a pass older than the join window) no longer blocks anybody: the next pass refreshes and, if
 * the old chain still holds the controller, finds the request not approvable and stays unconfirmed. That
 * keeps signing serialised without letting one hung chain stop renewal for the rest of the session.
 */
export function createAdminRenewalPass({ controller, runChain, render = () => {} }) {
  let chainOwner = null; // the isCurrent of the pass whose chain is running

  return async function runRenewalPass({ isCurrent = () => true, onAutoSignable = () => {} } = {}) {
    // A chain in flight runs its own refresh before every step; refreshing underneath it would only churn.
    if (chainOwner?.()) return null;
    const seen = await controller.refresh();
    if (!isCurrent()) return null;
    render();
    const snap = controller.snapshot();
    // The gate is the controller's, derived from the bytes that would be signed: anything else stays on
    // the panel for a human.
    if (!snap.visible || !snap.canApprove || !snap.autoSignable) return seen;
    chainOwner = isCurrent;
    try {
      onAutoSignable();
      await runChain({ isCurrent });
    } finally {
      if (chainOwner === isCurrent) chainOwner = null;
    }
    if (!isCurrent()) return null;
    const after = await controller.refresh();
    if (isCurrent()) render();
    return after;
  };
}

// The status line while a bundle is waiting. A hold that ran out without proof is said for as long as it
// is true, not once: the next poll's "Bundle ready for review" would otherwise erase it within seconds.
export function withBankAccessWarning(bankAccessState, message) {
  return bankAccessState === "unconfirmed"
    ? { message: BANK_ACCESS_UNCONFIRMED_TEXT, level: "warning" }
    : { message, level: "normal" };
}

export const BANK_ACCESS_UNCONFIRMED_TEXT = "Bank access could not be renewed. If you approve now, keep this app open until the payments are authorized.";
