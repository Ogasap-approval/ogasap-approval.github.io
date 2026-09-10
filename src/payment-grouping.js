import { base64urlToBytes } from "./core/crypto/bytes.js";
import { stableStringify } from "./core/protocol/canonical.js";
import { deriveVisiblePaymentFromInput } from "./payment-view.js";

// ---- split-payout grouping ---------------------------------------------------------------------
//
// A payout above the bank's per-payment cap is fanned out server-side into N bank instructions whose
// external ids are "<base>:part-01".."<base>:part-99" (nofipa-payments/src/lib/payout-split.js). The
// approver cares about the payout, not the instruction, so those rows are shown as ONE row carrying
// the summed amount -- while all N instructions are still signed and still sent to the bank.
//
// WHAT THIS IS NOT: `request_id` being hashed into bank_request_hash makes the marker tamper-EVIDENT,
// not authentic. The server chooses bundle contents up front and recomputes every commitment, so
// hashing cannot prove two parts share an upstream payout. Safety comes from the eligibility rules
// below; merging is refused whenever they are not all satisfied, and the members render individually.

// Deliberately STRICTER than SPLIT_SUFFIX in nofipa-payments/src/lib/payout-split-status.js, which
// uses a greedy `.+` base. Anchoring to the real upstream namespace (PAYOUT_UPSTREAM_REFERENCE in
// nofipa-payments/src/lib/payout-inbox-mapping.js) rejects nested markers like "x:part-01:part-02"
// and anything outside the payout_inbox namespace. Inputs sourced from `payments` carry no suffix.
const SPLIT_ID = /^(nofipa-(?:bp|bkp)-[1-9][0-9]{0,39}):part-(0[1-9]|[1-9][0-9])$/u;
const AMOUNT_MINOR = /^[0-9]+$/u;

// A field that is ABSENT must never compare equal to one that is present-but-empty: the history
// normalizer turns both into "", so two incomplete records would otherwise qualify as one payout.
// A NUL cannot occur in these fields -- they are display-safe text by the time they reach here.
const ABSENT = "\u0000absent";

// Compared for history equality. `bank_payment_id` is deliberately absent: every part has its own.
const HISTORY_IDENTITY = ["creditor_name", "creditor_account", "debtor_account_masked", "currency"];
const HISTORY_OPTIONAL = [
  "remittance_text",
  "bank_status",
  "bank_payment_status",
  "bank_payment_status_reason",
  "bank_error"
];

function parseSplitId(id) {
  if (typeof id !== "string") {
    return null;
  }
  const match = SPLIT_ID.exec(id);
  return match ? { base: match[1], index: Number(match[2]) } : null;
}

/** Normalize one server-supplied history line item for display. Lossy -- never use for eligibility. */
export function normalizeHistoryPayment(raw) {
  return {
    creditor_name: raw?.creditor_name ?? "",
    debtor_account_masked: raw?.debtor_account_masked ?? "",
    creditor_account: raw?.creditor_account ?? "",
    remittance_text: raw?.remittance_text ?? "",
    amount_minor: raw?.amount_minor ?? "0",
    currency: raw?.currency ?? "",
    bank_status: raw?.bank_status ?? "",
    bank_payment_status: raw?.bank_payment_status ?? "",
    bank_payment_status_reason: raw?.bank_payment_status_reason ?? "",
    bank_payment_id: raw?.bank_payment_id ?? "",
    bank_error: raw?.bank_error ?? "",
    external_id: raw?.external_id ?? ""
  };
}

/** E2: part indices must be unique, contiguous, and start at 01 -- no gaps, no duplicates. */
function indicesFormWholeFamily(family) {
  const seen = new Set();
  for (const member of family) {
    if (seen.has(member.split.index)) {
      return false;
    }
    seen.add(member.split.index);
  }
  return [...seen].sort((a, b) => a - b).every((value, offset) => value === offset + 1);
}

/** E3: money is compared and summed as digits, never as a Number. */
function amountsAreExact(family) {
  return family.every((member) => AMOUNT_MINOR.test(member.payment.amount_minor));
}

// E4 + E5. Returns a comparable signature of everything that must be EQUAL across split parts, or
// null when the input cannot be a split part at all.
//
// Genuine parts differ only in `amount` and `external_id` (nofipa-payments/src/services/bundle/
// staging.js shares debtor, creditor, currency, end_to_end_id and remittance across the fan-out), so
// comparing whole bodies minus those two subsumes the full debtor account -- which matters because
// debtor_account_masked keeps only the first and last four digits and therefore collides.
//
// Equal bodies are not equal REQUESTS: the validator accepts any path under /corporate/premium/v2/
// and does not require matching originating-host headers, so method/path/headers are compared too.
// `digest` necessarily differs, because the bodies differ in `amount`.
function pendingSignature(input) {
  let body;
  try {
    body = JSON.parse(new TextDecoder().decode(base64urlToBytes(input.body_base64url)));
  } catch {
    return null;
  }
  // E4: the grouping key must be the one inside the signed bytes. mapPaymentToBankSigningInputV1
  // assigns request_id = body.external_id, so this holds by construction for every genuine input.
  if (typeof body?.external_id !== "string" || body.external_id !== input?.request_id) {
    return null;
  }
  const rest = { ...body };
  delete rest.amount;
  delete rest.external_id;

  const headers = (Array.isArray(input.signed_headers) ? input.signed_headers : [])
    .filter((header) => String(header?.name ?? "").toLowerCase() !== "digest")
    .map((header) => [String(header?.name ?? ""), String(header?.value ?? "")]);

  try {
    return stableStringify({ method: input.method ?? "", path: input.path ?? "", headers, body: rest });
  } catch {
    // stableStringify is injective but partial; anything it refuses to encode cannot be compared,
    // so the input is simply not a merge candidate.
    return null;
  }
}

/** E6 presence gate. Runs on the RAW server item, before normalization defaults anything away. */
function historyMemberIsComplete(raw) {
  if (!raw || typeof raw !== "object") {
    return false;
  }
  if (typeof raw.amount_minor !== "string" || !AMOUNT_MINOR.test(raw.amount_minor)) {
    return false;
  }
  for (const key of HISTORY_IDENTITY) {
    if (typeof raw[key] !== "string" || raw[key] === "") {
      return false;
    }
  }
  for (const key of HISTORY_OPTIONAL) {
    if (raw[key] !== undefined && typeof raw[key] !== "string") {
      return false;
    }
  }
  return true;
}

// E6 equality. Raw values, so a rendered status string cannot collapse two different bank outcomes
// into one row: bankPaymentStatusText maps several distinct states onto identical text.
function historySignature(raw) {
  return stableStringify(
    [...HISTORY_IDENTITY, ...HISTORY_OPTIONAL].map((key) => [key, raw?.[key] === undefined ? ABSENT : raw[key]])
  );
}

function familyIsOnePayout(family) {
  if (!indicesFormWholeFamily(family) || !amountsAreExact(family)) {
    return false;
  }
  const [first, ...rest] = family;
  if (first.signature === null) {
    return false;
  }
  return rest.every((member) => member.signature !== null && member.signature === first.signature);
}

function mergeFamily(family) {
  let total = 0n;
  for (const member of family) {
    total += BigInt(member.payment.amount_minor);
  }
  const merged = { ...family[0].payment, amount_minor: total.toString(), part_count: family.length };
  if ("bank_payment_id" in merged) {
    // Each part has its own bank payment id, so a merged row can honestly name none.
    merged.bank_payment_id = "";
  }
  return merged;
}

// Merge every eligible family, leaving each surviving row at the position of its FIRST member. A
// family that fails any rule is not merged and its members keep their original places, so a
// half-executed split shows as separate rows rather than collapsing into one.
function assembleRows(members) {
  const mergedAt = new Map();
  const absorbed = new Set();

  const families = new Map();
  for (const member of members) {
    if (!member.split || !member.eligible) {
      continue; // E1 / presence gate: never a merge candidate.
    }
    const family = families.get(member.split.base) ?? [];
    family.push(member);
    families.set(member.split.base, family);
  }

  for (const family of families.values()) {
    if (family.length < 2 || !familyIsOnePayout(family)) {
      continue;
    }
    mergedAt.set(family[0].index, mergeFamily(family));
    for (const member of family.slice(1)) {
      absorbed.add(member.index);
    }
  }

  const rows = [];
  for (const member of members) {
    if (absorbed.has(member.index)) {
      continue;
    }
    rows.push(mergedAt.get(member.index) ?? { ...member.payment, part_count: 1 });
  }

  return { rows, paymentCount: rows.length, transferCount: members.length };
}

/**
 * Pending approval rows. Takes the bundle's payment_inputs verbatim and never mutates them.
 * MUST run only after validateBundleForApprovalV1 has accepted the bundle.
 */
export function buildBundleRowModel(paymentInputs) {
  const inputs = Array.isArray(paymentInputs) ? paymentInputs : [];
  return assembleRows(
    inputs.map((input, index) => ({
      index,
      payment: deriveVisiblePaymentFromInput(input),
      split: parseSplitId(input?.request_id),
      eligible: true,
      signature: pendingSignature(input)
    }))
  );
}

/**
 * History rows. Takes the RAW `visible_payments` array from the server -- eligibility is decided
 * before normalization, which would otherwise turn missing fields into "" and let two incomplete
 * records merge. History carries no signed bytes, so E4/E5 are impossible here; it is a
 * post-approval record, not the authorization surface, and E1/E2 still confine merging to one
 * upstream payout reference. Never mutates its input.
 */
export function buildHistoryRowModel(rawVisiblePayments) {
  const raws = Array.isArray(rawVisiblePayments) ? rawVisiblePayments : [];
  return assembleRows(
    raws.map((raw, index) => {
      // The presence gate runs first: historySignature is only defined over the string-or-absent
      // values it guarantees, so an ineligible member is never encoded.
      const eligible = historyMemberIsComplete(raw);
      return {
        index,
        payment: normalizeHistoryPayment(raw),
        split: parseSplitId(raw?.external_id),
        eligible,
        signature: eligible ? historySignature(raw) : null
      };
    })
  );
}

/** "2 payments (3 transfers)", or just "3 payments" when nothing was grouped. */
export function paymentCountText({ paymentCount, transferCount }) {
  const payments = `${paymentCount} payment${paymentCount === 1 ? "" : "s"}`;
  if (transferCount === paymentCount) {
    return payments;
  }
  return `${payments} (${transferCount} transfer${transferCount === 1 ? "" : "s"})`;
}

/** The same count for a metric that already carries its own "Payments" label: "2 (3 transfers)". */
export function paymentCountMetricText({ paymentCount, transferCount }) {
  if (transferCount === paymentCount) {
    return String(paymentCount);
  }
  return `${paymentCount} (${transferCount} transfer${transferCount === 1 ? "" : "s"})`;
}
