import { base64urlToBytes } from "./core/crypto/bytes.js";
import { deriveVisiblePaymentFromBankBodyV1, requestedExecutionDateOfBankBodyV1 } from "./core/protocol/envelopes.js";
import { isSwedishBankingDay, stockholmDateAndSeconds } from "./core/protocol/se-execution-date.js";

export function deriveVisiblePaymentFromInput(input) {
  const derived = deriveVisiblePaymentFromBankBodyV1(base64urlToBytes(input.body_base64url));

  for (const [key, value] of Object.entries(input.visible_payment)) {
    if ((derived[key] ?? "") !== value) {
      throw new Error(`visible payment mismatch for ${key}`);
    }
  }

  return derived;
}

export function amountMinorToDecimal(amountMinor, currency) {
  const value = BigInt(amountMinor);
  const whole = value / 100n;
  const fractional = (value % 100n).toString().padStart(2, "0");
  return `${whole.toLocaleString("da-DK")},${fractional} ${currency}`;
}

const EXECUTION_DATE_FORMAT = new Intl.DateTimeFormat("en-GB", {
  weekday: "long",
  day: "numeric",
  month: "long",
  timeZone: "UTC"
});

/**
 * "Paid on Monday 16 November (after today's cut-off)" for a payment whose signed body asks for a later
 * execution date, otherwise "". The date comes from the signed body bytes, never from a field beside them,
 * and is not part of the visible payment or its hash. The reason is read from the signed originating date:
 * a banking day means the payout was minted after the cut-off, anything else the weekend or a holiday.
 * Run only after validateBundleForApprovalV1 has bound the date to the rule.
 */
export function executionDateTextFromInput(input) {
  const date = requestedExecutionDateOfBankBodyV1(base64urlToBytes(input.body_base64url));
  if (date === null) {
    return "";
  }
  const dateText = EXECUTION_DATE_FORMAT.format(new Date(`${date}T00:00:00Z`));
  const originated = stockholmDateAndSeconds(Date.parse(input.signed_headers[2].value)).date;
  return `Paid on ${dateText} (${isSwedishBankingDay(originated) ? "after today's cut-off" : "next banking day"})`;
}
