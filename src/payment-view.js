import { base64urlToBytes } from "./core/crypto/bytes.js";
import { deriveVisiblePaymentFromBankBodyV1 } from "./core/protocol/envelopes.js";

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
