// The one rule for requested_execution_date on a DOMESTIC_CREDIT_TRANSFER_SE payout (docs/protocol.md).
//
// Nordea rejects a Swedish payout that is finally confirmed after its 13:30 cut-off. nofipa-payments,
// when its setting is on, therefore puts the next Swedish banking day in the body of a payout minted at
// or after 13:25 Stockholm time or on a non-banking day. The phone cannot alter a body, only validate
// and sign it, and cannot know whether forward-dating is switched on, so it never demands the date: it
// only BOUNDS it. A body that carries the field must carry exactly the date this function returns for the
// instant of its signed x-nordea-originating-date header and its creditor account, and a body without the
// field is valid at any time. Both sides import this module, so there is one rule, not two copies.
//
// Part of the hashed protocol core (tools/generate-protocol-release.mjs): editing it changes the
// protocol release id. No date library: Intl with a fixed time zone, which works in a browser and in Node.
//
// This module and envelopes.js import each other: the Nordea test needs the Swedish clearing table that
// lives there, and envelopes.js applies this rule. Neither uses the other at module evaluation, only
// inside functions, so the cycle is safe in either import order.
import { seBicForBban } from "./envelopes.js";

// Local time of the cut-off decision, in Europe/Stockholm: a payout minted from this second on is dated.
// 13:25 is five minutes before Nordea's 13:30 cut-off, leaving time to finish the approval.
export const SE_EXECUTION_DATE_CUTOFF = "13:25";
const CUTOFF_SECONDS = 13 * 3600 + 25 * 60;
// The longest wait the rule will date. The status polling capabilities cover 72 hours from approval; a
// payout dated further out (the Thursday afternoon before Good Friday, five days) would outlive them, so
// the rule returns null there and the payout stays undated.
export const SE_EXECUTION_DATE_MAX_GAP_DAYS = 3;
export const SE_EXECUTION_DATE_TIME_ZONE = "Europe/Stockholm";

const NORDEA_SE_BIC = "NDEASESS";
const DATE_STRING = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/u;
// Eleven to fifteen digits are a BBAN with its clearing number; exactly ten are a Nordea personkonto sent
// without one (isSePersonkontoBban in envelopes.js), which only the SE transfer's creditor may be.
const SE_BBAN_DIGITS = /^[0-9]{10,15}$/u;
const MS_PER_DAY = 86400000;

const STOCKHOLM_PARTS = new Intl.DateTimeFormat("en-US", {
  timeZone: SE_EXECUTION_DATE_TIME_ZONE,
  hourCycle: "h23",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

function pad(value, length) {
  return String(value).padStart(length, "0");
}

// Days since 1970-01-01 for a calendar date. UTC arithmetic: no DST in a plain day count.
function dayNumber(year, month, day) {
  return Date.UTC(year, month - 1, day) / MS_PER_DAY;
}

function dateStringOfDayNumber(days) {
  const date = new Date(days * MS_PER_DAY);
  return `${pad(date.getUTCFullYear(), 4)}-${pad(date.getUTCMonth() + 1, 2)}-${pad(date.getUTCDate(), 2)}`;
}

// A YYYY-MM-DD string that is a real calendar date -> { year, month, day, days }. Anything else throws.
function parseDateString(name, value) {
  const match = typeof value === "string" ? DATE_STRING.exec(value) : null;
  if (match === null) {
    throw new RangeError(`${name} must be a YYYY-MM-DD date`);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const days = dayNumber(year, month, day);
  if (year < 1970 || dateStringOfDayNumber(days) !== value) {
    throw new RangeError(`${name} must be a real calendar date from 1970`);
  }
  return { year, month, day, days };
}

// Easter Sunday of a Gregorian year as a day number (the anonymous Gregorian algorithm, Meeus/Jones/Butcher).
function easterDayNumber(year) {
  const a = year % 19;
  const b = Math.floor(year / 100);
  const c = year % 100;
  const d = Math.floor(b / 4);
  const e = b % 4;
  const f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4);
  const k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31);
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return dayNumber(year, month, day);
}

// 0 = Sunday .. 6 = Saturday.
function weekday(days) {
  return (((days + 4) % 7) + 7) % 7;
}

// The Swedish bank holidays of a year as day numbers: 1 Jan, 6 Jan, Good Friday, Easter Monday, 1 May,
// Ascension Day (39 days after Easter Sunday), 6 Jun, Midsummer Eve (the Friday from 19 to 25 June) and
// 24, 25, 26 and 31 Dec. Days with reduced opening hours are ordinary banking days.
function bankHolidays(year) {
  const easter = easterDayNumber(year);
  let midsummerEve = dayNumber(year, 6, 19);
  while (weekday(midsummerEve) !== 5) {
    midsummerEve += 1;
  }
  return new Set([
    dayNumber(year, 1, 1),
    dayNumber(year, 1, 6),
    easter - 2,
    easter + 1,
    dayNumber(year, 5, 1),
    easter + 39,
    dayNumber(year, 6, 6),
    midsummerEve,
    dayNumber(year, 12, 24),
    dayNumber(year, 12, 25),
    dayNumber(year, 12, 26),
    dayNumber(year, 12, 31)
  ]);
}

function isBankingDayNumber(days) {
  const day = weekday(days);
  if (day === 0 || day === 6) {
    return false;
  }
  return !bankHolidays(new Date(days * MS_PER_DAY).getUTCFullYear()).has(days);
}

// Whether a value is a YYYY-MM-DD string that is a real calendar date (from 1970).
export function isCalendarDateString(value) {
  try {
    parseDateString("date", value);
    return true;
  } catch {
    return false;
  }
}

// Whether a YYYY-MM-DD date is a Swedish banking day: not a Saturday, a Sunday or a bank holiday.
export function isSwedishBankingDay(dateString) {
  return isBankingDayNumber(parseDateString("date", dateString).days);
}

function instantMs(instant) {
  const ms = instant instanceof Date ? instant.getTime() : instant;
  if (typeof ms !== "number" || Number.isNaN(new Date(ms).getTime())) {
    throw new RangeError("instant must be a valid Date or epoch milliseconds");
  }
  return ms;
}

// The Stockholm calendar date of an instant, "YYYY-MM-DD", and the seconds since Stockholm midnight.
export function stockholmDateAndSeconds(instant) {
  const parts = {};
  for (const { type, value } of STOCKHOLM_PARTS.formatToParts(new Date(instantMs(instant)))) {
    parts[type] = value;
  }
  return Object.freeze({
    date: `${parts.year}-${parts.month}-${parts.day}`,
    secondsOfDay: Number(parts.hour) * 3600 + Number(parts.minute) * 60 + Number(parts.second)
  });
}

// null (the payout needs no date) or the YYYY-MM-DD next Swedish banking day to put in
// requested_execution_date. `creditorBban` is the creditor account's BBAN digits as the body sends them:
// a clearing number and an account, or the ten digits of a Nordea personkonto.
export function seExecutionDateFor({ instant, creditorBban } = {}) {
  if (typeof creditorBban !== "string" || !SE_BBAN_DIGITS.test(creditorBban)) {
    throw new RangeError("creditorBban must be a Swedish BBAN of digits");
  }
  const { date, secondsOfDay } = stockholmDateAndSeconds(instant);
  const today = parseDateString("date", date);
  if (isBankingDayNumber(today.days)) {
    if (secondsOfDay < CUTOFF_SECONDS) {
      return null;
    }
    // Nordea's own cut-off for a transfer between its accounts is 24:00, so a Nordea-held creditor on a
    // banking day needs no date at any time. seBicForBban reads a ten-digit personkonto as Nordea's by its
    // length, never by its first four digits, so one that starts like another bank's clearing number
    // (8501...) is still Nordea-held here.
    if (seBicForBban(creditorBban) === NORDEA_SE_BIC) {
      return null;
    }
  }
  let candidate = today.days + 1;
  while (!isBankingDayNumber(candidate)) {
    candidate += 1;
  }
  if (candidate - today.days > SE_EXECUTION_DATE_MAX_GAP_DAYS) {
    return null;
  }
  return dateStringOfDayNumber(candidate);
}
