import { useEffect, useState } from "react";
import type { FXRates } from "./types";

export type DisplayCurrency = "CNY" | "USD";

const STORAGE_KEY = "whoice:display-currency";
const CHANGE_EVENT = "whoice:display-currency";

function initialCurrency(locale: string): DisplayCurrency {
  return locale.startsWith("zh") ? "CNY" : "USD";
}

/**
 * The currency prices are converted to. Remembered in localStorage and
 * shared between every toggle on the page (card header and tab bar).
 */
export function useDisplayCurrency(locale: string): [DisplayCurrency, (next: DisplayCurrency) => void] {
  const [currency, setCurrency] = useState<DisplayCurrency>(() => initialCurrency(locale));
  useEffect(() => {
    const read = () => {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      setCurrency(stored === "CNY" || stored === "USD" ? stored : initialCurrency(locale));
    };
    read();
    window.addEventListener(CHANGE_EVENT, read);
    return () => window.removeEventListener(CHANGE_EVENT, read);
  }, [locale]);
  const update = (next: DisplayCurrency) => {
    window.localStorage.setItem(STORAGE_KEY, next);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  };
  return [currency, update];
}

/** Converts between currencies through USD-based rates; undefined when a rate is missing. */
export function convertAmount(amount: number | undefined, from: string, to: string, fx?: FXRates) {
  if (amount === undefined || amount === null || !fx) return undefined;
  const fromRate = fx.rates[from.toUpperCase()];
  const toRate = fx.rates[to.toUpperCase()];
  if (!fromRate || !toRate) return undefined;
  return (amount / fromRate) * toRate;
}
