// UI language and theme preferences, readable on the server so the first
// HTML is already in the right language and theme (no flash on load).
import type { IncomingMessage } from "http";

export type Locale = "en" | "zh-CN" | "zh-TW";
export type Theme = "system" | "light" | "dark";

export const LOCALE_COOKIE = "whoice.locale";
export const THEME_COOKIE = "whoice.theme";
const ONE_YEAR = 60 * 60 * 24 * 365;

const LOCALES: readonly Locale[] = ["en", "zh-CN", "zh-TW"];
const THEMES: readonly Theme[] = ["system", "light", "dark"];

export function isLocale(value: unknown): value is Locale {
  return typeof value === "string" && (LOCALES as readonly string[]).includes(value);
}

export function isTheme(value: unknown): value is Theme {
  return typeof value === "string" && (THEMES as readonly string[]).includes(value);
}

/**
 * Picks the UI language from language preferences in order: Traditional
 * Chinese for zh-TW/HK/MO or a Hant script tag, Simplified Chinese for other
 * zh, English otherwise. The first preference Whoice supports wins.
 */
export function detectLocale(preferences: readonly string[]): Locale {
  for (const preference of preferences) {
    const tag = (preference || "").trim().toLowerCase();
    if (tag.startsWith("zh")) {
      return /hant|-tw|-hk|-mo/.test(tag) ? "zh-TW" : "zh-CN";
    }
    if (tag.startsWith("en")) return "en";
  }
  return "en";
}

/** Parses an Accept-Language header into tags ordered by quality. */
export function acceptLanguageTags(header: string | undefined): string[] {
  if (!header) return [];
  return header
    .split(",")
    .map((part, index) => {
      const [tag, ...params] = part.trim().split(";");
      const q = params.map((param) => param.trim()).find((param) => param.startsWith("q="));
      const quality = q ? Number.parseFloat(q.slice(2)) : 1;
      return { tag: tag.trim(), quality: Number.isFinite(quality) ? quality : 0, index };
    })
    .filter((item) => item.tag && item.tag !== "*" && item.quality > 0)
    .sort((a, b) => b.quality - a.quality || a.index - b.index)
    .map((item) => item.tag);
}

function readCookie(header: string | undefined, name: string) {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return undefined;
}

/** Server side: the chosen language (cookie) or the browser's (Accept-Language). */
export function requestLocale(req: IncomingMessage | undefined): Locale {
  const chosen = readCookie(req?.headers.cookie, LOCALE_COOKIE);
  if (isLocale(chosen)) return chosen;
  const header = req?.headers["accept-language"];
  return detectLocale(acceptLanguageTags(Array.isArray(header) ? header.join(",") : header));
}

/** Server side: the chosen theme, "system" when none was picked. */
export function requestTheme(req: IncomingMessage | undefined): Theme {
  const chosen = readCookie(req?.headers.cookie, THEME_COOKIE);
  return isTheme(chosen) ? chosen : "system";
}

/** Client side: remember a choice for server rendering too. */
export function rememberPreference(name: string, value: string) {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${ONE_YEAR}; SameSite=Lax`;
}
