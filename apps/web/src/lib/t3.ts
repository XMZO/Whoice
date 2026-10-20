import { useI18n } from "./i18n";

// Inline translations for page- or feature-specific text: t3(English, 简体中文, 繁體中文).
// Shared UI strings live in lib/i18n.tsx; anything else user-visible goes through t3.
// The i18n gate (scripts/validate-web-i18n.mjs) only accepts literal text inside t3(...).

export type T3 = readonly [en: string, zhCN: string, zhTW: string];

export function t3(en: string, zhCN: string, zhTW: string): T3 {
  return [en, zhCN, zhTW] as const;
}

const INDEX = { en: 0, "zh-CN": 1, "zh-TW": 2 } as const;

export function fill(template: string, vars?: Record<string, string | number>) {
  return vars ? template.replace(/\{(\w+)\}/g, (match, name) => (name in vars ? String(vars[name]) : match)) : template;
}

export function useT3() {
  const { locale } = useI18n();
  const index = INDEX[locale] ?? 0;
  return (value: T3, vars?: Record<string, string | number>) => fill(value[index], vars);
}
