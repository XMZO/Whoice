import { Locale, Theme, useI18n } from "@/lib/i18n";

export function AppControls() {
  const { locale, theme, setLocale, setTheme, t } = useI18n();

  return (
    <div className="app-controls">
      <select aria-label="Language" value={locale} onChange={(event) => setLocale(event.target.value as Locale)}>
        <option value="en">EN</option>
        <option value="zh-CN">简体</option>
        <option value="zh-TW">繁體</option>
      </select>
      <select aria-label="Theme" value={theme} onChange={(event) => setTheme(event.target.value as Theme)}>
        <option value="system">{t("themeSystem")}</option>
        <option value="light">{t("themeLight")}</option>
        <option value="dark">{t("themeDark")}</option>
      </select>
    </div>
  );
}
