import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from "react";

export type Locale = "en" | "zh-CN" | "zh-TW";
export type Theme = "system" | "light" | "dark";

type I18nContextValue = {
  locale: Locale;
  theme: Theme;
  setLocale: (locale: Locale) => void;
  setTheme: (theme: Theme) => void;
  t: (key: keyof typeof messages.en) => string;
};

const messages = {
  en: {
    docs: "Docs",
    search: "Search",
    recent: "Recent queries",
    emptyHistory: "Your local search history will appear here.",
    heroEyebrow: "WHOIS / RDAP / IP / ASN",
    heroTitle: "Search the ownership trail.",
    placeholder: "domain, IP, ASN, CIDR, or URL...",
    advanced: "Advanced",
    rdapServer: "RDAP server",
    whoisServer: "WHOIS server",
    whoisFollow: "WHOIS follow",
    exactDomain: "Exact domain",
    exactDomainHint: "Use the full typed domain instead of PSL registrable-domain reduction.",
    forceAI: "AI parser",
    forceAIHint: "Analyze raw WHOIS/RDAP registration fields in the background after the main result loads.",
    aiAnalyzing: "AI analyzing",
    aiChecking: "AI is checking raw WHOIS/RDAP evidence...",
    summary: "Summary",
    registration: "Registration",
    network: "Network",
    dns: "DNS Resolution",
    status: "Status",
    nameservers: "Nameservers",
    noDns: "No DNS records resolved.",
    noNetwork: "No network fields parsed.",
    noStatus: "No status values parsed.",
    noNameservers: "No nameservers parsed.",
    noRegistration: "No public registrant fields parsed.",
    warnings: "Provider warnings",
    rawWhois: "Raw WHOIS",
    rawRdap: "Raw RDAP",
    share: "Copy link",
    copyUrl: "Copy URL",
    copyQuery: "Copy query",
    downloadImage: "Download image",
    openImage: "Open image",
    imageDownloaded: "Image downloaded",
    copyRaw: "Copy raw",
    downloadJson: "Download JSON",
    copied: "Copied",
    failed: "Lookup failed",
    sourceHint: "Switch source mode or check whether the lookup API is running.",
    themeSystem: "System",
    themeLight: "Light",
    themeDark: "Dark",
  },
  "zh-CN": {
    docs: "文档",
    search: "查询",
    recent: "最近查询",
    emptyHistory: "本地查询历史会显示在这里。",
    heroEyebrow: "WHOIS / RDAP / IP / ASN",
    heroTitle: "查询归属线索。",
    placeholder: "域名、IP、ASN、CIDR 或 URL...",
    advanced: "高级",
    rdapServer: "RDAP 服务器",
    whoisServer: "WHOIS 服务器",
    whoisFollow: "WHOIS 跟随",
    exactDomain: "完整域名查询",
    exactDomainHint: "把输入的多级域名整体查询，不按 PSL 自动收缩到可注册域。",
    forceAI: "AI 解析",
    forceAIHint: "主结果加载后，在后台分析原始 WHOIS/RDAP 注册字段。",
    aiAnalyzing: "AI 分析中",
    aiChecking: "AI 正在分析原始 WHOIS/RDAP 证据...",
    summary: "摘要",
    registration: "注册信息",
    network: "网络",
    dns: "DNS 解析",
    status: "状态",
    nameservers: "名称服务器",
    noDns: "没有解析到 DNS 记录。",
    noNetwork: "没有解析到网络字段。",
    noStatus: "没有解析到状态。",
    noNameservers: "没有解析到名称服务器。",
    noRegistration: "没有解析到公开注册信息。",
    warnings: "数据源警告",
    rawWhois: "原始 WHOIS",
    rawRdap: "原始 RDAP",
    share: "复制链接",
    copyUrl: "复制 URL",
    copyQuery: "复制查询",
    downloadImage: "下载图片",
    openImage: "打开图片",
    imageDownloaded: "图片已下载",
    copyRaw: "复制原文",
    downloadJson: "下载 JSON",
    copied: "已复制",
    failed: "查询失败",
    sourceHint: "切换来源模式，或检查查询 API 是否正在运行。",
    themeSystem: "跟随系统",
    themeLight: "浅色",
    themeDark: "深色",
  },
  "zh-TW": {
    docs: "文件",
    search: "查詢",
    recent: "最近查詢",
    emptyHistory: "本機查詢紀錄會顯示在這裡。",
    heroEyebrow: "WHOIS / RDAP / IP / ASN",
    heroTitle: "查詢歸屬線索。",
    placeholder: "網域、IP、ASN、CIDR 或 URL...",
    advanced: "進階",
    rdapServer: "RDAP 伺服器",
    whoisServer: "WHOIS 伺服器",
    whoisFollow: "WHOIS 跟隨",
    exactDomain: "完整網域查詢",
    exactDomainHint: "把輸入的多級網域整體查詢，不按 PSL 自動收縮到可註冊網域。",
    forceAI: "AI 解析",
    forceAIHint: "主結果載入後，在後台分析原始 WHOIS/RDAP 註冊欄位。",
    aiAnalyzing: "AI 分析中",
    aiChecking: "AI 正在分析原始 WHOIS/RDAP 證據...",
    summary: "摘要",
    registration: "註冊資訊",
    network: "網路",
    dns: "DNS 解析",
    status: "狀態",
    nameservers: "名稱伺服器",
    noDns: "沒有解析到 DNS 紀錄。",
    noNetwork: "沒有解析到網路欄位。",
    noStatus: "沒有解析到狀態。",
    noNameservers: "沒有解析到名稱伺服器。",
    noRegistration: "沒有解析到公開註冊資訊。",
    warnings: "資料來源警告",
    rawWhois: "原始 WHOIS",
    rawRdap: "原始 RDAP",
    share: "複製連結",
    copyUrl: "複製 URL",
    copyQuery: "複製查詢",
    downloadImage: "下載圖片",
    openImage: "開啟圖片",
    imageDownloaded: "圖片已下載",
    copyRaw: "複製原文",
    downloadJson: "下載 JSON",
    copied: "已複製",
    failed: "查詢失敗",
    sourceHint: "切換來源模式，或檢查查詢 API 是否正在執行。",
    themeSystem: "跟隨系統",
    themeLight: "淺色",
    themeDark: "深色",
  },
} as const;

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("en");
  const [theme, setThemeState] = useState<Theme>("system");

  useEffect(() => {
    const storedLocale = localStorage.getItem("whoice.locale") as Locale | null;
    if (storedLocale && storedLocale in messages) setLocaleState(storedLocale);
    const storedTheme = localStorage.getItem("whoice.theme") as Theme | null;
    if (storedTheme === "system" || storedTheme === "light" || storedTheme === "dark") {
      setThemeState(storedTheme);
      applyTheme(storedTheme);
    } else {
      applyTheme("system");
    }
    if (process.env.NODE_ENV === "production" && "serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => undefined);
    } else if (process.env.NODE_ENV !== "production" && "serviceWorker" in navigator) {
      navigator.serviceWorker.getRegistrations().then((registrations) => {
        registrations.forEach((registration) => void registration.unregister());
      }).catch(() => undefined);
    }
  }, []);

  const value = useMemo<I18nContextValue>(() => ({
    locale,
    theme,
    setLocale(next) {
      setLocaleState(next);
      localStorage.setItem("whoice.locale", next);
    },
    setTheme(next) {
      setThemeState(next);
      localStorage.setItem("whoice.theme", next);
      applyTheme(next);
    },
    t(key) {
      return messages[locale][key] || messages.en[key];
    },
  }), [locale, theme]);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const context = useContext(I18nContext);
  if (!context) throw new Error("useI18n must be used inside I18nProvider");
  return context;
}

function applyTheme(theme: Theme) {
  if (typeof document === "undefined") return;
  document.documentElement.dataset.theme = theme;
}
