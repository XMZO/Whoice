import { useI18n } from "@/lib/i18n";
import type { T3 } from "./schema";

const TEXT = {
  panel: ["Admin", "管理面板", "管理面板"],
  signInTitle: ["Sign in to the admin panel", "登录管理面板", "登入管理面板"],
  password: ["Password", "密码", "密碼"],
  signIn: ["Sign in", "登录", "登入"],
  signingIn: ["Signing in", "登录中", "登入中"],
  firstPassword: [
    "The first password is printed in the API log: docker compose logs lookup-api | grep \"admin panel password\"",
    "首次密码打印在 API 日志中：docker compose logs lookup-api | grep \"admin panel password\"",
    "首次密碼列印在 API 日誌中：docker compose logs lookup-api | grep \"admin panel password\"",
  ],
  backToSite: ["Back to Whoice", "返回 Whoice", "返回 Whoice"],
  signOut: ["Sign out", "退出登录", "登出"],
  sections: ["Sections", "分区", "分區"],
  unsaved: ["{n} unsaved", "{n} 项未保存", "{n} 項未儲存"],
  discard: ["Discard", "放弃", "捨棄"],
  save: ["Save", "保存", "儲存"],
  saving: ["Saving", "保存中", "儲存中"],
  saved: ["Saved and applied", "已保存并生效", "已儲存並生效"],
  loading: ["Loading", "加载中", "載入中"],
  retry: ["Retry", "重试", "重試"],
  envLocked: ["Set by {env}", "由 {env} 设置", "由 {env} 設定"],
  secretSet: ["Set. Leave blank to keep.", "已设置，留空保持不变", "已設定，留空保持不變"],
  secretUnset: ["Not set", "未设置", "未設定"],
  tokensSet: ["{n} set. Enter new tokens to replace them.", "已设置 {n} 个，输入新值将全部替换", "已設定 {n} 個，輸入新值將全部取代"],
  clear: ["Clear", "清除", "清除"],
  cleared: ["Will be cleared", "将被清除", "將被清除"],
  generate: ["Generate", "生成", "產生"],
  onePerLine: ["One per line", "每行一个", "每行一個"],
  resetDefault: ["Restore default", "恢复默认", "恢復預設"],
  on: ["On", "开", "開"],
  off: ["Off", "关", "關"],
  readOnly: ["Settings are read-only: {reason}", "设置为只读：{reason}", "設定為唯讀：{reason}"],
  // Overview
  service: ["Service", "服务", "服務"],
  version: ["Version", "版本", "版本"],
  uptime: ["Uptime", "运行时长", "執行時長"],
  lookups: ["Lookups", "查询次数", "查詢次數"],
  successRate: ["Success rate", "成功率", "成功率"],
  avgLatency: ["Average latency", "平均耗时", "平均耗時"],
  configuration: ["Configuration", "配置", "設定"],
  configFile: ["Config file", "配置文件", "設定檔"],
  loadedAt: ["Loaded", "加载时间", "載入時間"],
  configHealthy: ["Valid", "正常", "正常"],
  configError: ["Last reload failed; the previous valid config is in use", "最近一次加载失败，正在使用上一份有效配置", "最近一次載入失敗，正在使用上一份有效設定"],
  listen: ["Listen address", "监听地址", "監聽位址"],
  dataDir: ["Data directory", "数据目录", "資料目錄"],
  startupOnly: ["Change in whoice.toml and restart", "需在 whoice.toml 中修改并重启", "需在 whoice.toml 中修改並重啟"],
  envOverrides: ["Environment overrides", "环境变量覆盖", "環境變數覆蓋"],
  noOverrides: ["None", "无", "無"],
  sources: ["Sources", "数据来源", "資料來源"],
  provider: ["Source", "来源", "來源"],
  requests: ["Requests", "请求", "請求"],
  failures: ["Failures", "失败", "失敗"],
  plugins: ["Plugins", "插件", "外掛"],
  pluginsEnabled: ["{n} of {total} enabled", "已启用 {n} / {total}", "已啟用 {n} / {total}"],
  // Account
  changePassword: ["Change password", "修改密码", "修改密碼"],
  currentPassword: ["Current password", "当前密码", "目前密碼"],
  newPassword: ["New password", "新密码", "新密碼"],
  confirmPassword: ["Confirm new password", "确认新密码", "確認新密碼"],
  mismatch: ["The passwords do not match", "两次输入的密码不一致", "兩次輸入的密碼不一致"],
  minLength: ["At least 8 characters", "至少 8 个字符", "至少 8 個字元"],
  passwordChanged: ["Password changed. Other sessions were signed out.", "密码已修改，其他会话已退出", "密碼已修改，其他工作階段已登出"],
  passwordFromEnv: ["The password is set by WHOICE_ADMIN_PASSWORD and can only be changed there.", "密码由 WHOICE_ADMIN_PASSWORD 设置，只能在环境变量中修改。", "密碼由 WHOICE_ADMIN_PASSWORD 設定，只能在環境變數中修改。"],
  resetHint: ["Forgot the password? Run: docker compose exec lookup-api /app/whoice-api reset-admin-password", "忘记密码时运行：docker compose exec lookup-api /app/whoice-api reset-admin-password", "忘記密碼時執行：docker compose exec lookup-api /app/whoice-api reset-admin-password"],
  session: ["Session", "会话", "工作階段"],
  sessionNote: ["Sessions last 7 days and end when the password changes.", "会话有效期 7 天，修改密码后失效。", "工作階段有效期 7 天，修改密碼後失效。"],
} satisfies Record<string, T3>;

export type AdminTextKey = keyof typeof TEXT;

const INDEX = { en: 0, "zh-CN": 1, "zh-TW": 2 } as const;

export function useAdminText() {
  const { locale } = useI18n();
  const index = INDEX[locale] ?? 0;
  const pick = (value: T3) => value[index];
  const at = (key: AdminTextKey, vars?: Record<string, string | number>) =>
    TEXT[key][index].replace(/\{(\w+)\}/g, (match, name) => (vars && name in vars ? String(vars[name]) : match));
  return { pick, at, locale };
}
