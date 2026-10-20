import { useI18n } from "@/lib/i18n";
import { fill, t3, type T3 } from "@/lib/t3";

const TEXT = {
  panel: t3("Admin", "管理面板", "管理面板"),
  signInTitle: t3("Sign in to the admin panel", "登录管理面板", "登入管理面板"),
  password: t3("Password", "密码", "密碼"),
  signIn: t3("Sign in", "登录", "登入"),
  signingIn: t3("Signing in", "登录中", "登入中"),
  firstPassword: t3("The first password is printed in the API log: docker compose logs lookup-api | grep \"admin panel password\"", "首次密码打印在 API 日志中：docker compose logs lookup-api | grep \"admin panel password\"", "首次密碼列印在 API 日誌中：docker compose logs lookup-api | grep \"admin panel password\""),
  backToSite: t3("Back to Whoice", "返回 Whoice", "返回 Whoice"),
  signOut: t3("Sign out", "退出登录", "登出"),
  sections: t3("Sections", "分区", "分區"),
  unsaved: t3("{n} unsaved", "{n} 项未保存", "{n} 項未儲存"),
  discard: t3("Discard", "放弃", "捨棄"),
  save: t3("Save", "保存", "儲存"),
  saving: t3("Saving", "保存中", "儲存中"),
  saved: t3("Saved and applied", "已保存并生效", "已儲存並生效"),
  loading: t3("Loading", "加载中", "載入中"),
  retry: t3("Retry", "重试", "重試"),
  envLocked: t3("Set by {env}", "由 {env} 设置", "由 {env} 設定"),
  secretSet: t3("Set. Leave blank to keep.", "已设置，留空保持不变", "已設定，留空保持不變"),
  secretUnset: t3("Not set", "未设置", "未設定"),
  tokensSet: t3("{n} set. Enter new tokens to replace them.", "已设置 {n} 个，输入新值将全部替换", "已設定 {n} 個，輸入新值將全部取代"),
  clear: t3("Clear", "清除", "清除"),
  cleared: t3("Will be cleared", "将被清除", "將被清除"),
  generate: t3("Generate", "生成", "產生"),
  onePerLine: t3("One per line", "每行一个", "每行一個"),
  resetDefault: t3("Restore default", "恢复默认", "恢復預設"),
  on: t3("On", "开", "開"),
  off: t3("Off", "关", "關"),
  readOnly: t3("Settings are read-only: {reason}", "设置为只读：{reason}", "設定為唯讀：{reason}"),
  // Overview
  service: t3("Service", "服务", "服務"),
  version: t3("Version", "版本", "版本"),
  uptime: t3("Uptime", "运行时长", "執行時長"),
  lookups: t3("Lookups", "查询次数", "查詢次數"),
  successRate: t3("Success rate", "成功率", "成功率"),
  avgLatency: t3("Average latency", "平均耗时", "平均耗時"),
  configuration: t3("Configuration", "配置", "設定"),
  configFile: t3("Config file", "配置文件", "設定檔"),
  loadedAt: t3("Loaded", "加载时间", "載入時間"),
  configHealthy: t3("Valid", "正常", "正常"),
  configError: t3("Last reload failed; the previous valid config is in use", "最近一次加载失败，正在使用上一份有效配置", "最近一次載入失敗，正在使用上一份有效設定"),
  listen: t3("Listen address", "监听地址", "監聽位址"),
  dataDir: t3("Data directory", "数据目录", "資料目錄"),
  startupOnly: t3("Change in whoice.toml and restart", "需在 whoice.toml 中修改并重启", "需在 whoice.toml 中修改並重啟"),
  envOverrides: t3("Environment overrides", "环境变量覆盖", "環境變數覆蓋"),
  noOverrides: t3("None", "无", "無"),
  sources: t3("Sources", "数据来源", "資料來源"),
  provider: t3("Source", "来源", "來源"),
  requests: t3("Requests", "请求", "請求"),
  failures: t3("Failures", "失败", "失敗"),
  plugins: t3("Plugins", "插件", "外掛"),
  pluginsEnabled: t3("{n} of {total} enabled", "已启用 {n} / {total}", "已啟用 {n} / {total}"),
  // Account
  changePassword: t3("Change password", "修改密码", "修改密碼"),
  currentPassword: t3("Current password", "当前密码", "目前密碼"),
  newPassword: t3("New password", "新密码", "新密碼"),
  confirmPassword: t3("Confirm new password", "确认新密码", "確認新密碼"),
  mismatch: t3("The passwords do not match", "两次输入的密码不一致", "兩次輸入的密碼不一致"),
  minLength: t3("At least 8 characters", "至少 8 个字符", "至少 8 個字元"),
  passwordChanged: t3("Password changed. Other sessions were signed out.", "密码已修改，其他会话已退出", "密碼已修改，其他工作階段已登出"),
  passwordFromEnv: t3("The password is set by WHOICE_ADMIN_PASSWORD and can only be changed there.", "密码由 WHOICE_ADMIN_PASSWORD 设置，只能在环境变量中修改。", "密碼由 WHOICE_ADMIN_PASSWORD 設定，只能在環境變數中修改。"),
  resetHint: t3("Forgot the password? Run: docker compose exec lookup-api /app/whoice-api reset-admin-password", "忘记密码时运行：docker compose exec lookup-api /app/whoice-api reset-admin-password", "忘記密碼時執行：docker compose exec lookup-api /app/whoice-api reset-admin-password"),
  session: t3("Session", "会话", "工作階段"),
  sessionNote: t3("Sessions last 7 days and end when the password changes.", "会话有效期 7 天，修改密码后失效。", "工作階段有效期 7 天，修改密碼後失效。"),
} satisfies Record<string, T3>;

// Admin API error codes. The server's English message is kept only as a detail
// for codes whose message lists specific settings.
const ERRORS: Record<string, T3> = {
  invalid_password: t3("The password is incorrect.", "密码错误。", "密碼錯誤。"),
  too_many_attempts: t3("Too many failed attempts. Try again in a few minutes.", "失败次数过多，请几分钟后再试。", "失敗次數過多，請幾分鐘後再試。"),
  weak_password: t3("The new password must be at least 8 characters.", "新密码至少需要 8 个字符。", "新密碼至少需要 8 個字元。"),
  password_from_env: t3("The password is set by WHOICE_ADMIN_PASSWORD.", "密码由 WHOICE_ADMIN_PASSWORD 设置。", "密碼由 WHOICE_ADMIN_PASSWORD 設定。"),
  unauthorized: t3("Your session has ended. Sign in again.", "会话已失效，请重新登录。", "工作階段已失效，請重新登入。"),
  csrf_required: t3("The request was rejected. Reload the page and try again.", "请求被拒绝，请刷新页面后重试。", "請求被拒絕，請重新整理頁面後重試。"),
  admin_unavailable: t3("The admin panel is not enabled.", "管理面板未启用。", "管理面板未啟用。"),
  api_disabled: t3("The API is disabled.", "API 已关闭。", "API 已關閉。"),
  api_endpoint_disabled: t3("The admin endpoints are disabled.", "管理接口已关闭。", "管理介面已關閉。"),
  ip_not_allowed: t3("Your address is not in the API allowlist.", "当前地址不在 API 白名单中。", "目前位址不在 API 白名單中。"),
  invalid_config: t3("The settings are invalid", "设置无效", "設定無效"),
  env_locked: t3("Some settings are set by environment variables", "部分设置由环境变量指定", "部分設定由環境變數指定"),
  startup_only: t3("Some settings can only change in whoice.toml before startup", "部分设置只能在启动前修改 whoice.toml", "部分設定只能在啟動前修改 whoice.toml"),
  admin_lockout: t3("This change would lock the admin panel out", "该修改会导致无法访问管理面板", "該修改會導致無法存取管理面板"),
  config_write_failed: t3("The config file could not be written", "无法写入配置文件", "無法寫入設定檔"),
  reload_failed: t3("Saved, but the new settings could not be applied", "已保存，但新设置未能生效", "已儲存，但新設定未能生效"),
  config_unreadable: t3("The config file could not be read", "无法读取配置文件", "無法讀取設定檔"),
  network: t3("The server could not be reached.", "无法连接服务器。", "無法連線伺服器。"),
};

const DETAILED = new Set(["invalid_config", "env_locked", "startup_only", "admin_lockout", "config_write_failed", "reload_failed", "config_unreadable"]);

export type AdminTextKey = keyof typeof TEXT;

const INDEX = { en: 0, "zh-CN": 1, "zh-TW": 2 } as const;

export function useAdminText() {
  const { locale } = useI18n();
  const index = INDEX[locale] ?? 0;
  const pick = (value: T3) => value[index];
  const at = (key: AdminTextKey, vars?: Record<string, string | number>) => fill(TEXT[key][index], vars);
  // Translates an AdminError by code; unknown codes fall back to the server message.
  const errorText = (error: unknown) => {
    const code = (error as { code?: string })?.code || "";
    const message = error instanceof Error ? error.message : String(error);
    const known = ERRORS[code];
    if (!known) return message;
    return DETAILED.has(code) ? `${pick(known)}: ${message}` : pick(known);
  };
  return { pick, at, errorText, locale };
}
