import Link from "next/link";
import { ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { AppControls } from "@/components/AppControls";
import { BrandMark } from "@/components/BrandMark";
import { FileIcon, GlobeIcon, PadlockIcon, SearchIcon, ServerIcon, SparkIcon, TagIcon, TerminalIcon, UserIcon } from "@/components/Icons";
import { adminApi, AdminError, buildPatch, readPath, type AdminConfig } from "@/lib/admin/api";
import { allFields, NAV, SETTINGS_SECTIONS, type SectionId } from "@/lib/admin/schema";
import { useAdminText } from "@/lib/admin/text";
import { AccountSection } from "./AccountSection";
import { OverviewSection } from "./OverviewSection";
import { SettingsSection, type Draft } from "./SettingsSection";

const ICONS: Record<SectionId, ReactNode> = {
  overview: <TerminalIcon />,
  lookup: <SearchIcon />,
  dns: <GlobeIcon />,
  enrichment: <TagIcon />,
  ai: <SparkIcon />,
  icp: <FileIcon />,
  access: <PadlockIcon />,
  monitor: <ServerIcon />,
  account: <UserIcon />,
};

const SECRET_PATHS = new Set(allFields().filter((field) => field.type === "secret" || field.type === "tokens").map((field) => field.path));

function sameValue(left: unknown, right: unknown) {
  return JSON.stringify(left ?? null) === JSON.stringify(right ?? null);
}

export function AdminPanel({ passwordFromEnv, onSignedOut }: { passwordFromEnv: boolean; onSignedOut: () => void }) {
  const { pick, at } = useAdminText();
  const [config, setConfig] = useState<AdminConfig | null>(null);
  const [loadError, setLoadError] = useState("");
  const [active, setActive] = useState<SectionId>("overview");
  const [draft, setDraft] = useState<Draft>({});
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(() => {
    setLoadError("");
    adminApi
      .config()
      .then(setConfig)
      .catch((error: AdminError) => (error.status === 401 ? onSignedOut() : setLoadError(error.message)));
  }, [onSignedOut]);

  useEffect(load, [load]);

  // Edits equal to the saved value are not changes. Secrets are never read back, so any edit counts.
  const changes = useMemo(() => {
    if (!config) return {};
    return Object.fromEntries(Object.entries(draft).filter(([path, value]) => SECRET_PATHS.has(path) || !sameValue(value, readPath(config.settings, path))));
  }, [config, draft]);
  const changeCount = Object.keys(changes).length;
  const dirtySections = useMemo(() => {
    const out = new Set<SectionId>();
    for (const section of SETTINGS_SECTIONS) {
      if (section.groups.some((group) => group.fields.some((field) => field.path in changes))) out.add(section.id);
    }
    return out;
  }, [changes]);

  useEffect(() => {
    if (!changeCount) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [changeCount]);

  function update(path: string, value: unknown) {
    setNotice(null);
    setDraft((current) => ({ ...current, [path]: value }));
  }

  async function save() {
    setSaving(true);
    setNotice(null);
    try {
      const next = await adminApi.save(buildPatch(changes));
      setConfig(next);
      setDraft({});
      setNotice({ ok: true, text: at("saved") });
    } catch (error) {
      if (error instanceof AdminError && error.status === 401) {
        onSignedOut();
        return;
      }
      setNotice({ ok: false, text: error instanceof Error ? error.message : String(error) });
    } finally {
      setSaving(false);
    }
  }

  async function signOut() {
    await adminApi.logout().catch(() => undefined);
    onSignedOut();
  }

  const section = SETTINGS_SECTIONS.find((item) => item.id === active);
  const navItem = NAV.find((item) => item.id === active)!;
  const readOnly = config && !config.editor.writable;

  return (
    <main className="adm-shell">
      <header className="adm-header">
        <BrandMark />
        <span className="adm-header-title">{at("panel")}</span>
        <span className="spacer" />
        <Link href="/" className="adm-header-link">{at("backToSite")}</Link>
        <AppControls />
        <button type="button" className="adm-btn adm-btn-ghost" onClick={signOut}>{at("signOut")}</button>
      </header>

      <div className="adm-body">
        <nav className="adm-nav" aria-label={at("sections")}>
          {NAV.map((item) => (
            <button
              key={item.id}
              type="button"
              className={item.id === active ? "adm-nav-item active" : "adm-nav-item"}
              aria-current={item.id === active ? "page" : undefined}
              onClick={(event) => {
                setActive(item.id);
                event.currentTarget.scrollIntoView({ block: "nearest", inline: "nearest" });
              }}
            >
              <span className="adm-nav-icon" aria-hidden="true">{ICONS[item.id]}</span>
              {pick(item.title)}
              {dirtySections.has(item.id) && <span className="adm-dirty-dot" aria-hidden="true" />}
            </button>
          ))}
        </nav>

        <section className="adm-card" aria-labelledby="adm-section-title">
          <div className="adm-card-head">
            <span className="adm-card-icon" aria-hidden="true">{ICONS[active]}</span>
            <span className="adm-card-heading">
              <h2 id="adm-section-title">{pick(navItem.title)}</h2>
              {section && <span className="adm-card-desc">{pick(section.description)}</span>}
            </span>
          </div>
          <div className="adm-card-body" key={active}>
            {loadError ? (
              <p className="adm-alert">
                {loadError}
                <button type="button" className="adm-btn" onClick={load}>{at("retry")}</button>
              </p>
            ) : !config ? (
              <p className="adm-note">{at("loading")}</p>
            ) : active === "overview" ? (
              <OverviewSection config={config} />
            ) : active === "account" ? (
              <AccountSection passwordFromEnv={passwordFromEnv} onSignOut={signOut} />
            ) : section ? (
              <>
                {readOnly && <p className="adm-alert">{at("readOnly", { reason: config.editor.reason || "" })}</p>}
                <SettingsSection section={section} config={config} draft={draft} onChange={update} />
              </>
            ) : null}
          </div>
          {(changeCount > 0 || notice) && (
            <div className="adm-savebar" role="status">
              {notice ? <span className={notice.ok ? "adm-ok" : "adm-error"}>{notice.text}</span> : <span className="adm-savebar-count">{at("unsaved", { n: changeCount })}</span>}
              <span className="spacer" />
              {changeCount > 0 && (
                <>
                  <button type="button" className="adm-btn adm-btn-ghost" onClick={() => (setDraft({}), setNotice(null))} disabled={saving}>{at("discard")}</button>
                  <button type="button" className="adm-btn adm-btn-primary" onClick={save} disabled={saving || Boolean(readOnly)}>{saving ? at("saving") : at("save")}</button>
                </>
              )}
            </div>
          )}
        </section>
      </div>
    </main>
  );
}
