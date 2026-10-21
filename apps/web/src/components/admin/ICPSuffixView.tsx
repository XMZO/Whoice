import { useMemo, useRef, useState } from "react";
import type { ICPSuffixList } from "@/lib/admin/api";
import { useAdminText } from "@/lib/admin/text";
import { t3 } from "@/lib/t3";

// The ICP-fileable suffix list in use (fetched from MIIT, or the one built into
// this release): one summary line in the section, the full list in a dialog,
// so the section stays short.
function formatTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function ICPSuffixView({ list }: { list: ICPSuffixList }) {
  const { pick } = useAdminText();
  const dialog = useRef<HTMLDialogElement>(null);
  const [filter, setFilter] = useState("");
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase().replace(/^\./, "");
    return needle ? list.suffixes.filter((suffix) => suffix.includes(needle)) : list.suffixes;
  }, [filter, list.suffixes]);
  const count = list.suffixes.length;
  const fetched = list.origin === "miit" && list.fetchedAt ? formatTime(list.fetchedAt) : "";
  const summary = fetched
    ? pick(t3(`${count} suffixes · fetched from MIIT ${fetched}`, `${count} 个后缀 · 工信部 · 获取于 ${fetched}`, `${count} 個後綴 · 工信部 · 取得於 ${fetched}`))
    : pick(t3(`${count} suffixes · built into this release (${list.updatedAt})`, `${count} 个后缀 · 本版本内置（${list.updatedAt}）`, `${count} 個後綴 · 本版本內建（${list.updatedAt}）`));
  const title = pick(t3("ICP-fileable suffixes", "可备案后缀名单", "可備案後綴名單"));
  return (
    <div className="adm-suffix-line">
      <span className="adm-label">{pick(t3("Fileable suffixes", "可备案后缀", "可備案後綴"))}</span>
      <span className="adm-hint">{summary}</span>
      <button type="button" className="adm-link-button" onClick={() => dialog.current?.showModal()}>
        {pick(t3("View all", "查看全部", "查看全部"))}
      </button>
      <dialog
        ref={dialog}
        className="adm-dialog"
        aria-label={title}
        onClose={() => setFilter("")}
        onClick={(event) => {
          if (event.target === event.currentTarget) event.currentTarget.close();
        }}
      >
        <div className="adm-dialog-body">
          <div className="adm-dialog-head">
            <strong>{title}</strong>
            <span className="adm-hint">
              {summary}
              {list.sources.map((source) => (
                <span key={source.url}>
                  {" · "}
                  <a href={source.url} target="_blank" rel="noopener noreferrer">
                    {source.name}
                  </a>
                </span>
              ))}
            </span>
            <span className="spacer" />
            <input
              className="adm-input adm-suffix-filter"
              type="search"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder={pick(t3("Filter, e.g. com", "筛选，例如 com", "篩選，例如 com"))}
              aria-label={pick(t3("Filter suffixes", "筛选后缀", "篩選後綴"))}
            />
            <button type="button" className="adm-link-button" onClick={() => dialog.current?.close()}>
              {pick(t3("Close", "关闭", "關閉"))}
            </button>
          </div>
          <ul className="adm-suffix-list">
            {shown.map((suffix) => (
              <li key={suffix}>.{suffix}</li>
            ))}
          </ul>
        </div>
      </dialog>
    </div>
  );
}
