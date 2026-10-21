import { useMemo, useRef, useState } from "react";
import type { ICPSuffixList } from "@/lib/admin/api";
import { useAdminText } from "@/lib/admin/text";
import { t3 } from "@/lib/t3";

// The built-in ICP-fileable suffix list: one summary line in the section, the
// full list in a dialog, so the section stays short.
export function ICPSuffixView({ list }: { list: ICPSuffixList }) {
  const { pick } = useAdminText();
  const dialog = useRef<HTMLDialogElement>(null);
  const [filter, setFilter] = useState("");
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase().replace(/^\./, "");
    return needle ? list.suffixes.filter((suffix) => suffix.includes(needle)) : list.suffixes;
  }, [filter, list.suffixes]);
  const summary = pick(t3(`${list.suffixes.length} suffixes · updated ${list.updatedAt}`, `${list.suffixes.length} 个后缀 · 更新于 ${list.updatedAt}`, `${list.suffixes.length} 個後綴 · 更新於 ${list.updatedAt}`));
  const title = pick(t3("Built-in fileable suffixes", "内置可备案后缀", "內建可備案後綴"));
  return (
    <div className="adm-suffix-line">
      <span className="adm-label">{pick(t3("Built-in list", "内置名单", "內建名單"))}</span>
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
