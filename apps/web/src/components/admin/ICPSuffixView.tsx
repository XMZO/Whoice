import { useMemo, useState } from "react";
import type { ICPSuffixList } from "@/lib/admin/api";
import { useAdminText } from "@/lib/admin/text";
import { t3 } from "@/lib/t3";

// Read-only view of the built-in ICP-fileable suffix list. Lookups mark a
// domain whose TLD is listed here (or in the extra suffixes above).
export function ICPSuffixView({ list }: { list: ICPSuffixList }) {
  const { pick } = useAdminText();
  const [filter, setFilter] = useState("");
  const shown = useMemo(() => {
    const needle = filter.trim().toLowerCase().replace(/^\./, "");
    return needle ? list.suffixes.filter((suffix) => suffix.includes(needle)) : list.suffixes;
  }, [filter, list.suffixes]);
  return (
    <div className="adm-suffix-view">
      <div className="adm-suffix-head">
        <span className="adm-label">{pick(t3("Built-in list", "内置名单", "內建名單"))}</span>
        <span className="adm-hint">
          {pick(t3(`${list.suffixes.length} suffixes · updated ${list.updatedAt}`, `${list.suffixes.length} 个后缀 · 更新于 ${list.updatedAt}`, `${list.suffixes.length} 個後綴 · 更新於 ${list.updatedAt}`))}
          {list.sources.map((source) => (
            <span key={source.url}>
              {" · "}
              <a href={source.url} target="_blank" rel="noopener noreferrer">
                {source.name}
              </a>
            </span>
          ))}
        </span>
        <input
          className="adm-input adm-suffix-filter"
          type="search"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder={pick(t3("Filter, e.g. com", "筛选，例如 com", "篩選，例如 com"))}
          aria-label={pick(t3("Filter suffixes", "筛选后缀", "篩選後綴"))}
        />
      </div>
      <ul className="adm-suffix-list" aria-label={pick(t3("Built-in fileable suffixes", "内置可备案后缀", "內建可備案後綴"))}>
        {shown.map((suffix) => (
          <li key={suffix}>.{suffix}</li>
        ))}
      </ul>
    </div>
  );
}
