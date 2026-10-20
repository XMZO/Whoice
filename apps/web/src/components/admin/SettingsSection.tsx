import type { AdminConfig } from "@/lib/admin/api";
import { readPath } from "@/lib/admin/api";
import type { Field, Section } from "@/lib/admin/schema";
import { useAdminText } from "@/lib/admin/text";
import { FieldRow } from "./Fields";

export type Draft = Record<string, unknown>;

export function SettingsSection({
  section,
  config,
  draft,
  onChange,
}: {
  section: Section;
  config: AdminConfig;
  draft: Draft;
  onChange: (path: string, value: unknown) => void;
}) {
  const { pick } = useAdminText();
  const get = (path: string) => (path in draft ? draft[path] : readPath(config.settings, path));
  const visible = (field: Field) => !field.visibleWhen || field.visibleWhen(get);

  return (
    <div className="adm-groups">
      {section.groups.map((group, index) => {
        const fields = group.fields.filter(visible);
        if (!fields.length) return null;
        const toggles = fields.filter((field) => field.type === "toggle");
        const inputs = fields.filter((field) => field.type !== "toggle");
        const row = (field: Field) => (
          <FieldRow
            key={field.path}
            field={field}
            value={get(field.path)}
            touched={field.path in draft}
            lockedBy={config.envLocked[field.path]}
            secrets={config.secrets}
            onChange={(value) => onChange(field.path, value)}
          />
        );
        return (
          <section className="adm-group" key={group.title ? group.title[0] : index}>
            {group.title && <h3 className="adm-group-title">{pick(group.title)}</h3>}
            {toggles.length > 0 && <div className="adm-toggles">{toggles.map(row)}</div>}
            {inputs.length > 0 && <div className="adm-fields">{inputs.map(row)}</div>}
          </section>
        );
      })}
    </div>
  );
}
