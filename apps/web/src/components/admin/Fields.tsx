import { useId } from "react";
import type { SecretState } from "@/lib/admin/api";
import type { Field } from "@/lib/admin/schema";
import { useAdminText } from "@/lib/admin/text";

export type FieldProps = {
  field: Field;
  value: unknown;
  // True when the draft holds an edit for this field (secrets start untouched).
  touched: boolean;
  lockedBy?: string;
  secrets: SecretState;
  onChange: (value: unknown) => void;
};

function linesToList(text: string) {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function listText(value: unknown) {
  return Array.isArray(value) ? value.join("\n") : "";
}

function randomToken() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function FieldRow(props: FieldProps) {
  const { field, lockedBy } = props;
  const { pick, at } = useAdminText();
  const id = useId();
  const hint = lockedBy ? at("envLocked", { env: lockedBy }) : field.hint ? pick(field.hint) : undefined;

  if (field.type === "toggle") {
    const checked = Boolean(props.value);
    return (
      <label className={`adm-toggle${lockedBy ? " is-locked" : ""}`} htmlFor={id}>
        <span className="adm-field-text">
          <span className="adm-label">{pick(field.label)}</span>
          {hint && <span className={lockedBy ? "adm-hint adm-hint-locked" : "adm-hint"}>{hint}</span>}
        </span>
        <input
          id={id}
          type="checkbox"
          role="switch"
          className="adm-switch"
          checked={checked}
          disabled={Boolean(lockedBy)}
          onChange={(event) => props.onChange(event.target.checked)}
        />
      </label>
    );
  }

  return (
    <div className={`adm-field${field.wide ? " is-wide" : ""}${lockedBy ? " is-locked" : ""}`}>
      <label className="adm-label" htmlFor={id}>
        {pick(field.label)}
      </label>
      <FieldInput {...props} id={id} />
      {hint && <span className={lockedBy ? "adm-hint adm-hint-locked" : "adm-hint"}>{hint}</span>}
    </div>
  );
}

function FieldInput({ field, value, touched, lockedBy, secrets, onChange, id }: FieldProps & { id: string }) {
  const { pick, at } = useAdminText();
  const disabled = Boolean(lockedBy);

  switch (field.type) {
    case "text":
      return (
        <input
          id={id}
          className={`adm-input${field.mono ? " mono" : ""}`}
          value={String(value ?? "")}
          placeholder={field.placeholder}
          disabled={disabled}
          spellCheck={false}
          onChange={(event) => onChange(event.target.value)}
        />
      );
    case "duration":
      return (
        <input
          id={id}
          className="adm-input mono"
          value={String(value ?? "")}
          placeholder={field.cache ? "72h / 0 / forever" : "10s"}
          disabled={disabled}
          spellCheck={false}
          onChange={(event) => onChange(event.target.value)}
        />
      );
    case "number":
      return (
        <input
          id={id}
          className="adm-input mono"
          type="number"
          inputMode="decimal"
          min={field.min}
          max={field.max}
          step={field.step ?? 1}
          value={value === undefined || value === null ? "" : String(value)}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value === "" ? "" : Number(event.target.value))}
        />
      );
    case "select":
      return (
        <select id={id} className="adm-input" value={String(value ?? "")} disabled={disabled} onChange={(event) => onChange(event.target.value)}>
          {field.options.map((option) => (
            <option key={option.value} value={option.value}>
              {pick(option.label)}
            </option>
          ))}
        </select>
      );
    case "list":
      return (
        <textarea
          id={id}
          className="adm-input adm-textarea mono"
          rows={3}
          value={listText(value)}
          placeholder={`${field.placeholder || ""}\n${at("onePerLine")}`}
          disabled={disabled}
          spellCheck={false}
          onChange={(event) => onChange(event.target.value.split("\n"))}
          onBlur={(event) => onChange(linesToList(event.target.value))}
        />
      );
    case "secret": {
      const isSet = secrets[field.secret];
      const cleared = touched && value === "";
      return (
        <span className="adm-inline">
          <input
            id={id}
            className="adm-input mono"
            type="password"
            autoComplete="new-password"
            value={touched ? String(value ?? "") : ""}
            placeholder={cleared ? at("cleared") : isSet ? at("secretSet") : at("secretUnset")}
            disabled={disabled}
            onChange={(event) => onChange(event.target.value)}
          />
          {isSet && !disabled && (
            <button type="button" className="adm-btn adm-btn-ghost" onClick={() => onChange("")}>
              {at("clear")}
            </button>
          )}
        </span>
      );
    }
    case "tokens": {
      const count = secrets.api_tokens;
      const text = touched ? listText(value) : "";
      return (
        <span className="adm-stack">
          <textarea
            id={id}
            className="adm-input adm-textarea mono"
            rows={2}
            value={text}
            placeholder={count ? at("tokensSet", { n: count }) : at("onePerLine")}
            disabled={disabled}
            spellCheck={false}
            onChange={(event) => onChange(event.target.value.split("\n"))}
            onBlur={(event) => onChange(linesToList(event.target.value))}
          />
          {!disabled && (
            <span className="adm-inline-actions">
              <button type="button" className="adm-btn adm-btn-ghost" onClick={() => onChange([...linesToList(text), randomToken()])}>
                {at("generate")}
              </button>
              {count > 0 && (
                <button type="button" className="adm-btn adm-btn-ghost" onClick={() => onChange([])}>
                  {at("clear")}
                </button>
              )}
            </span>
          )}
        </span>
      );
    }
    case "prompt":
      return (
        <span className="adm-stack">
          <textarea
            id={id}
            className="adm-input adm-textarea adm-prompt mono"
            rows={8}
            value={String(value ?? "")}
            disabled={disabled}
            spellCheck={false}
            onChange={(event) => onChange(event.target.value)}
          />
          {!disabled && (
            <span className="adm-inline-actions">
              <button type="button" className="adm-btn adm-btn-ghost" onClick={() => onChange("")}>
                {at("resetDefault")}
              </button>
            </span>
          )}
        </span>
      );
    default:
      return null;
  }
}
