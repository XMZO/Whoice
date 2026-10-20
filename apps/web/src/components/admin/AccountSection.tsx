import { FormEvent, useState } from "react";
import { adminApi } from "@/lib/admin/api";
import { useAdminText } from "@/lib/admin/text";

export function AccountSection({ passwordFromEnv, onSignOut }: { passwordFromEnv: boolean; onSignOut: () => void }) {
  const { at, errorText } = useAdminText();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (next !== confirm) {
      setMessage({ ok: false, text: at("mismatch") });
      return;
    }
    if (next.length < 8) {
      setMessage({ ok: false, text: at("minLength") });
      return;
    }
    setBusy(true);
    try {
      await adminApi.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setMessage({ ok: true, text: at("passwordChanged") });
    } catch (error) {
      setMessage({ ok: false, text: errorText(error) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="adm-groups">
      <section className="adm-group">
        <h3 className="adm-group-title">{at("changePassword")}</h3>
        {passwordFromEnv ? (
          <p className="adm-note">{at("passwordFromEnv")}</p>
        ) : (
          <form className="adm-fields adm-password-form" onSubmit={submit}>
            <div className="adm-field">
              <label className="adm-label" htmlFor="adm-current">{at("currentPassword")}</label>
              <input id="adm-current" className="adm-input" type="password" autoComplete="current-password" value={current} onChange={(event) => setCurrent(event.target.value)} required />
            </div>
            <div className="adm-field">
              <label className="adm-label" htmlFor="adm-next">{at("newPassword")}</label>
              <input id="adm-next" className="adm-input" type="password" autoComplete="new-password" minLength={8} value={next} onChange={(event) => setNext(event.target.value)} required />
              <span className="adm-hint">{at("minLength")}</span>
            </div>
            <div className="adm-field">
              <label className="adm-label" htmlFor="adm-confirm">{at("confirmPassword")}</label>
              <input id="adm-confirm" className="adm-input" type="password" autoComplete="new-password" value={confirm} onChange={(event) => setConfirm(event.target.value)} required />
            </div>
            <div className="adm-field adm-form-actions">
              {message && <span className={message.ok ? "adm-ok" : "adm-error"} role="status">{message.text}</span>}
              <button type="submit" className="adm-btn adm-btn-primary" disabled={busy}>{at("changePassword")}</button>
            </div>
          </form>
        )}
        <p className="adm-note mono-wrap">{at("resetHint")}</p>
      </section>
      <section className="adm-group">
        <h3 className="adm-group-title">{at("session")}</h3>
        <p className="adm-note">{at("sessionNote")}</p>
        <button type="button" className="adm-btn" onClick={onSignOut}>{at("signOut")}</button>
      </section>
    </div>
  );
}
