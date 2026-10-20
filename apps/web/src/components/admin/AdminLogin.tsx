import Link from "next/link";
import { FormEvent, useState } from "react";
import { BrandMark } from "@/components/BrandMark";
import { PadlockIcon } from "@/components/Icons";
import { adminApi } from "@/lib/admin/api";
import { useAdminText } from "@/lib/admin/text";

export function AdminLogin({ onSignedIn }: { onSignedIn: () => void }) {
  const { at, errorText } = useAdminText();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await adminApi.login(password);
      onSignedIn();
    } catch (reason) {
      setError(errorText(reason));
      setBusy(false);
    }
  }

  return (
    <main className="adm-login">
      <form className="adm-login-card" onSubmit={submit}>
        <BrandMark variant="home" />
        <span className="adm-login-icon" aria-hidden="true"><PadlockIcon size={18} /></span>
        <h1>{at("signInTitle")}</h1>
        <label className="adm-label" htmlFor="adm-password">{at("password")}</label>
        <input
          id="adm-password"
          className="adm-input"
          type="password"
          autoComplete="current-password"
          autoFocus
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />
        {error && <p className="adm-error" role="alert">{error}</p>}
        <button type="submit" className="adm-btn adm-btn-primary adm-btn-block" disabled={busy || !password}>
          {busy ? at("signingIn") : at("signIn")}
        </button>
        <p className="adm-note mono-wrap">{at("firstPassword")}</p>
        <Link href="/" className="adm-back">{at("backToSite")}</Link>
      </form>
    </main>
  );
}
