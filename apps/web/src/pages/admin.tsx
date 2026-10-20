import Head from "next/head";
import { useCallback, useEffect, useState } from "react";
import { AdminLogin } from "@/components/admin/AdminLogin";
import { AdminPanel } from "@/components/admin/AdminPanel";
import { adminApi } from "@/lib/admin/api";
import { useAdminText } from "@/lib/admin/text";

type View = { state: "loading" } | { state: "signed-out" } | { state: "signed-in"; passwordFromEnv: boolean } | { state: "error"; message: string };

export default function AdminPage() {
  const { at } = useAdminText();
  const [view, setView] = useState<View>({ state: "loading" });

  const check = useCallback(() => {
    adminApi
      .session()
      .then((session) => setView(session.authenticated ? { state: "signed-in", passwordFromEnv: session.passwordFromEnv } : { state: "signed-out" }))
      .catch((error: Error) => setView({ state: "error", message: error.message }));
  }, []);

  useEffect(check, [check]);

  return (
    <>
      <Head>
        <title>{`${at("panel")} | Whoice`}</title>
        <meta name="robots" content="noindex" />
      </Head>
      {view.state === "signed-in" ? (
        <AdminPanel passwordFromEnv={view.passwordFromEnv} onSignedOut={() => setView({ state: "signed-out" })} />
      ) : view.state === "signed-out" ? (
        <AdminLogin onSignedIn={check} />
      ) : (
        <main className="adm-login">
          <div className="adm-login-card">
            {view.state === "error" ? (
              <>
                <p className="adm-error" role="alert">{view.message}</p>
                <button type="button" className="adm-btn" onClick={check}>{at("retry")}</button>
              </>
            ) : (
              <p className="adm-note">{at("loading")}</p>
            )}
          </div>
        </main>
      )}
    </>
  );
}
