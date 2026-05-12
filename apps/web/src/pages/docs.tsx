import Head from "next/head";
import Link from "next/link";
import { AppControls } from "@/components/AppControls";
import { useI18n } from "@/lib/i18n";

export default function DocsPage() {
  const { t } = useI18n();

  return (
    <>
      <Head>
        <title>API Docs | Whoice</title>
      </Head>
      <main className="shell docs-shell">
        <nav className="top-nav">
          <Link href="/" className="brand">Whoice</Link>
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <AppControls />
          </div>
        </nav>
        <section className="panel">
          <p className="eyebrow">GET</p>
          <h1>/api/lookup</h1>
          <p>Query domains, IPv4, IPv6, ASN, and CIDR values through the Go lookup API.</p>
          <pre>{`curl "http://localhost:8080/api/lookup?query=example.com"`}</pre>
        </section>
      </main>
    </>
  );
}
