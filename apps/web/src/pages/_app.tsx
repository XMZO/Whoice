import type { AppProps } from "next/app";
import Head from "next/head";
import { I18nProvider } from "@/lib/i18n";
import "@/styles/globals.css";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <I18nProvider>
      <Head>
        <meta name="theme-color" content="#111827" />
        <link rel="manifest" href="/manifest.webmanifest" />
        <link rel="icon" href="/icon.svg" />
      </Head>
      <Component {...pageProps} />
    </I18nProvider>
  );
}
