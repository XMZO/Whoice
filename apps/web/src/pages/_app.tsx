import NextApp, { type AppContext, type AppProps } from "next/app";
import Head from "next/head";
import { I18nProvider } from "@/lib/i18n";
import { requestLocale, requestTheme, type Locale, type Theme } from "@/lib/preferences";
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-sans/latin-700.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-600.css";
import "@fontsource/noto-sans-sc/400.css";
import "@fontsource/noto-sans-sc/500.css";
import "@fontsource/noto-sans-sc/700.css";
import "@/styles/theme.css";
import "@/styles/globals.css";

type WhoiceAppProps = AppProps & { initialLocale?: Locale; initialTheme?: Theme };

export default function App({ Component, pageProps, initialLocale, initialTheme }: WhoiceAppProps) {
  return (
    <I18nProvider initialLocale={initialLocale} initialTheme={initialTheme}>
      <Head>
        <meta name="theme-color" content="#edf1f2" />
        <link rel="manifest" href="/manifest.webmanifest" />
        <link rel="icon" href="/icon.svg" />
      </Head>
      <Component {...pageProps} />
    </I18nProvider>
  );
}

// Server renders read the language and theme from the request (cookie, then
// Accept-Language), so the first HTML is final. Client-side navigations keep
// the provider's current state.
App.getInitialProps = async (context: AppContext) => {
  const props = await NextApp.getInitialProps(context);
  const req = context.ctx.req;
  return req ? { ...props, initialLocale: requestLocale(req), initialTheme: requestTheme(req) } : props;
};
