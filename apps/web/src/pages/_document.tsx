import Document, { Head, Html, Main, NextScript, type DocumentContext, type DocumentInitialProps } from "next/document";
import { requestLocale, requestTheme, type Locale, type Theme } from "@/lib/preferences";

type Props = DocumentInitialProps & { locale: Locale; theme: Theme };

// Sets <html lang> and data-theme from the request so the page is in the
// right language and theme before any script runs.
export default class WhoiceDocument extends Document<Props> {
  static async getInitialProps(context: DocumentContext): Promise<Props> {
    const initial = await Document.getInitialProps(context);
    return { ...initial, locale: requestLocale(context.req), theme: requestTheme(context.req) };
  }

  render() {
    return (
      <Html lang={this.props.locale} data-theme={this.props.theme}>
        <Head />
        <body>
          <Main />
          <NextScript />
        </body>
      </Html>
    );
  }
}
