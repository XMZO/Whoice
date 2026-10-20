// Marks developer-facing diagnostic text (shown verbatim as error details, never as
// headings or labels). The i18n gate skips strings wrapped in diagnostic(...).
export function diagnostic(text: string) {
  return text;
}
