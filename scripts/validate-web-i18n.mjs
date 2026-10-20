// Strict i18n gate for the web app. Fails when user-visible text bypasses translation.
//
// Allowed ways to put text on screen:
//   - t("key") from lib/i18n.tsx (shared strings; all three locales must define every key)
//   - t3("English", "简体中文", "繁體中文") for page- or feature-specific text
//   - diagnostic("...") for developer-facing error details shown verbatim
//   - code samples inside <pre>, <code>, <kbd>, or <CodeBlock>
//
// Run with --list to print every violation, otherwise the first 40 are shown.
import { readFile } from "node:fs/promises";
import { readdirSync, statSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

const ROOT = "apps/web/src";

// Files outside the gate, each with the reason it is safe.
const EXEMPT = new Map([
  ["lib/i18n.tsx", "translation dictionary; checked for locale parity below"],
  ["pages/api/og.tsx", "share image renders with the bundled Latin-only font, so its text stays English"],
  ["pages/api/[...upstream].ts", "API proxy; returns error codes that the UI translates"],
  ["pages/api/lookup.ts", "API route; returns error codes that the UI translates"],
  ["pages/api/icp.ts", "API route; returns error codes that the UI translates"],
  ["pages/api/lookup/ai.ts", "API route; returns error codes that the UI translates"],
  ["pages/api/lookup/enrich.ts", "API route; returns error codes that the UI translates"],
]);

// Words that are product names, protocols, or units rather than prose.
const TERMS = new Set([
  "Whoice", "GitHub", "Cloudflare", "Google", "Moz", "Ollama", "Prometheus", "Caddy", "Nginx", "Docker",
  "ms", "px", "KB", "MB", "UTC",
]);

const TEXT_ATTRIBUTES = new Set(["aria-label", "aria-description", "aria-valuetext", "title", "placeholder", "alt", "label"]);
const TECHNICAL_ATTRIBUTES = new Set([
  "className", "href", "src", "rel", "target", "type", "id", "key", "name", "role", "autoComplete", "inputMode",
  "d", "viewBox", "fill", "stroke", "strokeLinecap", "strokeLinejoin", "htmlFor", "method", "lang", "property",
  "referrerPolicy", "loading", "spellCheck", "data-section", "data-state", "data-run", "data-tab", "data-kind",
  "aria-controls", "aria-current", "aria-hidden", "aria-live", "aria-labelledby", "aria-busy", "aria-modal",
  "aria-checked", "aria-selected", "aria-expanded", "rows", "min", "max", "step", "value", "defaultValue", "charSet",
]);
const UI_PROPERTIES = new Set(["title", "label", "message", "description", "hint", "eyebrow", "text", "heading", "placeholder", "detail", "summary"]);
const CODE_ELEMENTS = new Set(["pre", "code", "kbd", "CodeBlock"]);
const ALLOWED_CALLS = new Set(["t3", "diagnostic", "t", "tf", "at", "pick", "require", "import"]);

// CJK ideographs. Full-width punctuation alone (for example input normalization tables) is not text.
const CJK = /[\u3400-\u9fff\uf900-\ufaff]/;

function proseWords(text) {
  const stripped = text
    .replace(/&[a-z]+;/g, " ")
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/\S*[A-Za-z0-9*]\.[A-Za-z]\S*/g, " ")
    .replace(/(^|\s)\/[\w/.:?=&{}\-[\]]*/g, " ")
    .replace(/\{[^}]*\}/g, " ");
  return stripped
    .split(/[\s,;:()[\]{}"'`|·/—–\-.!?>…×+=*#&]+/)
    .filter((word) => /^[A-Za-z][a-z]+$/.test(word) && !TERMS.has(word));
}

// Language names in the language picker are shown in their own script on purpose.
const ENDONYMS = new Set(["EN", "简体", "繁體", "English", "简体中文", "繁體中文"]);

function isProse(text, minWords) {
  if (ENDONYMS.has(text.trim())) return false;
  return CJK.test(text) || proseWords(text).length >= minWords;
}

function literalText(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) return [node.head.text, ...node.templateSpans.map((span) => span.literal.text)].join(" ");
  return undefined;
}

// String literals a JSX child expression can render: the expression itself, the branches of
// a ternary, and the operands of &&, ||, and ??.
function renderedLiterals(expression) {
  if (ts.isParenthesizedExpression(expression)) return renderedLiterals(expression.expression);
  if (literalText(expression) !== undefined) return [expression];
  if (ts.isConditionalExpression(expression)) return [...renderedLiterals(expression.whenTrue), ...renderedLiterals(expression.whenFalse)];
  if (ts.isBinaryExpression(expression)) {
    const operator = expression.operatorToken.kind;
    if (operator === ts.SyntaxKind.AmpersandAmpersandToken) return renderedLiterals(expression.right);
    if (operator === ts.SyntaxKind.BarBarToken || operator === ts.SyntaxKind.QuestionQuestionToken) {
      return [...renderedLiterals(expression.left), ...renderedLiterals(expression.right)];
    }
  }
  return [];
}

function calleeName(call) {
  const expression = call.expression;
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return "";
}

function insideAllowedCall(node) {
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isCallExpression(current) && ALLOWED_CALLS.has(calleeName(current))) return true;
    if (ts.isImportDeclaration(current) || ts.isExportDeclaration(current)) return true;
  }
  return false;
}

function insideCodeElement(node) {
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isJsxElement(current)) {
      const tag = current.openingElement.tagName.getText();
      if (CODE_ELEMENTS.has(tag)) return true;
    }
  }
  return false;
}

function walkFiles(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) return walkFiles(full);
    return /\.(ts|tsx)$/.test(entry) && !entry.endsWith(".d.ts") ? [full] : [];
  });
}

const violations = [];

for (const file of walkFiles(ROOT)) {
  const relative = path.relative(ROOT, file).split(path.sep).join("/");
  if (EXEMPT.has(relative)) continue;
  const source = ts.createSourceFile(file, await readFile(file, "utf8"), ts.ScriptTarget.Latest, true, file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const report = (node, rule, text) => {
    const { line } = source.getLineAndCharacterOfPosition(node.getStart());
    violations.push(`${relative}:${line + 1}  [${rule}] ${JSON.stringify(text.trim().slice(0, 90))}`);
  };

  const visit = (node) => {
    if (ts.isCallExpression(node) && calleeName(node) === "t3") {
      const args = node.arguments;
      if (args.length !== 3 || !args.every((arg) => literalText(arg) !== undefined && literalText(arg).trim() !== "")) {
        report(node, "t3-shape", node.getText());
      }
      return;
    }

    if (ts.isJsxText(node)) {
      const text = node.getText();
      if (text.trim() && isProse(text, 1) && !insideCodeElement(node)) report(node, "jsx-text", text);
    }

    if (ts.isJsxAttribute(node) && node.initializer) {
      const name = node.name.getText();
      let value;
      if (ts.isStringLiteral(node.initializer)) value = node.initializer.text;
      else if (ts.isJsxExpression(node.initializer) && node.initializer.expression) value = literalText(node.initializer.expression);
      if (value !== undefined && !TECHNICAL_ATTRIBUTES.has(name) && !name.startsWith("data-")) {
        if (isProse(value, TEXT_ATTRIBUTES.has(name) ? 1 : 2)) report(node, `attr:${name}`, value);
      }
    }

    if (ts.isJsxExpression(node) && node.expression && (ts.isJsxElement(node.parent) || ts.isJsxFragment(node.parent)) && !insideCodeElement(node)) {
      for (const branch of renderedLiterals(node.expression)) {
        const value = literalText(branch);
        if (isProse(value, 1)) report(branch, "jsx-child", value);
      }
    }

    if (ts.isPropertyAssignment(node) && UI_PROPERTIES.has(node.name.getText().replace(/["']/g, ""))) {
      const value = literalText(node.initializer);
      if (value !== undefined && isProse(value, 2) && !insideAllowedCall(node)) report(node, `prop:${node.name.getText()}`, value);
    }

    const text = literalText(node);
    if (text !== undefined && CJK.test(text) && !insideAllowedCall(node)) report(node, "cjk-literal", text);

    ts.forEachChild(node, visit);
  };
  visit(source);
}

// Locale parity for the shared dictionary.
const dictionary = await readFile(path.join(ROOT, "lib/i18n.tsx"), "utf8");
const localeKeys = {};
for (const [locale, head] of [["en", "  en: {"], ["zh-CN", '  "zh-CN": {'], ["zh-TW", '  "zh-TW": {']]) {
  const start = dictionary.indexOf(head);
  const end = dictionary.indexOf("\n  },", start);
  if (start < 0 || end < 0) {
    violations.push(`lib/i18n.tsx  [parity] locale block ${locale} not found`);
    continue;
  }
  const block = dictionary.slice(start, end);
  localeKeys[locale] = new Map([...block.matchAll(/\n {4}([A-Za-z0-9]+): ("(?:[^"\\]|\\.)*")/g)].map((match) => [match[1], JSON.parse(match[2])]));
}
const englishKeys = localeKeys.en ? [...localeKeys.en.keys()] : [];
for (const locale of ["zh-CN", "zh-TW"]) {
  for (const key of englishKeys) {
    const value = localeKeys[locale]?.get(key);
    if (value === undefined) violations.push(`lib/i18n.tsx  [parity] ${locale} is missing "${key}"`);
    else if (!value.trim()) violations.push(`lib/i18n.tsx  [parity] ${locale} has an empty "${key}"`);
  }
  for (const key of localeKeys[locale]?.keys() || []) {
    if (!localeKeys.en.has(key)) violations.push(`lib/i18n.tsx  [parity] ${locale} defines "${key}" which English lacks`);
  }
}

if (violations.length) {
  const list = process.argv.includes("--list") ? violations : violations.slice(0, 40);
  console.error(`i18n gate failed: ${violations.length} untranslated user-visible strings.\n`);
  for (const violation of list) console.error(`  ${violation}`);
  if (list.length < violations.length) console.error(`  ... ${violations.length - list.length} more (run with --list)`);
  console.error("\nWrap UI text in t(\"key\") or t3(\"English\", \"简体中文\", \"繁體中文\"); use diagnostic() only for verbatim error details.");
  process.exit(1);
}
console.log(`Validated i18n: ${englishKeys.length} shared keys in 3 locales, no untranslated UI text.`);
