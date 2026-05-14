import { readFile } from "node:fs/promises";

const themePath = "apps/web/src/styles/theme.css";
const globalsPath = "apps/web/src/styles/globals.css";

const theme = await readFile(themePath, "utf8");
const globals = await readFile(globalsPath, "utf8");
const failures = [];

const themeVariables = new Set([...theme.matchAll(/--([a-zA-Z0-9_-]+)\s*:/g)].map((match) => match[1]));
const consumedVariables = new Set([...globals.matchAll(/var\(--([a-zA-Z0-9_-]+)/g)].map((match) => match[1]));

for (const variable of consumedVariables) {
  if (!themeVariables.has(variable)) {
    failures.push(`${globalsPath} uses --${variable}, but ${themePath} does not define it.`);
  }
}

const duplicatedVariables = [...themeVariables].filter((variable) => {
  const matches = theme.match(new RegExp(`--${escapeRegExp(variable)}\\s*:`, "g")) || [];
  return matches.length > 1 && !isAllowedOverrideVariable(variable);
});

for (const variable of duplicatedVariables) {
  failures.push(`${themePath} defines --${variable} more than once in the base contract.`);
}

const forbiddenThemeProperties = [
  "display",
  "visibility",
  "opacity",
  "position",
  "z-index",
  "pointer-events",
  "content",
  "overflow",
  "clip",
  "clip-path",
];

for (const block of parseCssBlocks(theme)) {
  if (block.selector.includes(":root")) continue;
  failures.push(`${themePath} should only target :root theme scopes, found selector "${block.selector}".`);
}

for (const declaration of parseCssDeclarations(theme)) {
  if (forbiddenThemeProperties.includes(declaration.property)) {
    failures.push(`${themePath} must not set "${declaration.property}"; themes should not hide or reposition UI features.`);
  }
}

const criticalSelectors = [
  ".search-box",
  ".mini-search",
  ".source-toggle",
  ".advanced-lookup",
  ".lookup-workbench",
  ".tool-sidebar",
  ".tool-panel",
  ".tool-stage",
  ".tool-zone",
  ".status-strip",
  ".summary-panel",
  ".dns-panel",
  ".registration-panel",
  ".icp-panel",
  ".status-panel",
  ".action-bar",
  ".share-menu-panel",
  ".resolver-tooltip",
  ".source-popover-body",
  ".raw-panel pre",
  ".trace-list",
  ".plugin-shell",
];

const allowedControlledHiddenSelectors = new Set([
  ".source-popover-body",
]);

for (const selector of criticalSelectors) {
  if (!hasSelector(globals, selector)) {
    failures.push(`${globalsPath} is missing critical UI selector "${selector}".`);
  }
}

for (const block of parseCssBlocks(globals)) {
  const selectors = block.selector.split(",").map((selector) => selector.trim());
  if (!selectors.some((selector) => criticalSelectors.includes(selector))) continue;
  for (const declaration of parseBlockDeclarations(block.body)) {
    if (declaration.property === "display" && declaration.value === "none") {
      if (selectors.some((selector) => allowedControlledHiddenSelectors.has(selector))) continue;
      failures.push(`${globalsPath} statically hides critical UI selector "${block.selector}" with display:none.`);
    }
    if (declaration.property === "visibility" && declaration.value === "hidden") {
      failures.push(`${globalsPath} statically hides critical UI selector "${block.selector}" with visibility:hidden.`);
    }
  }
}

if (failures.length) {
  throw new Error(`Web theme validation failed:\n- ${failures.join("\n- ")}`);
}

console.log(`Validated ${themeVariables.size} theme variables and ${criticalSelectors.length} critical UI selectors.`);

function parseCssBlocks(css) {
  const blocks = [];
  const blockPattern = /([^{}]+)\{([^{}]*)\}/g;
  let match;
  while ((match = blockPattern.exec(stripComments(css)))) {
    blocks.push({ selector: match[1].trim(), body: match[2] });
  }
  return blocks;
}

function parseCssDeclarations(css) {
  const declarations = [];
  for (const block of parseCssBlocks(css)) {
    declarations.push(...parseBlockDeclarations(block.body).map((declaration) => ({ ...declaration, selector: block.selector })));
  }
  return declarations;
}

function parseBlockDeclarations(body) {
  const declarations = [];
  for (const part of body.split(";")) {
    const index = part.indexOf(":");
    if (index === -1) continue;
    const property = part.slice(0, index).trim().toLowerCase();
    if (!property || property.startsWith("--")) continue;
    declarations.push({ property, value: part.slice(index + 1).trim().toLowerCase() });
  }
  return declarations;
}

function hasSelector(css, selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\ /g, "\\s+");
  return new RegExp(`(^|[},])\\s*${escaped}\\s*([,{])`, "m").test(css);
}

function isAllowedOverrideVariable(variable) {
  const overrideVariables = new Set([
    "bg",
    "panel",
    "panel-subtle",
    "border",
    "text",
    "muted",
    "link",
    "brand",
    "green",
    "green-bg",
    "blue",
    "blue-bg",
    "amber",
    "amber-bg",
    "red",
    "red-bg",
    "shadow-control",
    "shadow-menu",
    "shadow-popover",
    "resolver-error-bg",
    "resolver-error-border",
    "resolver-error-text",
  ]);
  return overrideVariables.has(variable);
}

function stripComments(css) {
  return css.replace(/\/\*[\s\S]*?\*\//g, "");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
