// Refreshes packages/data/icp-suffixes/icp-suffixes.json from MIIT's
// 中国互联网域名体系 page (https://domain.miit.gov.cn/chinayu.jsp), which loads
// the approved TLDs from /yuming/getYMList, then copies it into the API's
// embedded snapshot. A failed or implausible fetch keeps the current list.
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const file = path.join(root, "packages/data/icp-suffixes/icp-suffixes.json");
const embedded = path.join(root, "services/lookup-api/internal/data/icpsuffixes/snapshots/icp-suffixes.json");
const page = "https://domain.miit.gov.cn/chinayu.jsp";
const endpoint = process.env.WHOICE_ICP_SUFFIX_URL || "https://domain.miit.gov.cn/yuming/getYMList";

const current = JSON.parse(await readFile(file, "utf8"));

async function fetchList() {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "X-Requested-With": "XMLHttpRequest", Referer: page },
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const data = JSON.parse(await response.text());
  const names = ["cn", "china", "ch", "en"].flatMap((group) => (Array.isArray(data[group]) ? data[group] : []).map((item) => item?.DICT_NAME));
  const suffixes = [...new Set(names.filter((name) => typeof name === "string").map((name) => name.trim().replace(/^[.．]/, "").toLowerCase()).filter(Boolean))];
  for (const required of ["cn", "中国", "com", "net"]) {
    if (!suffixes.includes(required)) throw new Error(`answer lacks .${required}`);
  }
  if (suffixes.length < 100) throw new Error(`only ${suffixes.length} suffixes`);
  const ascii = suffixes.filter((suffix) => /^[a-z0-9-]+$/.test(suffix)).sort();
  const other = suffixes.filter((suffix) => !/^[a-z0-9-]+$/.test(suffix)).sort();
  return [...ascii, ...other];
}

let suffixes;
try {
  suffixes = await fetchList();
} catch (error) {
  console.warn(`ICP suffix list not refreshed (${error.message}); keeping the current list.`);
  process.exit(0);
}

if (JSON.stringify(suffixes) === JSON.stringify(current.suffixes)) {
  console.log(`ICP suffix list unchanged (${suffixes.length} suffixes).`);
} else {
  const next = { ...current, updatedAt: new Date().toISOString().slice(0, 10), suffixes };
  const body = `${JSON.stringify(next, null, 2)}\n`;
  await writeFile(file, body);
  await writeFile(embedded, body);
  console.log(`ICP suffix list updated: ${suffixes.length} suffixes.`);
}
