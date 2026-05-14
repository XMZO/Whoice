import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';

const requiredRDAPKinds = ['dns', 'ipv4', 'ipv6', 'asn'];
const requiredPublicSuffixes = ['pp.ua', 'eu.org', 'qzz.io', 'edu.kg', 'de5.net', 'cc.cd', 'us.ci'];
const requiredRDAPExtraSuffixes = ['li', 'ch', 'de', 'io', 'me', 'eu.com', 'uk.com', 'radio.fm', 'ae.org', 'v.ua'];

await validateRDAPBootstrap();
await validateRegistrars();
await validatePublicSuffix();
await validateJSONData();
await validateSnapshotSync();

console.log('Validated data snapshots, manifests, embedded sync, and critical routing coverage.');

async function validateRDAPBootstrap() {
  const manifest = await readJSON('packages/data/rdap-bootstrap/manifest.json');
  for (const kind of requiredRDAPKinds) {
    const file = `packages/data/rdap-bootstrap/${kind}.json`;
    const body = await readText(file);
    assertHash(manifest, kind, file, body);
    const parsed = JSON.parse(body);
    assert(Array.isArray(parsed.services), `${file} must contain services[]`);
    assert(parsed.services.length > 0, `${file} must contain at least one RDAP service`);
    for (const [index, service] of parsed.services.entries()) {
      assert(Array.isArray(service) && service.length >= 2, `${file} service ${index} must be [keys, urls]`);
      assert(Array.isArray(service[0]) && service[0].length > 0, `${file} service ${index} must include keys`);
      assert(Array.isArray(service[1]) && service[1].some(isHTTPURL), `${file} service ${index} must include an HTTP(S) RDAP URL`);
    }
  }

  const dns = JSON.parse(await readText('packages/data/rdap-bootstrap/dns.json'));
  for (const suffix of ['com', 'net', 'org', 'uk']) {
    assert(rdapDNSHasSuffix(dns, suffix), `RDAP DNS snapshot must cover .${suffix}`);
  }
  const extra = await readJSON('packages/data/rdap-bootstrap/extra.json');
  for (const suffix of requiredRDAPExtraSuffixes) {
    assert(isHTTPURL(extra[suffix]), `RDAP extra overlay must route ${suffix}`);
  }
  const ipv4 = JSON.parse(await readText('packages/data/rdap-bootstrap/ipv4.json'));
  for (const rir of ['rdap.arin.net', 'rdap.apnic.net', 'rdap.db.ripe.net', 'rdap.afrinic.net', 'rdap.lacnic.net']) {
    assert(rdapHasServiceURL(ipv4, rir), `RDAP IPv4 snapshot must cover ${rir}`);
  }
  const asn = JSON.parse(await readText('packages/data/rdap-bootstrap/asn.json'));
  assert(rdapHasServiceURL(asn, 'rdap.arin.net'), 'RDAP ASN snapshot must cover ARIN');
}

async function validateRegistrars() {
  const file = 'packages/data/registrars/icann-accredited-registrars.csv';
  const manifest = await readJSON('packages/data/registrars/manifest.json');
  const body = await readText(file);
  assertHash(manifest, 'icannAccreditedRegistrars', file, body);
  const rows = parseCSV(body);
  assert(rows.length > 1000, `${file} should contain the full ICANN registrar list, got ${rows.length} rows`);
  const header = rows[0].map((cell) => cell.trim());
  assert(header.includes('Registrar Name') && header.includes('IANA Number'), `${file} has an unexpected header`);
  const names = rows.slice(1).map((row) => row[0]);
  assert(names.some((name) => /Cloudflare/i.test(name)), `${file} should include Cloudflare`);
  assert(names.some((name) => /GoDaddy/i.test(name)), `${file} should include GoDaddy`);
}

async function validatePublicSuffix() {
  const file = 'packages/data/public-suffix/public_suffix_list.dat';
  const manifest = await readJSON('packages/data/public-suffix/manifest.json');
  const body = await readText(file);
  assertHash(manifest, 'publicSuffixList', file, body);
  assert(body.includes('BEGIN ICANN DOMAINS'), `${file} must contain ICANN section`);
  assert(body.includes('BEGIN PRIVATE DOMAINS'), `${file} must contain PRIVATE section`);
  const suffixes = publicSuffixLines(body + '\n' + await readText('packages/data/public-suffix/extra.dat'));
  for (const suffix of requiredPublicSuffixes) {
    assert(suffixes.has(suffix), `PSL snapshot or overlay must cover ${suffix}`);
  }
}

async function validateJSONData() {
  await readJSON('packages/data/brands/brand-map.json');
  await readJSON('packages/data/pricing/pricing.json');
  await readJSON('packages/data/enrichment/moz.json');
  const whoisIANA = await readJSON('packages/data/whois-servers/iana.json');
  const whoisExtra = await readJSON('packages/data/whois-servers/extra.json');
  for (const suffix of requiredPublicSuffixes) {
    assert(whoisExtra[suffix] || whoisIANA[tldOf(suffix)], `WHOIS server maps must route ${suffix}`);
  }
  for (const suffix of ['com', 'net', 'org', 'uk']) {
    assert(Object.hasOwn(whoisIANA, suffix), `WHOIS IANA server map must include ${suffix}`);
  }
}

async function validateSnapshotSync() {
  const pairs = [
    ['packages/data/rdap-bootstrap/dns.json', 'services/lookup-api/internal/data/rdapbootstrap/snapshots/dns.json'],
    ['packages/data/rdap-bootstrap/ipv4.json', 'services/lookup-api/internal/data/rdapbootstrap/snapshots/ipv4.json'],
    ['packages/data/rdap-bootstrap/ipv6.json', 'services/lookup-api/internal/data/rdapbootstrap/snapshots/ipv6.json'],
    ['packages/data/rdap-bootstrap/asn.json', 'services/lookup-api/internal/data/rdapbootstrap/snapshots/asn.json'],
    ['packages/data/rdap-bootstrap/extra.json', 'services/lookup-api/internal/data/rdapbootstrap/snapshots/extra.json'],
    ['packages/data/registrars/icann-accredited-registrars.csv', 'services/lookup-api/internal/data/registrars/snapshots/icann-accredited-registrars.csv'],
    ['packages/data/brands/brand-map.json', 'services/lookup-api/internal/data/brandmap/snapshots/brand-map.json'],
    ['packages/data/pricing/pricing.json', 'services/lookup-api/internal/enrich/pricing/snapshots/pricing.json'],
    ['packages/data/enrichment/moz.json', 'services/lookup-api/internal/data/enrichment/snapshots/moz.json'],
    ['packages/data/whois-servers/iana.json', 'services/lookup-api/internal/data/whoisservers/snapshots/iana.json'],
    ['packages/data/whois-servers/extra.json', 'services/lookup-api/internal/data/whoisservers/snapshots/extra.json'],
    ['packages/data/public-suffix/public_suffix_list.dat', 'services/lookup-api/internal/data/publicsuffixes/snapshots/public_suffix_list.dat'],
    ['packages/data/public-suffix/extra.dat', 'services/lookup-api/internal/data/publicsuffixes/snapshots/extra.dat'],
  ];
  for (const [reviewable, embedded] of pairs) {
    const left = await readText(reviewable);
    const right = await readText(embedded);
    assert(left === right, `${embedded} must match ${reviewable}`);
  }
}

function assertHash(manifest, key, file, body) {
  const expected = manifest?.sha256?.[key];
  assert(typeof expected === 'string' && expected.length === 64, `${file} is missing sha256 manifest entry ${key}`);
  const actual = sha256(body);
  assert(actual === expected, `${file} sha256 mismatch: got ${actual}, want ${expected}`);
}

function rdapDNSHasSuffix(file, suffix) {
  return file.services.some((service) => Array.isArray(service?.[0]) && service[0].includes(suffix));
}

function rdapHasServiceURL(file, needle) {
  return file.services.some((service) => Array.isArray(service?.[1]) && service[1].some((url) => String(url).includes(needle)));
}

function isHTTPURL(value) {
  const text = String(value);
  return text.startsWith('https://') || text.startsWith('http://');
}

function publicSuffixLines(body) {
  const values = new Set();
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim().toLowerCase();
    if (!line || line.startsWith('//')) {
      continue;
    }
    values.add(line.replace(/^\*\./, '').replace(/^!/, ''));
  }
  return values;
}

function tldOf(suffix) {
  return String(suffix).split('.').at(-1);
}

function parseCSV(body) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    const next = body[i + 1];
    if (quoted) {
      if (ch === '"' && next === '"') {
        cell += '"';
        i += 1;
      } else if (ch === '"') {
        quoted = false;
      } else {
        cell += ch;
      }
      continue;
    }
    if (ch === '"') {
      quoted = true;
    } else if (ch === ',') {
      row.push(cell);
      cell = '';
    } else if (ch === '\n') {
      row.push(cell.replace(/\r$/, ''));
      rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += ch;
    }
  }
  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

async function readJSON(file) {
  const body = await readText(file);
  if (file.endsWith('.yaml') || file.endsWith('.yml')) {
    return parseYaml(body);
  }
  return JSON.parse(body);
}

async function readText(file) {
  return readFile(path.normalize(file), 'utf8');
}

function sha256(body) {
  return createHash('sha256').update(body).digest('hex');
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}
