#!/usr/bin/env node
// Builds data/kev.json, data/kev.csv and the README stats block.
// Inputs: the CISA KEV catalog (CC0) and Vektor's public POST /api/triage (decision, inputs, EPSS), 500 ids per call.
// No secrets: both endpoints are public. Usage: node scripts/build.mjs
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const KEV_FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const VEKTOR = 'https://vektor.jvcr.se';
const BATCH = 500;
const UA = 'kev-ssvc-decisions (+https://github.com/jvcr/kev-ssvc-decisions)';
// Fail instead of publishing a dump with many empty decisions (API outage, partial answer).
const MAX_MISSING_SHARE = 0.02;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(url, init = {}) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, { ...init, headers: { 'User-Agent': UA, Accept: 'application/json', ...init.headers }, signal: AbortSignal.timeout(120_000) });
    if (res.ok) return await res.json();
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt >= 4) throw new Error(`${init.method ?? 'GET'} ${url}: HTTP ${res.status} ${(await res.text()).slice(0, 300)}`);
    const after = Number(res.headers.get('Retry-After'));
    await sleep(Number.isFinite(after) && after > 0 ? after * 1000 : res.status === 429 ? 61_000 : 2000 * 2 ** attempt);
  }
}

const kev = await fetchJson(KEV_FEED);
if (!Array.isArray(kev.vulnerabilities) || kev.vulnerabilities.length < 1000) throw new Error('Unexpected KEV feed shape');
const ids = [...new Set(kev.vulnerabilities.map((v) => v.cveID))];
if (ids.length !== kev.vulnerabilities.length) throw new Error(`KEV feed has duplicate cveIDs (${kev.vulnerabilities.length} rows, ${ids.length} ids)`);
if (typeof kev.count === 'number' && kev.count !== ids.length) throw new Error(`KEV count field ${kev.count} != ${ids.length} entries`);

const vektor = new Map();
for (let i = 0; i < ids.length; i += BATCH) {
  const body = await fetchJson(`${VEKTOR}/api/triage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ cves: ids.slice(i, i + BATCH) }) });
  for (const item of body.items ?? []) vektor.set(item.id, item);
}
const missing = ids.filter((id) => !vektor.has(id));
if (missing.length > ids.length * MAX_MISSING_SHARE) throw new Error(`Vektor returned no row for ${missing.length} of ${ids.length} KEV CVEs`);

const FLOOR = { 'Vektor policy: active exploitation': 'active_exploitation', 'Vektor policy: CISA-confirmed ransomware': 'ransomware_network' };
const floorCode = (reason) => reason ? Object.entries(FLOOR).find(([prefix]) => reason.startsWith(prefix))?.[1] ?? 'other' : null;
const day = (s) => (typeof s === 'string' && s ? s.slice(0, 10) : null);

const records = kev.vulnerabilities.map((v) => {
  const item = vektor.get(v.cveID);
  const d = item?.decision;
  return {
    cve_id: v.cveID,
    kev: {
      vendor_project: v.vendorProject ?? null,
      product: v.product ?? null,
      vulnerability_name: v.vulnerabilityName ?? null,
      date_added: v.dateAdded ?? null,
      due_date: v.dueDate ?? null,
      known_ransomware_campaign_use: v.knownRansomwareCampaignUse ?? null,
    },
    decision: d ? {
      value: d.decision,
      label: d.label,
      ssvc_table_result: d.ssvc_label,
      sla_days: d.sla_days,
      policy_floor: floorCode(d.policy_floor_reason),
      inputs: {
        exploitation: d.inputs.exploitation,
        automatable: d.inputs.automatable,
        technical_impact: d.inputs.technical_impact,
        mission: d.inputs.mission,
      },
      model_version: d.model_version,
    } : null,
    epss: item && item.epss != null ? { score: item.epss, percentile: item.epss_pct ?? null, date: day(item.epss_date) } : null,
    vektor_url: `${VEKTOR}/cve/${v.cveID}`,
  };
}).sort((a, b) => (b.kev.date_added ?? '').localeCompare(a.kev.date_added ?? '') || a.cve_id.localeCompare(b.cve_id));

const models = [...new Set(records.map((r) => r.decision?.model_version).filter(Boolean))];
const generatedAt = new Date().toISOString();
const doc = {
  generated_at: generatedAt,
  count: records.length,
  kev_catalog_version: kev.catalogVersion ?? null,
  kev_date_released: kev.dateReleased ?? null,
  decision_model_version: models.length === 1 ? models[0] : models,
  mission_assumed: 'medium',
  without_vektor_record: missing,
  sources: {
    kev: { name: 'CISA Known Exploited Vulnerabilities Catalog', url: KEV_FEED, license: 'CC0-1.0' },
    epss: { name: 'FIRST EPSS (Exploit Prediction Scoring System)', url: 'https://www.first.org/epss/', terms: 'Free to use; attribution requested by FIRST' },
    decision: { name: 'Vektor', url: `${VEKTOR}/methodology`, license: 'CC0-1.0' },
  },
  vulnerabilities: records,
};

const COLUMNS = [
  ['cve_id', (r) => r.cve_id],
  ['kev_vendor_project', (r) => r.kev.vendor_project],
  ['kev_product', (r) => r.kev.product],
  ['kev_vulnerability_name', (r) => r.kev.vulnerability_name],
  ['kev_date_added', (r) => r.kev.date_added],
  ['kev_due_date', (r) => r.kev.due_date],
  ['kev_known_ransomware_campaign_use', (r) => r.kev.known_ransomware_campaign_use],
  ['decision', (r) => r.decision?.value],
  ['decision_label', (r) => r.decision?.label],
  ['ssvc_table_result', (r) => r.decision?.ssvc_table_result],
  ['sla_days', (r) => r.decision?.sla_days],
  ['policy_floor', (r) => r.decision?.policy_floor],
  ['exploitation', (r) => r.decision?.inputs.exploitation.value],
  ['exploitation_source', (r) => r.decision?.inputs.exploitation.source],
  ['automatable', (r) => r.decision?.inputs.automatable.value],
  ['automatable_source', (r) => r.decision?.inputs.automatable.source],
  ['technical_impact', (r) => r.decision?.inputs.technical_impact.value],
  ['technical_impact_source', (r) => r.decision?.inputs.technical_impact.source],
  ['mission', (r) => r.decision?.inputs.mission],
  ['epss', (r) => r.epss?.score],
  ['epss_percentile', (r) => r.epss?.percentile],
  ['epss_date', (r) => r.epss?.date],
  ['decision_model_version', (r) => r.decision?.model_version],
  ['vektor_url', (r) => r.vektor_url],
];
const cell = (v) => {
  const s = v == null ? '' : String(v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const csv = [COLUMNS.map(([name]) => name).join(','), ...records.map((r) => COLUMNS.map(([, get]) => cell(get(r))).join(','))].join('\r\n') + '\r\n';

const atomic = async (path, text) => { await mkdir(dirname(path), { recursive: true }); await writeFile(`${path}.tmp`, text); await rename(`${path}.tmp`, path); };
await atomic(resolve(ROOT, 'data/kev.json'), JSON.stringify(doc, null, 1) + '\n');
await atomic(resolve(ROOT, 'data/kev.csv'), csv);

// README stats block: counts per decision and the latest KEV additions, each linked to its Vektor page.
const ORDER = ['act', 'attend', 'track_star', 'track'];
const tally = new Map();
for (const r of records) { const k = r.decision?.value ?? 'none'; tally.set(k, (tally.get(k) ?? 0) + 1); }
const labels = Object.fromEntries(records.filter((r) => r.decision).map((r) => [r.decision.value, r.decision.label]));
// README is prose: CISA's verbatim names can carry en/em dashes, shown there as a plain hyphen (data files stay verbatim).
const esc = (s) => String(s ?? '').replace(/[\u2013\u2014]/g, '-').replace(/\|/g, '\\|');
const latest = records.slice(0, 15);
const stats = [
  `Last build: ${generatedAt.slice(0, 10)}. KEV catalog ${kev.catalogVersion ?? 'unknown'}, ${records.length} entries.`,
  '',
  '| Decision | Entries |',
  '|---|---|',
  ...[...ORDER, 'none'].filter((k) => tally.has(k)).map((k) => `| ${k === 'none' ? 'No Vektor record yet' : `${labels[k]} (\`${k}\`)`} | ${tally.get(k)} |`),
  '',
  'Latest KEV additions:',
  '',
  '| CVE | Vendor | Product | Added to KEV | Decision | EPSS |',
  '|---|---|---|---|---|---|',
  ...latest.map((r) => `| [${r.cve_id}](${r.vektor_url}) | ${esc(r.kev.vendor_project)} | ${esc(r.kev.product)} | ${r.kev.date_added ?? ''} | ${r.decision?.label ?? ''} | ${r.epss ? r.epss.score.toFixed(4) : ''} |`),
].join('\n');
const readmePath = resolve(ROOT, 'README.md');
const readme = await readFile(readmePath, 'utf8');
const START = '<!-- stats:start -->', END = '<!-- stats:end -->';
const a = readme.indexOf(START), b = readme.indexOf(END);
if (a < 0 || b < a) throw new Error('README.md is missing the stats markers');
await atomic(readmePath, `${readme.slice(0, a + START.length)}\n${stats}\n${readme.slice(b)}`);

console.log(`KEV ${kev.catalogVersion}: ${records.length} entries, Vektor rows ${records.length - missing.length}, without record ${missing.length}, triage calls ${Math.ceil(ids.length / BATCH)}`);
