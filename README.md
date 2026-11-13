# CISA KEV with SSVC decisions and EPSS

A daily machine-readable list of every entry in the CISA Known Exploited Vulnerabilities (KEV) catalog. Each entry has its KEV dates, the remediation decision computed by [Vektor](https://vektor.jvcr.se), the inputs behind that decision with the source of each input, the FIRST EPSS score, and a link to the CVE page on Vektor.

- [`data/kev.csv`](data/kev.csv): one row per KEV entry.
- [`data/kev.json`](data/kev.json): the same data as nested JSON, plus build metadata.

A GitHub Actions workflow rebuilds both files once a day and commits them when anything changed.

## Current snapshot

<!-- stats:start -->
Last build: 2026-11-13. KEV catalog 2026.11.10, 1779 entries.

| Decision | Entries |
|---|---|
| Fix now (`act`) | 698 |
| Fix this sprint (`attend`) | 1081 |

Latest KEV additions:

| CVE | Vendor | Product | Added to KEV | Decision | EPSS |
|---|---|---|---|---|---|
| [CVE-2026-111560](https://vektor.jvcr.se/cve/CVE-2026-111560) | Barracuda Networks | Multiple Products | 2026-11-10 | Fix this sprint | 0.0620 |
| [CVE-2026-111793](https://vektor.jvcr.se/cve/CVE-2026-111793) | Openwave Messaging Limited | Webtop Media Transcoder | 2026-11-10 | Fix this sprint | 0.0064 |
| [CVE-2026-116606](https://vektor.jvcr.se/cve/CVE-2026-116606) | Barracuda Networks | Barracuda Email Security Gateway (ESG) | 2026-11-10 | Fix now | 0.0893 |
| [CVE-2026-124194](https://vektor.jvcr.se/cve/CVE-2026-124194) | Microsoft | Office | 2026-11-10 | Fix this sprint | 0.0162 |
| [CVE-2026-125350](https://vektor.jvcr.se/cve/CVE-2026-125350) | Google | Chromium | 2026-11-10 | Fix this sprint | 0.0096 |
| [CVE-2026-20320](https://vektor.jvcr.se/cve/CVE-2026-20320) | Cisco | BroadWorks | 2026-11-10 | Fix this sprint | 0.0082 |
| [CVE-2026-102895](https://vektor.jvcr.se/cve/CVE-2026-102895) | GPUStack | GPUStack | 2026-11-09 | Fix now | 0.0052 |
| [CVE-2026-116779](https://vektor.jvcr.se/cve/CVE-2026-116779) | SignalWire | FreeSwitch | 2026-11-09 | Fix now | 0.0247 |
| [CVE-2026-123158](https://vektor.jvcr.se/cve/CVE-2026-123158) | OpenBSD | OpenSSH | 2026-11-09 | Fix this sprint | 0.1890 |
| [CVE-2026-123218](https://vektor.jvcr.se/cve/CVE-2026-123218) | IBM | Aspera Faspex | 2026-11-09 | Fix now | 0.0053 |
| [CVE-2026-19868](https://vektor.jvcr.se/cve/CVE-2026-19868) | SonicWall | SonicOS SSLVPN | 2026-11-06 | Fix this sprint | 0.0053 |
| [CVE-2024-27834](https://vektor.jvcr.se/cve/CVE-2024-27834) | Apple | Multiple Products | 2026-11-04 | Fix this sprint | 0.0150 |
| [CVE-2026-119977](https://vektor.jvcr.se/cve/CVE-2026-119977) | WordPress | WordPress Core | 2026-11-03 | Fix now | 0.0120 |
| [CVE-2026-111357](https://vektor.jvcr.se/cve/CVE-2026-111357) | Ivanti | Connect Secure | 2026-10-30 | Fix this sprint | 0.0053 |
| [CVE-2026-118527](https://vektor.jvcr.se/cve/CVE-2026-118527) | Ivanti | Connect Secure | 2026-10-30 | Fix this sprint | 0.0082 |
<!-- stats:end -->

## Fields

| CSV column | JSON path | Meaning | Source |
|---|---|---|---|
| `cve_id` | `cve_id` | CVE identifier | CISA KEV |
| `kev_vendor_project` | `kev.vendor_project` | Vendor as named in KEV | CISA KEV |
| `kev_product` | `kev.product` | Product as named in KEV | CISA KEV |
| `kev_vulnerability_name` | `kev.vulnerability_name` | KEV entry title | CISA KEV |
| `kev_date_added` | `kev.date_added` | Date the CVE was added to KEV | CISA KEV |
| `kev_due_date` | `kev.due_date` | Remediation due date for US federal agencies (BOD 22-01) | CISA KEV |
| `kev_known_ransomware_campaign_use` | `kev.known_ransomware_campaign_use` | `Known` or `Unknown` | CISA KEV |
| `decision` | `decision.value` | `act`, `attend`, `track_star` or `track` | Vektor |
| `decision_label` | `decision.label` | Fix now, Fix this sprint, Next patch cycle, Routine | Vektor |
| `ssvc_table_result` | `decision.ssvc_table_result` | Result of the CISA SSVC table before the Vektor policy floor | Vektor |
| `sla_days` | `decision.sla_days` | Suggested fix window in days: 3, 14, 30 or 90 | Vektor |
| `policy_floor` | `decision.policy_floor` | Empty, `active_exploitation` or `ransomware_network` (see below) | Vektor |
| `exploitation` | `decision.inputs.exploitation.value` | `active`, `poc` or `none` | Vektor, from the named source |
| `exploitation_source` | `decision.inputs.exploitation.source` | Where the exploitation value came from | Vektor |
| `automatable` | `decision.inputs.automatable.value` | `yes` or `no` | Vektor, from the named source |
| `automatable_source` | `decision.inputs.automatable.source` | `CISA SSVC`, `CVSS vector` or `assumed (no CVSS vector)` | Vektor |
| `technical_impact` | `decision.inputs.technical_impact.value` | `total` or `partial` | Vektor, from the named source |
| `technical_impact_source` | `decision.inputs.technical_impact.source` | `CISA SSVC`, `CVSS vector` or `assumed (no CVSS vector)` | Vektor |
| `mission` | `decision.inputs.mission` | Always `medium` in this file (no asset context) | Vektor |
| `epss` | `epss.score` | Probability of exploitation activity in the next 30 days, 0 to 1 | FIRST EPSS |
| `epss_percentile` | `epss.percentile` | Share of scored CVEs with the same or a lower score | FIRST EPSS |
| `epss_date` | `epss.date` | Date of the EPSS score | FIRST EPSS |
| `decision_model_version` | `decision.model_version` | Version of Vektor's decision rules | Vektor |
| `vektor_url` | `vektor_url` | CVE page on Vektor with the full explanation | Vektor |

Rows are sorted by `kev_date_added`, newest first, then by CVE id. Decision and EPSS columns are empty when Vektor has no record for a CVE yet; `kev.json` lists those ids in `without_vektor_record`.

## How the decision is computed

The decision follows the CISA SSVC coordinator decision tree (SSVC guide, Table 9) with one Vektor policy overlay. The full rules are on the [methodology page](https://vektor.jvcr.se/methodology).

Inputs, each taken from the strongest available source:

- **Exploitation.** A KEV entry is `active` by definition, so every row here has exploitation `active` from `CISA KEV`.
- **Automatable.** CISA's own SSVC value from the CVE record (CISA Vulnrichment) when present. Otherwise derived from the CVSS vector: `yes` when the vector has network attack vector, no privileges required and no user interaction (`AV:N`, `PR:N`, `UI:N`). Without a vector it is assumed `no`.
- **Technical impact.** CISA's SSVC value when present. Otherwise `total` when the CVSS vector has high confidentiality and high integrity impact (`C:H` and `I:H`, or `VC:H` and `VI:H` for CVSS 4.0). Without a vector it is assumed `partial`.
- **Mission prevalence.** Set to `medium` for everyone. On Vektor, a watchlist marked as internet-facing or critical uses `high`, which can raise the decision.

The table result is then adjusted by Vektor policy:

- Active exploitation lifts the decision to at least `attend` (Fix this sprint). This is `policy_floor = active_exploitation`.
- A KEV entry with `Known` ransomware use on a network-reachable flaw (`AV:N`) is lifted to `act` (Fix now). This is `policy_floor = ransomware_network`.

`ssvc_table_result` shows the unadjusted SSVC table result, so the effect of the floor is visible. The fix windows follow NIST SP 800-40r4 emergency versus routine maintenance. The KEV due date is a federal deadline and is published separately.

The CVSS vectors used to derive `automatable` and `technical_impact` are not included in this file; only the derived value and the name of its source are. The CVE page on Vektor shows the vector and its origin.

## Sources and licences

| Data | Source | Terms |
|---|---|---|
| KEV fields | [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CC0 1.0 (public domain) |
| CISA SSVC values used as inputs | [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) | CC0 1.0 |
| EPSS score, percentile, date | [FIRST EPSS](https://www.first.org/epss/) | Free to use; FIRST requests attribution |
| Decision, inputs, source names, links | [Vektor](https://vektor.jvcr.se) | CC0 1.0 |

See [ATTRIBUTION.md](ATTRIBUTION.md) and [LICENSE](LICENSE). This project is not affiliated with or endorsed by CISA, DHS or FIRST.

## Rebuilding locally

```sh
node scripts/build.mjs
```

Node 20 or newer, no dependencies, no credentials. The script downloads the KEV catalog from CISA and asks Vektor's public [`POST /api/triage`](https://vektor.jvcr.se/api) endpoint for the decision and EPSS data, 500 CVE ids per request.

## Related on Vektor

- [Vektor home](https://vektor.jvcr.se): CVE search with exploit evidence and decisions
- [Methodology](https://vektor.jvcr.se/methodology): how decisions and priorities are computed
- [KEV RSS feed](https://vektor.jvcr.se/feed/kev.rss): new KEV entries with their decision
- [API documentation](https://vektor.jvcr.se/api)
