# Attribution

## CISA Known Exploited Vulnerabilities Catalog

KEV fields (`cve_id`, `kev_vendor_project`, `kev_product`, `kev_vulnerability_name`, `kev_date_added`, `kev_due_date`, `kev_known_ransomware_campaign_use`) come from the [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), feed URL `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

CISA distributes the KEV catalog under the [Creative Commons 0 1.0 License](https://github.com/cisagov/kev-data/blob/develop/LICENSE) (public domain). Use of this data does not imply endorsement by CISA or DHS. The CISA logo and DHS seal are not used here.

This file republishes only the KEV fields listed above. The KEV `shortDescription`, `requiredAction`, `notes` and `cwes` fields are not included; the `notes` field links to third-party sites whose content has its own terms.

## CISA Vulnrichment (SSVC values)

Where a CVE record carries CISA's own SSVC values (Automatable, Technical Impact) from [CISA Vulnrichment](https://github.com/cisagov/vulnrichment), Vektor uses them as decision inputs and names the source `CISA SSVC`. Vulnrichment is published under CC0 1.0.

## FIRST EPSS

EPSS scores (`epss`, `epss_percentile`, `epss_date`) are from the Exploit Prediction Scoring System (EPSS), maintained by the EPSS Special Interest Group at [FIRST](https://www.first.org/epss/), with daily scores produced by Empirical Security. FIRST publishes EPSS free of charge and [requests attribution](https://www.first.org/epss/faq) when EPSS data is used in publications or products.

Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., and Adjerid, I. Exploit Prediction Scoring System (EPSS). https://www.first.org/epss/

Scores reach this file through Vektor, which loads the daily EPSS snapshot. The score date is in `epss_date`.

## Vektor

The decision (`decision`, `decision_label`, `ssvc_table_result`, `sla_days`, `policy_floor`), its inputs and their source names, `decision_model_version` and `vektor_url` are computed by [Vektor](https://vektor.jvcr.se) and dedicated to the public domain under CC0 1.0 (see [LICENSE](LICENSE)). Attribution is welcome but not required. The rules are described on the [methodology page](https://vektor.jvcr.se/methodology).

CVSS vectors used to derive `automatable` and `technical_impact` are not republished here; only the derived value and the name of its source are.
