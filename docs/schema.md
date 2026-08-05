# Schemas — the pipeline contract

## Common finding (output of normalize)
| field | type | notes |
|---|---|---|
| finding_id | str | stable hash of tool+file+line+rule |
| tool | str | "bandit" \| "semgrep" |
| file | str | relative path in targets/ |
| line | int | |
| rule_id | str | e.g. B608, python.lang.security.* |
| cwe_ids | list[str] | canonical "CWE-<int>"; may be empty |
| severity | str | tool-native |
| confidence | str | tool-native |
| message | str | |
| raw | dict | original tool record, preserved |

## Mapping record (output of bridge + enrich)
| field | type | notes |
|---|---|---|
| finding_id | str | FK to finding |
| cwe | str | source CWE for this mapping |
| capec_ids | list[str] | chain hop (empty if NLP path) |
| technique_ids | list[str] | ATT&CK technique(s) |
| method | str | "authoritative" \| "nlp" |
| chain_evidence | dict | actual IDs/links traversed |
| confidence | str | high \| medium \| low |
| detection | dict | { data_sources[], sigma_rule_ids[] } |

## Run metadata (provenance stamp, written alongside output)
Echoes `data/VERSIONS.txt` so a run is reproducible. See `docs/data-sources.md`.
| field | type | notes |
|---|---|---|
| attack_version | str | pinned ATT&CK release |
| cwe_version | str | pinned CWE version |
| capec_version | str | pinned CAPEC version |
| mappings_explorer_commit | str | CTID reference commit SHA |
| sigma_release | str | pinned SigmaHQ release |
| tool_versions | dict | { bandit, semgrep, ... } |
