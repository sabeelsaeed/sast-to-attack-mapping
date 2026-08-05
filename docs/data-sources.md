# Data sources & versioning

Pin every release in data/VERSIONS.txt. Output metadata must echo these.

| catalogue | source | access | licence |
|---|---|---|---|
| ATT&CK (STIX) | MITRE CTI repo | mitreattack-python | permissive, attribution |
| CWE | cwe.mitre.org XML | local parse | permissive, attribution |
| CAPEC | capec.mitre.org XML | local parse | permissive, attribution |
| Mappings Explorer | CTID reference data | CSV/JSON | permissive, attribution |
| Sigma | SigmaHQ ruleset | git clone | DRL/permissive |

Refresh: `python -m pipeline.data.refresh_cti` — writes new versions to
data/VERSIONS.txt. Never refresh mid-experiment; a version change invalidates
prior coverage numbers.
