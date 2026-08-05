"""Read the pinned CWE/CAPEC/ATT&CK catalogues into typed structures.

IDs are canonicalised to CWE-89 / CAPEC-66 / T1190. ATT&CK is read via
mitreattack-python; CWE/CAPEC XML via lxml. Gaps (a CAPEC with no ATT&CK
mapping) surface as empty lists, not errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree
from mitreattack.stix20 import MitreAttackData

from pipeline.data.refresh_cti import DATA, read_pins


@dataclass(frozen=True)
class CweEntry:
    """A CWE weakness and the CAPEC attack patterns it relates to (hop 1)."""

    cwe_id: str  # canonical "CWE-<int>"
    name: str
    related_capec_ids: list[str] = field(default_factory=list)  # "CAPEC-<int>"
    description: str = ""  # Description + Extended_Description, for the NLP query


@dataclass(frozen=True)
class CapecEntry:
    """A CAPEC attack pattern and its ATT&CK taxonomy mappings (hop 2)."""

    capec_id: str  # canonical "CAPEC-<int>"
    name: str
    technique_ids: list[str] = field(default_factory=list)  # "T<id>"; empty = gap
    child_of: list[str] = field(default_factory=list)  # parent "CAPEC-<int>"


@dataclass(frozen=True)
class TechniqueInfo:
    """Minimal ATT&CK technique metadata resolved from the STIX bundle."""

    technique_id: str  # "T<id>"
    name: str
    data_sources: list[str] = field(default_factory=list)  # refined by enrich (O6)
    description: str = ""  # technique prose, for the NLP corpus


def _ns(tree: etree._ElementTree) -> dict[str, str]:
    """Return an ``{"c": <default-namespace-uri>}`` map for XPath queries."""
    return {"c": tree.getroot().nsmap[None]}


def load_cwe(path: Path) -> dict[str, CweEntry]:
    """Parse the CWE catalogue XML, keyed by canonical ``CWE-<int>``."""
    tree = etree.parse(str(path))
    ns = _ns(tree)
    entries: dict[str, CweEntry] = {}
    for w in tree.xpath("//c:Weakness", namespaces=ns):
        cwe_id = f"CWE-{w.get('ID')}"
        capecs = [
            f"CAPEC-{cid}"
            for cid in w.xpath(".//c:Related_Attack_Pattern/@CAPEC_ID", namespaces=ns)
        ]
        desc = w.xpath("normalize-space(string(./c:Description))", namespaces=ns)
        ext = w.xpath("normalize-space(string(./c:Extended_Description))", namespaces=ns)
        description = f"{desc} {ext}".strip()
        entries[cwe_id] = CweEntry(cwe_id, w.get("Name", ""), capecs, description)
    return entries


def load_capec(path: Path) -> dict[str, CapecEntry]:
    """Parse the CAPEC catalogue XML, keyed by canonical ``CAPEC-<int>``."""
    tree = etree.parse(str(path))
    ns = _ns(tree)
    entries: dict[str, CapecEntry] = {}
    for p in tree.xpath("//c:Attack_Pattern", namespaces=ns):
        capec_id = f"CAPEC-{p.get('ID')}"
        techniques = [
            f"T{eid}"
            for eid in p.xpath(
                './/c:Taxonomy_Mapping[@Taxonomy_Name="ATTACK"]/c:Entry_ID/text()',
                namespaces=ns,
            )
        ]
        parents = [
            f"CAPEC-{pid}"
            for pid in p.xpath(
                './/c:Related_Attack_Pattern[@Nature="ChildOf"]/@CAPEC_ID',
                namespaces=ns,
            )
        ]
        entries[capec_id] = CapecEntry(capec_id, p.get("Name", ""), techniques, parents)
    return entries


class AttackData:
    """Thin wrapper over ``MitreAttackData`` for technique resolution."""

    def __init__(self, path: Path) -> None:
        self._data = MitreAttackData(str(path))

    def technique(self, technique_id: str) -> TechniqueInfo | None:
        """Resolve an ATT&CK technique id (e.g. ``T1190``) to its metadata."""
        obj = self._data.get_object_by_attack_id(technique_id, "attack-pattern")
        if obj is None:
            return None
        sources = list(getattr(obj, "x_mitre_data_sources", []) or [])
        return TechniqueInfo(
            technique_id, obj.name, sources, getattr(obj, "description", "") or ""
        )

    def techniques(self) -> list[TechniqueInfo]:
        """Enumerate all (non-revoked, non-deprecated) enterprise techniques."""
        out: list[TechniqueInfo] = []
        for obj in self._data.get_techniques(remove_revoked_deprecated=True):
            technique_id = None
            for ref in getattr(obj, "external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            if not technique_id:
                continue
            sources = list(getattr(obj, "x_mitre_data_sources", []) or [])
            out.append(
                TechniqueInfo(
                    technique_id,
                    getattr(obj, "name", ""),
                    sources,
                    getattr(obj, "description", "") or "",
                )
            )
        return out

    def data_source_index(self) -> dict[str, list[str]]:
        """Map technique id -> data-component names that detect it.

        ATT&CK v19 moved detections behind detection-strategy/analytic objects,
        so traverse: technique <-detects- strategy -> analytic -> data-component.
        """
        from stix2 import Filter

        # src.query returns dict-like STIX; use mapping access (works for both).
        src = self._data.src
        dc_name = {
            o["id"]: o.get("name", "")
            for o in src.query([Filter("type", "=", "x-mitre-data-component")])
        }
        analytic_dcs: dict[str, set[str]] = {}
        for a in src.query([Filter("type", "=", "x-mitre-analytic")]):
            names = {
                dc_name[ref["x_mitre_data_component_ref"]]
                for ref in a.get("x_mitre_log_source_references", []) or []
                if ref.get("x_mitre_data_component_ref") in dc_name
                and dc_name[ref["x_mitre_data_component_ref"]]
            }
            analytic_dcs[a["id"]] = names
        strategy_dcs: dict[str, set[str]] = {}
        for s in src.query([Filter("type", "=", "x-mitre-detection-strategy")]):
            names = set()
            for aid in s.get("x_mitre_analytic_refs", []) or []:
                names |= analytic_dcs.get(aid, set())
            strategy_dcs[s["id"]] = names

        by_technique_stix: dict[str, set[str]] = {}
        for r in src.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "detects"),
            ]
        ):
            if r["source_ref"] in strategy_dcs:
                by_technique_stix.setdefault(r["target_ref"], set()).update(
                    strategy_dcs[r["source_ref"]]
                )

        index: dict[str, list[str]] = {}
        for stix_id, names in by_technique_stix.items():
            obj = src.get(stix_id)
            if obj is None:
                continue
            for ref in obj.get("external_references", []) or []:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    index[ref["external_id"]] = sorted(names)
                    break
        return index


def load_attack(path: Path) -> AttackData:
    """Load the ATT&CK Enterprise STIX bundle."""
    return AttackData(path)


@dataclass
class Catalogues:
    """All three catalogues, loaded together — the bridge's single data handle."""

    cwe: dict[str, CweEntry]
    capec: dict[str, CapecEntry]
    attack: AttackData

    @classmethod
    def from_versions(cls) -> Catalogues:
        """Load the exact files pinned in ``data/VERSIONS.txt``."""
        pins = read_pins()
        cwe_path = DATA / "cwe" / f"cwec_v{pins['cwe_version']}.xml"
        capec_path = DATA / "capec" / f"capec_v{pins['capec_version']}.xml"
        attack_name = f"enterprise-attack-{pins['attack_version']}.json"
        attack_path = DATA / "attack" / attack_name
        return cls(
            cwe=load_cwe(cwe_path),
            capec=load_capec(capec_path),
            attack=load_attack(attack_path),
        )
