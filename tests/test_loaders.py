"""Loader tests against the real pinned catalogues.

Includes the confirmed gap: CAPEC-66 has no ATT&CK taxonomy mapping.
"""

from __future__ import annotations

from pipeline.data.loaders import Catalogues, load_attack, load_capec, load_cwe
from pipeline.data.refresh_cti import DATA

CWE_XML = DATA / "cwe" / "cwec_v4.20.xml"
CAPEC_XML = DATA / "capec" / "capec_v3.9.xml"
ATTACK_JSON = DATA / "attack" / "enterprise-attack-19.1.json"


def test_cwe_hop1_present() -> None:
    cwe = load_cwe(CWE_XML)
    assert "CAPEC-66" in cwe["CWE-89"].related_capec_ids


def test_capec66_attack_gap_is_honest() -> None:
    # CAPEC-66 carries only WASC/OWASP taxonomy mappings, no ATT&CK. The loader
    # must surface that gap as an empty list, not fabricate a technique.
    capec = load_capec(CAPEC_XML)
    assert capec["CAPEC-66"].technique_ids == []


def test_capec_technique_ids_are_normalised() -> None:
    capec = load_capec(CAPEC_XML)
    techs = [t for e in capec.values() for t in e.technique_ids]
    assert techs, "expected some CAPECs to carry ATT&CK mappings"
    assert all(t.startswith("T") for t in techs)


def test_attack_resolves_technique() -> None:
    attack = load_attack(ATTACK_JSON)
    info = attack.technique("T1190")
    assert info is not None
    assert info.name == "Exploit Public-Facing Application"


def test_catalogues_from_versions_loads_all() -> None:
    cats = Catalogues.from_versions()
    assert "CWE-89" in cats.cwe
    assert "CAPEC-66" in cats.capec
    assert cats.attack.technique("T1190") is not None
