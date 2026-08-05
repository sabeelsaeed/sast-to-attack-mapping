"""Pipeline orchestrator: normalize -> bridge -> optional nlp -> optional enrich.

Writes out/mappings.json (mappings + unmapped queue + version stamp).
Deterministic: sorted, no wall-clock.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path

from pipeline.bridge.authoritative import map_finding
from pipeline.data.loaders import Catalogues
from pipeline.data.refresh_cti import DATA, read_pins
from pipeline.schema import Finding, Mapping, RunMeta


def _build_run_meta() -> RunMeta:
    """Stamp the run with the pinned versions from ``data/VERSIONS.txt``."""
    pins = read_pins()
    return RunMeta(
        attack_version=pins.get("attack_version", ""),
        cwe_version=pins.get("cwe_version", ""),
        capec_version=pins.get("capec_version", ""),
        mappings_explorer_commit=pins.get("mappings_explorer_commit", ""),
        sigma_release=pins.get("sigma_release", ""),
        tool_versions={
            "bandit": pins.get("bandit", ""),
            "semgrep": pins.get("semgrep", ""),
        },
    )


def _build_report(mappings: list[Mapping], unmapped: list[str], n: int) -> dict:
    """Assemble the deterministic output document."""
    mapped_ids = {m.finding_id for m in mappings}
    coverage = round(len(mapped_ids) / n, 4) if n else 0.0
    detected = sum(
        1 for m in mappings if m.detection.data_sources or m.detection.sigma_rule_ids
    )
    detection_yield = round(detected / len(mappings), 4) if mappings else 0.0
    return {
        "run_meta": dataclasses.asdict(_build_run_meta()),
        "counts": {
            "findings": n,
            "findings_mapped": len(mapped_ids),
            "findings_unmapped": len(unmapped),
            "mappings": len(mappings),
            "mappings_with_detection": detected,
        },
        "coverage": coverage,
        "detection_yield": detection_yield,
        "mappings": [dataclasses.asdict(m) for m in mappings],
        "unmapped": sorted(unmapped),
    }


def run(
    input_dir: Path, out_dir: Path, use_nlp: bool = False, use_enrich: bool = False
) -> dict:
    """Run the pipeline; --nlp adds the fallback, --enrich adds detection."""
    from pipeline.normalize import normalize_findings

    findings = normalize_findings(sorted(input_dir.glob("*.json")))
    catalogues = Catalogues.from_versions()

    mappings: list[Mapping] = []
    unmapped_findings: list[Finding] = []
    for finding in findings:
        found = map_finding(finding, catalogues)
        if found:
            mappings.extend(found)
        else:
            unmapped_findings.append(finding)

    if use_nlp and unmapped_findings:
        from pipeline.bridge.nlp import NlpMapper

        mapper = NlpMapper(catalogues)
        still_unmapped: list[Finding] = []
        for finding in unmapped_findings:
            nlp_mappings = mapper.map_finding(finding)
            if nlp_mappings:
                mappings.extend(nlp_mappings)
            else:
                still_unmapped.append(finding)
        unmapped_findings = still_unmapped

    if use_enrich and mappings:
        from pipeline.enrich import SigmaIndex, enrich

        sigma_index = SigmaIndex(DATA / "sigma" / "rules")
        ds_index = catalogues.attack.data_source_index()
        mappings = [enrich(m, sigma_index, ds_index) for m in mappings]

    unmapped = [f.finding_id for f in unmapped_findings]
    report = _build_report(mappings, unmapped, len(findings))

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "mappings.json").write_text(json.dumps(report, indent=2, sort_keys=True))

    c = report["counts"]
    line = (
        f"{c['findings']} findings, {c['findings_mapped']} mapped "
        f"({report['coverage']:.1%}), {c['findings_unmapped']} unmapped"
    )
    if use_enrich:
        line += f", detection yield {report['detection_yield']:.1%}"
    print(f"{line} -> {out_dir / 'mappings.json'}")
    return report


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(prog="pipeline.run")
    parser.add_argument("--input", type=Path, required=True, help="dir of scanner JSON")
    parser.add_argument("--out", type=Path, required=True, help="output dir")
    parser.add_argument(
        "--nlp", action="store_true", help="run NLP fallback on unmapped findings"
    )
    parser.add_argument(
        "--enrich", action="store_true", help="attach Sigma rules + ATT&CK data sources"
    )
    args = parser.parse_args(argv)
    run(args.input, args.out, use_nlp=args.nlp, use_enrich=args.enrich)


if __name__ == "__main__":
    main()
