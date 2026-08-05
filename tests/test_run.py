"""Orchestration tests — run the pipeline on fixtures into a tmp dir."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.run import run

FIXTURES = Path(__file__).parent / "fixtures"


def _seed_input(tmp: Path) -> Path:
    """Copy the fixture scanner JSON into an input dir the pipeline can glob."""
    inp = tmp / "findings"
    inp.mkdir()
    for name in ("bandit_sample.json", "semgrep_sample.json"):
        (inp / name).write_text((FIXTURES / name).read_text())
    return inp


def test_run_writes_mappings_and_maps_cwe798(tmp_path: Path) -> None:
    report = run(_seed_input(tmp_path), tmp_path / "out")
    assert (tmp_path / "out" / "mappings.json").exists()
    techniques = {t for m in report["mappings"] for t in m["technique_ids"]}
    assert {"T1552.001", "T1078.001"} <= techniques


def test_gaps_recorded_as_unmapped(tmp_path: Path) -> None:
    report = run(_seed_input(tmp_path), tmp_path / "out")
    # CWE-259 (Bandit B105), CWE-89 (both tools) complete no authoritative chain.
    assert report["counts"]["findings_unmapped"] >= 3
    assert report["coverage"] < 1.0


def test_run_meta_echoes_versions(tmp_path: Path) -> None:
    report = run(_seed_input(tmp_path), tmp_path / "out")
    meta = report["run_meta"]
    assert meta["attack_version"] == "19.1"
    assert meta["cwe_version"] == "4.20"
    assert meta["tool_versions"]["bandit"] == "1.9.4"


def test_output_is_deterministic(tmp_path: Path) -> None:
    inp = _seed_input(tmp_path)
    run(inp, tmp_path / "out1")
    run(inp, tmp_path / "out2")
    a = (tmp_path / "out1" / "mappings.json").read_bytes()
    b = (tmp_path / "out2" / "mappings.json").read_bytes()
    assert a == b


def test_report_is_json_serializable(tmp_path: Path) -> None:
    report = run(_seed_input(tmp_path), tmp_path / "out")
    json.dumps(report)  # must not raise
