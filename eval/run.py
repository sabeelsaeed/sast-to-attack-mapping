"""Evaluation entry point (O7): python -m eval.run.

Modes:
  --pred mappings.json              coverage + Sigma/data-source yields
  --pred ... --sample N             write a plausibility sheet to label
  --pred ... --labels sheet.csv     plausibility from a filled sheet
  --agreement --input findings/     authoritative-vs-NLP agreement (RQ2)

Plausibility needs human labels (no CWE->ATT&CK gold set exists).
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from eval.metrics import (
    coverage,
    data_source_yield,
    method_agreement,
    plausibility,
    plausibility_sample,
    sigma_yield,
)


def evaluate_predictions(
    pred_path: Path, out_dir: Path, sample: int, labels: Path | None
) -> dict:
    """Compute coverage + detection yields (+ optional plausibility) from output."""
    report = json.loads(pred_path.read_text())
    mappings = report["mappings"]
    n_findings = report["counts"]["findings"]

    result: dict = {
        "coverage": coverage(mappings, n_findings),
        "sigma_yield": sigma_yield(mappings),
        "data_source_yield": data_source_yield(mappings),
    }
    if labels is not None:
        with labels.open() as f:
            result["plausibility"] = plausibility(list(csv.DictReader(f)))

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "eval.json").write_text(json.dumps(result, indent=2, sort_keys=True))

    if sample:
        rows = plausibility_sample(mappings, sample)
        sample_path = out_dir / "plausibility_sample.csv"
        with sample_path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"wrote {len(rows)} rows to label -> {sample_path}")

    cov = result["coverage"]
    print(
        f"coverage: authoritative {cov['authoritative']:.1%} | "
        f"combined {cov['combined']:.1%}  (n={cov['n_findings']})\n"
        f"detection: Sigma yield {result['sigma_yield']:.1%} | "
        f"data-source yield {result['data_source_yield']:.1%}"
    )
    if "plausibility" in result:
        p = result["plausibility"]
        print(f"plausibility: {p['plausible_rate']:.1%} (n={p['n_labelled']})")
    return result


def evaluate_agreement(input_dir: Path, out_dir: Path) -> dict:
    """Run both bridge methods on all findings and compute agreement (RQ2)."""
    from pipeline.bridge.authoritative import map_finding
    from pipeline.bridge.nlp import NlpMapper
    from pipeline.data.loaders import Catalogues
    from pipeline.normalize import normalize_findings

    findings = normalize_findings(sorted(input_dir.glob("*.json")))
    catalogues = Catalogues.from_versions()
    mapper = NlpMapper(catalogues)

    auth_by: dict[str, set[str]] = {}
    nlp_by: dict[str, set[str]] = {}
    for finding in findings:
        auth_by[finding.finding_id] = {
            t for m in map_finding(finding, catalogues) for t in m.technique_ids
        }
        nlp_by[finding.finding_id] = {
            t for m in mapper.map_finding(finding) for t in m.technique_ids
        }

    result = method_agreement(auth_by, nlp_by)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "agreement.json").write_text(
        json.dumps(result, indent=2, sort_keys=True)
    )
    print(
        f"method agreement (RQ2): mean Jaccard {result['mean_jaccard']:.3f} | "
        f">=1 shared technique {result['any_overlap_rate']:.1%} "
        f"(over {result['comparable_findings']} findings both mapped)"
    )
    return result


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(prog="eval.run")
    parser.add_argument("--pred", type=Path, help="predicted mappings.json")
    parser.add_argument("--out", type=Path, default=Path("out"), help="output dir")
    parser.add_argument(
        "--sample", type=int, default=0, help="plausibility sample size"
    )
    parser.add_argument("--labels", type=Path, help="filled plausibility sheet (csv)")
    parser.add_argument("--agreement", action="store_true", help="RQ2 agreement mode")
    parser.add_argument("--input", type=Path, help="findings dir (for --agreement)")
    args = parser.parse_args(argv)

    if args.agreement:
        if not args.input:
            parser.error("--agreement requires --input")
        evaluate_agreement(args.input, args.out)
    elif args.pred:
        evaluate_predictions(args.pred, args.out, args.sample, args.labels)
    else:
        parser.error("provide --pred or --agreement")


if __name__ == "__main__":
    main()
