from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json_report(report: dict[str, Any], output_file: str) -> None:
    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")


def _pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "0.0%"
    return f"{(100.0 * numerator / denominator):.1f}%"


def print_summary(report: dict[str, Any], output_file: str) -> None:
    query = report["query"]
    coverage = report["coverage"]
    errors = report["errors"]
    matches = report["matches"]

    print("ENI scan summary")
    print(f"query mode:         {query['mode']}")
    print(f"query value:        {query['value']}")
    print(f"match mode:         {query['match_mode']}")
    print(f"target accounts:    {coverage['target_accounts']}")
    print(f"scanned accounts:   {coverage['scanned_accounts']}")
    print(
        "target acct-regions:"
        f" {coverage['target_account_regions']}"
    )
    print(
        "scanned acct-regions:"
        f" {coverage['scanned_account_regions']}"
        f" ({_pct(coverage['scanned_account_regions'], coverage['target_account_regions'])})"
    )
    print(f"skipped regions:    {coverage['skipped_account_regions']}")
    print(f"matches:            {len(matches)}")
    print(f"errors:             {len(errors)}")
    print(f"status:             {report['status']}")
    print(f"output file:        {output_file}")
