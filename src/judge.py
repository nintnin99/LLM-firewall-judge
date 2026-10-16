"""Run the M5 test file through the hybrid judge and sanitizer."""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from logic import pipeline  # noqa: E402


def main():
    source = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "tests" / "m5_cases.csv")
    failed = 0
    total = 0
    with source.open(encoding="utf-8", newline="") as handle:
        for case in csv.DictReader(handle):
            total += 1
            decision = pipeline(
                {
                    "case_id": case["case_id"],
                    "text": case["text"],
                    "segments": json.loads(case["segments_json"]),
                    "findings": json.loads(case["findings_json"]),
                    "matches": json.loads(case["rag_json"]),
                }
            )
            ok = decision["verdict"] == case["expected_verdict"]
            cleaned = case.get("expected_cleaned") or ""
            if cleaned and decision.get("cleaned_text") != cleaned:
                ok = False
            if not ok:
                failed += 1
                print(f"{case['case_id']} got {decision['verdict']} expected {case['expected_verdict']} {decision['justification']}")
            else:
                print(f"{case['case_id']} {decision['verdict']}")
    print(f"\n{total - failed}/{total} matched")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
