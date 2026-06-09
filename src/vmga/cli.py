"""Command-line helpers for VMGA."""

from __future__ import annotations

import argparse
import json
import sys

from .evidence import load_jsonl_events, verify_events


def verify_evidence_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify VMGA JSONL evidence")
    parser.add_argument("path", help="Path to VMGA evidence JSONL")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    args = parser.parse_args(argv)

    try:
        events = load_jsonl_events(args.path)
        result = verify_events(events)
    except Exception as exc:
        result = {"valid": False, "errors": [str(exc)], "warnings": []}
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"VMGA evidence invalid: {exc}", file=sys.stderr)
        return 2

    payload = result.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2))
    elif result.valid:
        print("VMGA evidence valid")
    else:
        print("VMGA evidence invalid", file=sys.stderr)
        for error in result.errors:
            print(f"- {error}", file=sys.stderr)
    return 0 if result.valid else 2


if __name__ == "__main__":
    raise SystemExit(verify_evidence_main())
