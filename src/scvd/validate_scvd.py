#!/usr/bin/env python3
import argparse, json, sys
from jsonschema import Draft7Validator
from pathlib import Path

def main():
    ap = argparse.ArgumentParser(description="Validate SCVD JSONL against schema v0.1")
    ap.add_argument("jsonl", help="Path to findings.jsonl")
    ap.add_argument("--schema", default="schema/scvd_finding_v0_1.json", help="Path to JSON Schema")
    args = ap.parse_args()

    schema = json.loads(Path(args.schema).read_text())
    validator = Draft7Validator(schema)

    errors = 0
    with Path(args.jsonl).open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                print(f"[line {i}] invalid JSON: {e}", file=sys.stderr)
                errors += 1
                continue

            for err in validator.iter_errors(obj):
                print(f"[line {i}] {err.message} at {'/'.join(map(str, err.path))}", file=sys.stderr)
                errors += 1

    if errors:
        print(f"❌ validation failed with {errors} error(s)", file=sys.stderr)
        sys.exit(1)
    print("✅ all good")

if __name__ == "__main__":
    main()
