"""Compare benchmark artifacts, ignoring only pass durations and output-directory prefixes.

Usage: python corpus/compare-performance.py BEFORE AFTER
Pass directories containing the manifest subdirectories (e.g. benchmark/1).
"""

import json
import sys
from pathlib import Path


def normalized(path, root):
    absolute = root.resolve()
    prefixes = (str(absolute), absolute.as_posix())
    if str(root) != ".":
        prefixes += (str(root), root.as_posix())

    def visit(value):
        if isinstance(value, dict):
            return {key: visit(item) for key, item in value.items()}
        if isinstance(value, list):
            return [visit(item) for item in value]
        if isinstance(value, str):
            for prefix in prefixes:
                value = value.replace(prefix, "<output>")
            return value
        return value

    content = path.read_text(encoding="utf-8-sig")
    parsed = json.loads(content) if path.suffix == ".json" else content
    if path.name.endswith(".analysis.json"):
        for result in parsed.get("Passes", []):
            result.pop("Duration", None)
    return visit(parsed)


def main():
    before, after = map(Path, sys.argv[1:])
    # Analysis covers recovery metrics, evidence, blockers, validation and payload hashes;
    # outcomes add pinned corpus expectations, oracle comparisons and cleaned output hashes.
    patterns = ("corpus.outcomes.json", "*.analysis.json", "*.changes.json", "*.blockers.json",
                "*.lifted.il", "*.vmprogram.txt")
    files = lambda root: {path.relative_to(root) for pattern in patterns for path in root.rglob(pattern)}
    left, right = files(before), files(after)
    differences = []
    for path in sorted(left ^ right):
        differences.append(f"Missing counterpart: {path}")
    for path in sorted(left & right):
        if normalized(before / path, before) != normalized(after / path, after):
            differences.append(f"Different: {path}")
    if not left or not right:
        differences.append("No benchmark reports found")
    for difference in differences:
        print(difference)
    print(f"Compared {len(left & right)} reports/listings; {len(differences)} differences")
    return bool(differences)


if __name__ == "__main__":
    sys.exit(main())
