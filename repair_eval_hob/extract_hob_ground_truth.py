#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

ALIGN_EXPR_RE = re.compile(r"\(\s*\w+\s*\+\s*0x7\s*\)\s*&\s*\(~0x7\)")
OVERFLOW_GUARD_RE = re.compile(r"if\s*\(\s*\w+\s*>\s*MAX_UINT16\s*-\s*0x7\s*\)")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    result = {}
    total = 0
    for filepath in sorted(glob.glob(os.path.join(args.fixed_dir, "*.c"))):
        name = os.path.basename(filepath)
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()

        anchors = []
        for i, line in enumerate(lines):
            if not ALIGN_EXPR_RE.search(line):
                continue
            j = i - 1
            found_guard = False
            while j >= 0:
                stripped = lines[j].strip()
                if not stripped:
                    j -= 1; continue
                if stripped == "}":
                    j -= 1; continue
                if stripped.startswith("//"):
                    j -= 1; continue
                if stripped.startswith("return"):
                    j -= 1; continue
                if OVERFLOW_GUARD_RE.search(stripped):
                    found_guard = True
                break

            if found_guard:
                anchors.append(line.strip())

        result[name] = {"anchors": anchors}
        total += len(anchors)
        print(f"{name}: {len(anchors)} ground-truth site(s)")
        for a in anchors:
            print(f"    -> {a[:70]}")

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nTotal ground-truth sites: {total}")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
