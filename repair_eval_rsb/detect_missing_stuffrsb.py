#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

RSM_RE = re.compile(r"^\s*rsm\b", re.IGNORECASE)
STUFF_RSB_RE = re.compile(r"^\s*StuffRsb(32|64)\b", re.IGNORECASE)
COMMENT_ONLY_RE = re.compile(r"^\s*;")  # both MASM and NASM use ';' for comments

def detect_candidates(filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    candidates = []
    for i, line in enumerate(lines):
        if RSM_RE.match(line):
            j = i - 1
            while j >= 0 and (not lines[j].strip() or COMMENT_ONLY_RE.match(lines[j])):
                j -= 1
            preceding = lines[j].strip() if j >= 0 else ""
            if not STUFF_RSB_RE.match(preceding):
                candidates.append({
                    "rsm_line": i + 1,
                    "preceding_line_text": preceding,
                    "rsm_text": line.strip(),
                })
    return candidates

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buggy-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    all_results = {}
    total = 0
    for filepath in sorted(glob.glob(os.path.join(args.buggy_dir, "*"))):
        if not os.path.isfile(filepath):
            continue
        name = os.path.basename(filepath)
        candidates = detect_candidates(filepath)
        all_results[name] = candidates
        total += len(candidates)
        print(f"{name}: {len(candidates)} candidate(s)")
        for c in candidates:
            print(f"    line {c['rsm_line']}: \"{c['rsm_text']}\" "
                  f"(preceded by: \"{c['preceding_line_text'][:50]}\")")

    with open(args.out, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nTotal candidates flagged: {total}")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
