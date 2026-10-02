#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

RSM_RE = re.compile(r"^\s*rsm\b", re.IGNORECASE)
STUFF_RSB_RE = re.compile(r"^\s*StuffRsb(32|64)\b", re.IGNORECASE)

def find_rsm_sites(lines):
    sites = []
    for i, line in enumerate(lines):
        if RSM_RE.match(line):
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            protected = j >= 0 and bool(STUFF_RSB_RE.match(lines[j].strip()))
            sites.append({
                "rsm_line": i + 1,
                "preceding_line_text": lines[j].strip() if j >= 0 else "",
                "protected": protected,
            })
    return sites

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    result = {}
    total = 0
    for filepath in sorted(glob.glob(os.path.join(args.fixed_dir, "*"))):
        name = os.path.basename(filepath)
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        sites = find_rsm_sites(lines)
        protected_sites = [s for s in sites if s["protected"]]
        unprotected_sites = [s for s in sites if not s["protected"]]

        result[name] = {
            "rsm_count": len(sites),
            "protected_count": len(protected_sites),
            "anchors": [s["rsm_line"] for s in protected_sites],
        }
        total += len(protected_sites)

        print(f"{name}: {len(sites)} rsm site(s), {len(protected_sites)} protected by StuffRsb")
        if unprotected_sites:
            print(f"    WARNING: {len(unprotected_sites)} rsm site(s) in the FIXED file "
                  f"still lack a StuffRsb call -- check manually: "
                  f"{[s['rsm_line'] for s in unprotected_sites]}")

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nTotal ground-truth (protected) rsm sites: {total}")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
