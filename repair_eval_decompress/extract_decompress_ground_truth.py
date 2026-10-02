#!/usr/bin/env python3
import argparse
import json
import os
import re

IN_SCOPE_PATTERNS = [
    re.compile(r"Count\[BitLen\[Index\]\]\+\+;"),
    re.compile(r"Table\[Index\]\s*=\s*Char;"),
    re.compile(r"Sd->mDstBase\[Sd->mOutBuf\+\+\]\s*=\s*Sd->mDstBase\[DataIdx\+\+\];"),
]

IN_SCOPE_FILES = [
    "Decompress.c",
    "BaseUefiTianoCustomDecompressLib.c",
    "BaseUefiDecompressLib.c",
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buggy-dir", required=True)
    parser.add_argument("--fixed-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    result = {}
    total = 0
    for name in IN_SCOPE_FILES:
        fixed_path = os.path.join(args.fixed_dir, name)
        if not os.path.exists(fixed_path):
            print(f"WARNING: {fixed_path} not found, skipping")
            continue
        with open(fixed_path, encoding="utf-8", errors="replace") as f:
            content = f.read()

        anchors = []
        for pat in IN_SCOPE_PATTERNS:
            m = pat.search(content)
            if m:
                anchors.append(m.group(0))
            else:
                print(f"WARNING: pattern not found in {name}: {pat.pattern}")

        result[name] = {"anchors": anchors}
        total += len(anchors)
        print(f"{name}: {len(anchors)} in-scope ground-truth site(s)")
        for a in anchors:
            print(f"    -> {a}")

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nTotal in-scope ground-truth sites: {total}")
    print(f"Wrote {args.out}")
    print("\n(Excluded from scope: TianoCompress.c InputLength checks, "
          "and the integer-overflow condition-strengthening fixes -- "
          "different fix shapes, documented in detect_missing_bounds_check.py)")

if __name__ == "__main__":
    main()
