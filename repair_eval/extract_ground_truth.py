#!/usr/bin/env python3
import argparse
import json
import re
import subprocess

def run_git(repo, args):
    result = subprocess.run(["git", "-C", repo] + args, capture_output=True, text=True, check=True)
    return result.stdout

def parse_sites(path):
    sites = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            orig, parent, filepath = line.split("|")
            sites.append((orig, parent, filepath))
    return sites

LFENCE_CALL_RE = re.compile(r"^(AsmLfence|MemoryLoadFence)\s*\(\s*\)\s*;")

def extract_anchors_for_file(repo, orig, filepath):
    content = run_git(repo, ["show", f"{orig}:{filepath}"])
    lines = content.splitlines()

    anchors = []
    for i, line in enumerate(lines):
        if LFENCE_CALL_RE.match(line.strip()):
            j = i + 1
            while j < len(lines):
                stripped = lines[j].strip()
                if not stripped:
                    j += 1
                    continue
                if stripped.startswith("//"):
                    j += 1
                    continue
                anchors.append(stripped)
                break
    return anchors

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sites", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    sites = parse_sites(args.sites)
    result = {}
    total_anchors = 0
    for orig, parent, filepath in sites:
        anchors = extract_anchors_for_file(args.repo, orig, filepath)
        pkg = filepath.split("/")[0]
        base = filepath.split("/")[-1]
        name = f"{pkg}_{base}" if base in ("Variable.c", "VariableSmm.c") else base
        result[name] = {
            "original_hash": orig,
            "parent_hash": parent,
            "filepath": filepath,
            "anchors": anchors,
        }
        total_anchors += len(anchors)
        print(f"{name}: {len(anchors)} ground-truth insertion point(s)")
        for a in anchors:
            print(f"    -> {a[:80]}")

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nTotal ground-truth insertion points: {total_anchors}")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
