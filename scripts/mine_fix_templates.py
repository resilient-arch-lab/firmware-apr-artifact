#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
from collections import defaultdict

MIN_CLUSTER_SIZE_DEFAULT = 2

IGNORE_PREFIXES = ("index ", "+++ ", "--- ", "diff --git", "commit ", "Author:",
                   "Date:", "    ", "@@")

COPYRIGHT_RE = re.compile(r"Copyright \(c\)", re.IGNORECASE)

IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
NUMBER_RE = re.compile(r"\b(0x[0-9a-fA-F]+|[0-9]+)\b")
STRING_RE = re.compile(r'"[^"]*"')

def structural_skeleton(line):
    s = line.strip()
    s = COPYRIGHT_RE.sub("", s)
    s = STRING_RE.sub("STR", s)
    s = NUMBER_RE.sub("NUM", s)
    s = IDENTIFIER_RE.sub("ID", s)
    return " ".join(s.split())

def run_git(repo, args):
    result = subprocess.run(
        ["git", "-C", repo] + args,
        capture_output=True, text=True, check=True,
    )
    return result.stdout

def get_all_cve_commits(repo):
    out = run_git(repo, ["log", "--all", "--format=%H", "-i", "--grep=CVE"])
    return [h for h in out.splitlines() if h]

def get_commit_subject(repo, h):
    return run_git(repo, ["log", "-1", "--format=%s", h]).strip()

def get_diff_lines(repo, h):
    diff = run_git(repo, ["show", h, "--", "*.c", "*.h", "*.asm", "*.nasm", "*.inc", "*.S"])
    added, removed = [], []
    for line in diff.splitlines():
        if line.startswith(IGNORE_PREFIXES):
            continue
        if COPYRIGHT_RE.search(line):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].strip())
    return added, removed

def fingerprint_exact(added, removed):
    return tuple(sorted(added + removed))

def fingerprint_structural(added, removed):
    return tuple(sorted(set(structural_skeleton(l) for l in added + removed
                           if l.strip() and len(l.strip()) > 3)))

def cluster_commits(repo, commits, min_cluster_size):
    print(f"Collecting diff fingerprints for {len(commits)} CVE-tagged commits...")
    data = {}
    for i, h in enumerate(commits):
        if i % 10 == 0:
            print(f"  {i}/{len(commits)}...", end="\r", flush=True)
        subj = get_commit_subject(repo, h)
        added, removed = get_diff_lines(repo, h)
        if not added and not removed:
            continue
        data[h] = {
            "subject": subj,
            "added": added,
            "removed": removed,
            "fp_exact": fingerprint_exact(added, removed),
            "fp_structural": fingerprint_structural(added, removed),
        }
    print(f"\nCollected {len(data)} commits with code changes.")

    exact_groups = defaultdict(list)
    for h, d in data.items():
        exact_groups[d["fp_exact"]].append(h)

    already_grouped = set()
    clusters = []
    for fp, members in exact_groups.items():
        if len(members) >= 2:
            clusters.append({
                "type": "exact",
                "members": members,
                "subjects": [data[h]["subject"] for h in members],
                "dominant_added": list(dict.fromkeys(
                    l for h in members for l in data[h]["added"] if l
                ))[:5],
            })
            already_grouped.update(members)

    structural_groups = defaultdict(list)
    for h, d in data.items():
        if h not in already_grouped and d["fp_structural"]:
            structural_groups[d["fp_structural"]].append(h)

    for fp, members in structural_groups.items():
        if len(members) >= min_cluster_size:
            clusters.append({
                "type": "structural",
                "members": members,
                "subjects": [data[h]["subject"] for h in members],
                "dominant_added": list(dict.fromkeys(
                    l for h in members for l in data[h]["added"] if l
                ))[:5],
            })

    return sorted(clusters, key=lambda c: -len(c["members"]))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--min-cluster", type=int, default=MIN_CLUSTER_SIZE_DEFAULT)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    commits = get_all_cve_commits(args.repo)
    print(f"Found {len(commits)} CVE-tagged commits total.")

    clusters = cluster_commits(args.repo, commits, args.min_cluster)

    print(f"\n=== {len(clusters)} candidate fix-template clusters (size >= {args.min_cluster}) ===\n")
    for i, cluster in enumerate(clusters):
        print(f"--- Cluster {i+1} [{cluster['type']}] size={len(cluster['members'])} ---")
        for subj in cluster["subjects"][:5]:
            print(f"  {subj}")
        if len(cluster["subjects"]) > 5:
            print(f"  ... ({len(cluster['subjects']) - 5} more)")
        print(f"  Sample added lines:")
        for line in cluster["dominant_added"][:3]:
            print(f"    + {line[:80]}")
        print()

    if args.out:
        out_clusters = []
        for c in clusters:
            out_clusters.append({
                "type": c["type"],
                "size": len(c["members"]),
                "member_hashes": c["members"],
                "subjects": c["subjects"],
                "dominant_added": c["dominant_added"],
            })
        with open(args.out, "w") as f:
            json.dump(out_clusters, f, indent=2)
        print(f"Wrote clusters to {args.out}")

    known_campaigns = {
        "CVE-2017-5753": "Fix bounds check bypass",
        "CVE-2017-5715": "Stuff RSB",
        "CVE FIX decompression": "Add more checker in",
    }
    print("=== Recovery check: do known campaigns appear? ===")
    for label, keyword in known_campaigns.items():
        found = any(
            any(keyword.lower() in s.lower() for s in c["subjects"])
            for c in clusters
        )
        print(f"  {label}: {'RECOVERED' if found else 'NOT FOUND'}")

if __name__ == "__main__":
    main()
