#!/usr/bin/env python3
import argparse
import csv
import re
import subprocess
from collections import defaultdict

CAMPAIGNS = {
    "spectre-v1": {
        "label": "Bounds check bypass / Spectre v1 (CVE-2017-5753)",
        "grep": "Fix bounds check bypass",
        "extended_regex": False,
    },
    "rsb": {
        "label": "RSB stuffing / Spectre v2-class SMM (CVE-2017-5715)",
        "grep": "Stuff RSB before RSM",
        "extended_regex": False,
    },
    "decompress": {
        "label": "Decompression bounds checking (CVE FIX)",
        "grep": "Add more checker in.*CVE FIX",
        "extended_regex": True,
    },
}

CHERRY_PICK_RE = re.compile(r"cherry picked from commit ([0-9a-f]{40})")

_IGNORE_LINE_PREFIXES = ("index ", "+++ ", "--- ")

def run_git(repo, args):
    result = subprocess.run(
        ["git", "-C", repo] + args,
        capture_output=True, text=True, check=True,
    )
    return result.stdout

def get_candidate_commits(repo, pattern, extended_regex):
    grep_flag = "--extended-regexp" if extended_regex else "--fixed-strings"
    out = run_git(repo, [
        "log", "--all", "--format=%H",
        grep_flag, f"--grep={pattern}", "-i",
    ])
    return [h for h in out.splitlines() if h]

def get_commit_body(repo, commit_hash):
    return run_git(repo, ["log", "-1", "--format=%B", commit_hash])

def get_commit_author_date(repo, commit_hash):
    return run_git(repo, ["log", "-1", "--format=%at", commit_hash]).strip()

def explicit_cherry_pick_target(repo, commit_hash):
    body = get_commit_body(repo, commit_hash)
    m = CHERRY_PICK_RE.search(body)
    return m.group(1) if m else None

def content_fingerprint(repo, commit_hash):
    diff_text = run_git(
        repo,
        ["show", commit_hash, "--",
         "*.c", "*.h", "*.inf", "*.asm", "*.nasm", "*.inc", "*.S"],
    )
    current_file = None
    changes = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            current_file = line.split(" b/")[-1]
            continue
        if line.startswith(_IGNORE_LINE_PREFIXES):
            continue
        if "Copyright (c)" in line:
            continue
        if line.startswith("+") or line.startswith("-"):
            changes.append((current_file, line))
    return tuple(sorted(changes))

def mine_campaign(repo, cfg):
    candidates = get_candidate_commits(repo, cfg["grep"], cfg["extended_regex"])
    candidate_set = set(candidates)

    explicit_backport_of = {}
    for h in candidates:
        target = explicit_cherry_pick_target(repo, h)
        if target and target in candidate_set:
            explicit_backport_of[h] = target

    backport_map = defaultdict(list)
    for h, target in explicit_backport_of.items():
        backport_map[target].append(h)

    root_candidates = [h for h in candidates if h not in explicit_backport_of]
    fingerprints = {h: content_fingerprint(repo, h) for h in root_candidates}
    dates = {h: get_commit_author_date(repo, h) for h in root_candidates}

    fp_groups = defaultdict(list)
    empty_fp_roots = []
    for h, fp in fingerprints.items():
        if not fp:
            empty_fp_roots.append(h)  # no matched file types; can't compare
        else:
            fp_groups[fp].append(h)

    originals = set()
    for fp, members in fp_groups.items():
        members_sorted = sorted(members, key=lambda h: dates[h])
        origin = members_sorted[0]
        originals.add(origin)
        for h in members_sorted[1:]:
            backport_map[origin].append(h)

    originals.update(empty_fp_roots)

    return {
        "label": cfg["label"],
        "raw_commit_count": len(candidates),
        "original_count": len(originals),
        "originals": sorted(originals),
        "backport_count": sum(len(v) for v in backport_map.values()),
        "backport_map": dict(backport_map),
        "explicit_backport_count": len(explicit_backport_of),
        "implicit_backport_count": sum(len(v) for v in backport_map.values()) - len(explicit_backport_of),
        "unfingerprinted_roots": empty_fp_roots,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Path to local edk2 clone")
    parser.add_argument(
        "--campaign", default="all",
        choices=["all"] + list(CAMPAIGNS.keys()),
    )
    parser.add_argument("--csv", default=None, help="Optional path to write per-site CSV")
    args = parser.parse_args()

    keys = list(CAMPAIGNS.keys()) if args.campaign == "all" else [args.campaign]

    results = {}
    total_originals = 0
    total_backports = 0

    for key in keys:
        cfg = CAMPAIGNS[key]
        res = mine_campaign(args.repo, cfg)
        results[key] = res
        total_originals += res["original_count"]
        total_backports += res["backport_count"]

        print(f"=== {res['label']} ===")
        print(f"  raw candidate commits  : {res['raw_commit_count']}")
        print(f"  distinct original sites: {res['original_count']}")
        print(f"  backports (deduped)    : {res['backport_count']}"
              f"  (explicit cherry-pick: {res['explicit_backport_count']},"
              f" implicit/content-matched: {res['implicit_backport_count']})")
        if res["unfingerprinted_roots"]:
            print(
                f"  WARNING: {len(res['unfingerprinted_roots'])} commit(s) had no "
                f"explicit trailer AND no matched file type to fingerprint -- "
                f"counted as distinct originals by default, verify manually: "
                f"{res['unfingerprinted_roots']}"
            )
        print()

    print("=== TOTAL ===")
    print(f"  distinct original fix sites: {total_originals}")
    print(f"  total backports             : {total_backports}")
    if total_originals:
        print(f"  avg backports / fix         : {total_backports / total_originals:.2f}")

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["campaign", "label", "original_hash", "backport_count", "backport_hashes"])
            for key, res in results.items():
                for orig in res["originals"]:
                    backports = res["backport_map"].get(orig, [])
                    writer.writerow([key, res["label"], orig, len(backports), ";".join(backports)])
        print(f"\nWrote per-site CSV to {args.csv}")

if __name__ == "__main__":
    main()
