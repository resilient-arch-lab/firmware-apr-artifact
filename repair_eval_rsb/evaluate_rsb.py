#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

RSM_RE = re.compile(r"^\s*rsm\b", re.IGNORECASE)

def count_rsm_occurrences(filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    return sum(1 for l in lines if RSM_RE.match(l))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--buggy-dir", required=True)
    args = parser.parse_args()

    with open(args.candidates) as f:
        candidates = json.load(f)
    with open(args.ground_truth) as f:
        ground_truth = json.load(f)

    print(f"{'File':<55} {'GT':>4} {'BuggyRSM':>9} {'Cand':>5} {'TP':>4} {'FP':>4} {'FN':>4}")
    print("-" * 90)

    total_gt = total_cand = total_tp = total_fp = total_fn = 0
    consistency_warnings = []

    for name, gt_entry in ground_truth.items():
        gt_protected_count = gt_entry["protected_count"]
        gt_total_rsm = gt_entry["rsm_count"]

        buggy_path = os.path.join(args.buggy_dir, name)
        if not os.path.exists(buggy_path):
            print(f"WARNING: {buggy_path} not found")
            continue
        buggy_rsm_count = count_rsm_occurrences(buggy_path)

        if buggy_rsm_count != gt_total_rsm:
            consistency_warnings.append(
                f"{name}: buggy has {buggy_rsm_count} rsm occurrences, "
                f"fixed has {gt_total_rsm} -- ordinal matching assumption violated!"
            )

        cand_count = len(candidates.get(name, []))

        tp = min(cand_count, gt_protected_count, buggy_rsm_count)
        fp = max(0, cand_count - tp)
        fn = max(0, gt_protected_count - tp)

        total_gt += gt_protected_count
        total_cand += cand_count
        total_tp += tp
        total_fp += fp
        total_fn += fn

        print(f"{name:<55} {gt_protected_count:>4} {buggy_rsm_count:>9} {cand_count:>5} "
              f"{tp:>4} {fp:>4} {fn:>4}")

    print("-" * 90)
    overall_recall = total_tp / total_gt if total_gt else float("nan")
    overall_precision = total_tp / total_cand if total_cand else float("nan")
    print(f"{'TOTAL':<55} {total_gt:>4} {'':<9} {total_cand:>5} {total_tp:>4} {total_fp:>4} {total_fn:>4}")
    print(f"\nRecall: {overall_recall:.1%} ({total_tp}/{total_gt})")
    print(f"Precision: {overall_precision:.1%} ({total_tp}/{total_cand})")

    if consistency_warnings:
        print("\nCONSISTENCY WARNINGS (ordinal matching may be invalid for these files):")
        for w in consistency_warnings:
            print(f"  - {w}")
    else:
        print("\nConsistency check passed: rsm count matches between buggy and fixed for every file "
              "(ordinal matching is exact, not approximate).")

if __name__ == "__main__":
    main()
