#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

IF_ANY_RE = re.compile(r"\bif\s*\(")
IF_COMPARISON_RE = re.compile(
    r"\bif\s*\(.*?(==|!=|<=|>=|(?<![<>=!])<(?!=)|(?<![<>=!])>(?!=))"
)
COMMENT_RE = re.compile(r"^\s*//")

def find_anchor_lines(lines, anchors):
    norm_lines = [" ".join(l.split()) for l in lines]
    found = []
    for a in anchors:
        a_norm = " ".join(a.split())
        for i, nl in enumerate(norm_lines):
            if a_norm in nl or nl in a_norm and nl:
                found.append(i)
                break
    return found

def detect_naive(filepath, mode):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()
    hits = []
    pattern = IF_ANY_RE if mode == "any-if" else IF_COMPARISON_RE
    for i, line in enumerate(lines):
        if COMMENT_RE.match(line):
            continue
        if pattern.search(line):
            hits.append(i)
    return lines, hits

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--buggy-dir", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--window", type=int, default=3,
                    help="line-number tolerance for counting a naive hit as a TP")
    ap.add_argument("--mode", choices=["comparison-only", "any-if"],
                    default="comparison-only",
                    help="comparison-only: flag if(...) with a comparison "
                         "operator. any-if: flag every if(...) statement "
                         "(the absolute floor baseline).")
    args = ap.parse_args()

    gt = json.load(open(args.ground_truth))

    total_cand = total_tp = total_gt = 0
    print(f"Mode: {args.mode}")
    print(f"{'File':<28}{'GT':>4}{'Cand':>7}{'TP':>4}{'FP':>5}")
    print("-" * 48)
    for fname, entry in gt.items():
        path = os.path.join(args.buggy_dir, fname)
        if not os.path.exists(path):
            continue
        lines, hits = detect_naive(path, args.mode)
        anchor_lines = find_anchor_lines(lines, entry["anchors"])

        tp = 0
        used = set()
        for al in anchor_lines:
            for h in hits:
                if h in used:
                    continue
                if abs(h - al) <= args.window:
                    tp += 1
                    used.add(h)
                    break
        cand = len(hits)
        gt_n = len(entry["anchors"])
        fp = cand - tp

        total_cand += cand
        total_tp += tp
        total_gt += gt_n
        print(f"{fname:<28}{gt_n:>4}{cand:>7}{tp:>4}{fp:>5}")

    print("-" * 48)
    recall = total_tp / total_gt if total_gt else float("nan")
    precision = total_tp / total_cand if total_cand else float("nan")
    print(f"{'TOTAL':<28}{total_gt:>4}{total_cand:>7}{total_tp:>4}{total_cand-total_tp:>5}")
    print(f"\nNaive baseline -- Recall: {recall:.1%} ({total_tp}/{total_gt})  "
          f"Precision: {precision:.1%} ({total_tp}/{total_cand})")

if __name__ == "__main__":
    main()
