#!/usr/bin/env python3
import argparse
import json

def normalize(s):
    return " ".join(s.split())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--ground-truth", required=True)
    args = parser.parse_args()

    with open(args.candidates) as f:
        candidates = json.load(f)
    with open(args.ground_truth) as f:
        ground_truth = json.load(f)

    print(f"{'File':<35} {'GT':>4} {'Cand':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'Recall':>8} {'Precision':>10}")
    print("-" * 80)

    total_gt = total_cand = total_tp = total_fp = total_fn = 0

    for name, gt_entry in ground_truth.items():
        gt_anchors = [normalize(a) for a in gt_entry["anchors"]]
        cand_list = candidates.get(name, [])
        cand_exprs = [normalize(c["alignment_expr"]) for c in cand_list]

        tp = sum(1 for a in gt_anchors if any(a in e or e in a for e in cand_exprs))
        fp = len(cand_exprs) - tp
        fn = len(gt_anchors) - tp

        recall = tp / len(gt_anchors) if gt_anchors else float("nan")
        precision = tp / len(cand_exprs) if cand_exprs else float("nan")

        total_gt += len(gt_anchors)
        total_cand += len(cand_exprs)
        total_tp += tp
        total_fp += fp
        total_fn += fn

        print(f"{name:<35} {len(gt_anchors):>4} {len(cand_exprs):>6} {tp:>4} {fp:>4} {fn:>4} "
              f"{recall:>7.0%} {precision:>9.1%}")

    print("-" * 80)
    overall_recall = total_tp / total_gt if total_gt else float("nan")
    overall_precision = total_tp / total_cand if total_cand else float("nan")
    print(f"{'TOTAL':<35} {total_gt:>4} {total_cand:>6} {total_tp:>4} {total_fp:>4} {total_fn:>4} "
          f"{overall_recall:>7.0%} {overall_precision:>9.1%}")
    print(f"\nRecall: {overall_recall:.1%} ({total_tp}/{total_gt})")
    print(f"Precision: {overall_precision:.1%} ({total_tp}/{total_cand})")

if __name__ == "__main__":
    main()
