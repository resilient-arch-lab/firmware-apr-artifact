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

    print(f"{'File':<28} {'GT':>4} {'Cand':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'Recall':>8} {'Precision':>10}")
    print("-" * 80)

    total_gt = total_cand = total_tp = total_fp = total_fn = 0

    for name, gt_entry in ground_truth.items():
        gt_anchors = [normalize(a) for a in gt_entry["anchors"]]
        cand_list = candidates.get(name, [])
        cand_anchors = [normalize(c["next_statement"]) for c in cand_list]

        gt_remaining = list(gt_anchors)
        tp = 0
        for ca in cand_anchors:
            if ca in gt_remaining:
                gt_remaining.remove(ca)
                tp += 1

        fn = len(gt_remaining)
        fp = len(cand_anchors) - tp

        recall = tp / len(gt_anchors) if gt_anchors else float("nan")
        precision = tp / len(cand_anchors) if cand_anchors else float("nan")

        total_gt += len(gt_anchors)
        total_cand += len(cand_anchors)
        total_tp += tp
        total_fp += fp
        total_fn += fn

        print(f"{name:<28} {len(gt_anchors):>4} {len(cand_anchors):>6} {tp:>4} {fp:>4} {fn:>4} "
              f"{recall:>7.0%} {precision:>9.1%}" if gt_anchors or cand_anchors else
              f"{name:<28} {0:>4} {0:>6} {0:>4} {0:>4} {0:>4} {'n/a':>8} {'n/a':>10}")

    print("-" * 80)
    overall_recall = total_tp / total_gt if total_gt else float("nan")
    overall_precision = total_tp / total_cand if total_cand else float("nan")
    f1 = (2 * overall_precision * overall_recall / (overall_precision + overall_recall)
          if (overall_precision + overall_recall) else float("nan"))
    print(f"{'TOTAL':<28} {total_gt:>4} {total_cand:>6} {total_tp:>4} {total_fp:>4} {total_fn:>4} "
          f"{overall_recall:>7.0%} {overall_precision:>9.1%}")
    print(f"\nF1: {f1:.3f}")
    print(f"Recall (did we find the real bug sites): {overall_recall:.1%} ({total_tp}/{total_gt})")
    print(f"Precision (of flagged sites, how many were real): {overall_precision:.1%} ({total_tp}/{total_cand})")
    print(f"False positives (flagged but not a real Spectre-v1 fix site): {total_fp}")
    print(f"False negatives (real fix site missed entirely): {total_fn}")

if __name__ == "__main__":
    main()
