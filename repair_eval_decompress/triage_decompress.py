#!/usr/bin/env python3
import argparse
import json
import os
import re

def norm(s):
    return " ".join(s.split())

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--buggy-dir", required=True)
    ap.add_argument("--lookback", type=int, default=40,
                    help="lines to scan backward for an enclosing loop bound")
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--dump-other", action="store_true")
    args = ap.parse_args()

    cands = json.load(open(args.candidates))
    gt = json.load(open(args.ground_truth))

    buckets = {
        "D1_const_bounded_loop": [],
        "D2_runtime_bounded_loop": [],
        "D3_literal_index": [],
        "D4_read_access": [],
        "D5_other": [],
    }
    n_tp = n_fp = 0

    for fname, gte in gt.items():
        anchors = [norm(a) for a in gte["anchors"]]
        path = os.path.join(args.buggy_dir, fname)
        lines = open(path, errors="replace").read().splitlines()

        for c in cands.get(fname, []):
            stmt = norm(c["statement"])
            if any(a in stmt for a in anchors):
                n_tp += 1
                continue
            n_fp += 1
            idx = c["index_expr"].strip()
            arr = c["array"]
            site = [fname, c["line"], f"{arr}[{idx}]", stmt[:70]]

            if re.fullmatch(r"\d+", idx):
                buckets["D3_literal_index"].append(site)
                continue

            lhs = stmt.split("=")[0] if "=" in stmt else ""
            is_write = arr in lhs and "[" in lhs
            if not is_write:
                buckets["D4_read_access"].append(site)
                continue

            base = re.match(r"([A-Za-z_][A-Za-z0-9_\.\->]*)", idx)
            base = re.split(r"[^\w]", base.group(1))[-1] if base else idx
            kind = None
            for back in range(c["line"] - 1,
                              max(0, c["line"] - args.lookback), -1):
                ln = lines[back - 1] if back - 1 < len(lines) else ""
                m = re.search(
                    r"(?:for|while)\s*\(.*\b%s\b\s*[<>]=?\s*"
                    r"([A-Za-z0-9_\.\->]+)" % re.escape(base), ln)
                if m:
                    bound = m.group(1)
                    if re.fullmatch(r"\d+", bound) or bound.isupper():
                        kind = "D1_const_bounded_loop"
                    else:
                        kind = "D2_runtime_bounded_loop"
                    break
            buckets[kind or "D5_other"].append(site)

    print(f"TP: {n_tp}  FP: {n_fp}")
    print(f"{'Bucket':<28}{'Count':>6}{'% of FPs':>10}")
    print("-" * 44)
    for k, v in buckets.items():
        pct = 100.0 * len(v) / n_fp if n_fp else 0.0
        print(f"{k:<28}{len(v):>6}{pct:>9.1f}%")

    if args.dump_other:
        print("\n-- D5_other sites (manual review) --")
        for s in buckets["D5_other"]:
            print(f"  {s[0]}:{s[1]}  {s[2]}  | {s[3][:60]}")

    if args.out_json:
        with open(args.out_json, "w") as f:
            json.dump(buckets, f, indent=1)
        print(f"\nWrote {args.out_json}")

if __name__ == "__main__":
    main()
