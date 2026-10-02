#!/usr/bin/env python3
import argparse
import json
import os
import re

STATUS_GUARD_RE = re.compile(
    r"\b(Status|Error|Result|Null|NULL|EFI_ERROR|RETURN_ERROR|EFI_SUCCESS)\b"
)
NULL_ONLY_RE = re.compile(r"^\s*if\s*\(\s*\S+\s*(==|!=)\s*NULL\s*\)", re.IGNORECASE)

SUBSCRIPT_RE = re.compile(r"\[([^\[\]]+)\]")
MEM_OP_RE = re.compile(r"\b(CopyMem|ZeroMem|SetMem|AllocatePool|AllocateZeroPool)\s*\(")

STOPLIST = {
    "Index", "i", "j", "k", "n", "Count", "NULL", "TRUE", "FALSE",
    "sizeof", "OFFSET_OF", "EFI_SUCCESS", "0", "1",
}

def extract_identifiers(text):
    ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
    return {i for i in ids if i not in STOPLIST and len(i) > 1}

def is_status_or_null_guard(condition_text):
    ids = extract_identifiers(condition_text)
    non_status = [i for i in ids if not STATUS_GUARD_RE.search(i)]
    if not non_status:
        return True
    if NULL_ONLY_RE.match(condition_text.strip()):
        return True
    return False

def has_subscript_use(lines, start_idx, cond_ids, window=40):
    end = min(start_idx + window, len(lines))
    for k in range(start_idx, end):
        line = lines[k]
        for m in SUBSCRIPT_RE.finditer(line):
            subscript_ids = extract_identifiers(m.group(1))
            if cond_ids & subscript_ids:
                return True
        if MEM_OP_RE.search(line):
            line_ids = extract_identifiers(line)
            if cond_ids & line_ids:
                return True
    return False

def load_file_lines(buggy_dir, name):
    path = os.path.join(buggy_dir, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()

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

    tp_anchors = set()
    for name, entry in ground_truth.items():
        for a in entry["anchors"]:
            tp_anchors.add((name, a.strip()[:80]))

    print(f"{'Check':<30} {'Cand':>6} {'TP kept':>8} {'FP elim':>9} {'Precision':>10}")
    print("-" * 68)

    results = {}
    for check_name, use_status_filter, use_subscript_filter in [
        ("baseline (targeted+dataflow)", False, False),
        ("+ status/null guard filter",   True,  False),
        ("+ subscript use filter",       False, True),
        ("+ both filters",               True,  True),
    ]:
        kept_tp = 0
        kept_fp = 0
        eliminated_fp = 0
        total_cand = 0

        for name, cand_list in candidates.items():
            lines = load_file_lines(args.buggy_dir, name)
            if lines is None:
                continue

            for c in cand_list:
                total_cand += 1
                anchor = c["next_statement"].strip()[:80]
                is_tp = (name, anchor) in tp_anchors or any(
                    anchor in a or a in anchor
                    for (n, a) in tp_anchors if n == name
                )

                cond_ids = extract_identifiers(c["condition_snippet"])
                insertion_line = c["insertion_after_line"]

                keep = True
                if use_status_filter and is_status_or_null_guard(c["condition_snippet"]):
                    keep = False
                if use_subscript_filter and keep:
                    if not has_subscript_use(lines, insertion_line, cond_ids):
                        keep = False

                if keep:
                    if is_tp:
                        kept_tp += 1
                    else:
                        kept_fp += 1
                else:
                    if not is_tp:
                        eliminated_fp += 1
                    elif is_tp:
                        print(f"  WARNING: filter eliminated TP: {name} / {anchor[:50]}")

        precision = kept_tp / (kept_tp + kept_fp) if (kept_tp + kept_fp) > 0 else 0
        print(f"{check_name:<30} {kept_tp+kept_fp:>6} {kept_tp:>8} {eliminated_fp:>9} {precision:>9.1%}")
        results[check_name] = {
            "candidates": kept_tp + kept_fp,
            "tp_kept": kept_tp,
            "fp_eliminated": eliminated_fp,
            "precision": precision,
        }

    print("-" * 68)
    print(f"\nBaseline TPs (ground truth): {sum(len(e['anchors']) for e in ground_truth.values())}")
    print("All filters preserve 100% recall unless a WARNING appears above.")

if __name__ == "__main__":
    main()
