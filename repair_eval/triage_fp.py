#!/usr/bin/env python3
import argparse
import json
import os
import re

STATUS_ID_RE = re.compile(
    r"(Status|Error|Result|NULL|Null|EFI_ERROR|RETURN_ERROR|EFI_SUCCESS|"
    r"Supported|Enabled|Present|Found|Valid|Boolean)", re.IGNORECASE
)
MEM_OP_RE = re.compile(
    r"\b(CopyMem|ZeroMem|SetMem|SetMem32|CompareMem|AllocatePool|"
    r"AllocateZeroPool|AllocateCopyPool)\s*\("
)
TAINT_SRC_RE = re.compile(r"CommBuffer", re.IGNORECASE)
STOPLIST = {
    "if", "IF", "NULL", "TRUE", "FALSE", "sizeof", "OFFSET_OF",
    "EFI_SUCCESS", "EFI_ERROR", "RETURN_ERROR", "VOID", "UINTN",
    "UINT8", "UINT16", "UINT32", "UINT64", "EFI_STATUS",
}

def idents(text):
    out = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
    return [i for i in out if i not in STOPLIST and len(i) > 1]

def is_status_guard(cond):
    ids = idents(cond)
    if not ids:
        return True
    return all(STATUS_ID_RE.search(i) for i in ids)

def checked_vars(cond):
    return [i for i in idents(cond) if not STATUS_ID_RE.search(i)]

def forward_window(lines, start_line, n):
    lo = max(0, start_line - 1)
    return lines[lo:lo + n]

def var_in_subscript_or_memop(var, window_lines):
    for ln in window_lines:
        for sub in re.findall(r"\[([^\[\]]+)\]", ln):
            if re.search(r"\b%s\b" % re.escape(var), sub):
                return True
        m = MEM_OP_RE.search(ln)
        if m and re.search(r"\b%s\b" % re.escape(var), ln[m.end():]):
            return True
    return False

def enclosing_function_text(lines, line_no, max_back=200):
    lo = max(0, line_no - max_back)
    return "\n".join(lines[lo:line_no + 25])

def is_tp(cand, gt_anchors):
    stmt = " ".join(cand.get("next_statement", "").split())
    cond = " ".join(cand.get("condition_snippet", "").split())
    for a in gt_anchors:
        if a in stmt or a in cond:
            return True
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--ground-truth", required=True)
    ap.add_argument("--buggy-dir", required=True)
    ap.add_argument("--window", type=int, default=25)
    ap.add_argument("--dump-other", action="store_true")
    ap.add_argument("--out-json", default=None)
    args = ap.parse_args()

    cands = json.load(open(args.candidates))
    gt = json.load(open(args.ground_truth))

    buckets = {"B1_status_guard": [], "B2_no_memory_use": [],
               "B3_untainted_index": [], "B4_other": []}
    n_tp = 0
    n_fp = 0

    for fname, clist in cands.items():
        gt_anchors = [" ".join(a.split()) for a in gt.get(fname, {}).get("anchors", [])]
        path = os.path.join(args.buggy_dir, fname)
        lines = open(path, errors="replace").read().splitlines()

        for c in clist:
            if is_tp(c, gt_anchors):
                n_tp += 1
                continue
            n_fp += 1
            cond = c.get("condition_snippet", "")
            site = (fname, c.get("if_line"), cond.strip()[:90])

            if is_status_guard(cond):
                buckets["B1_status_guard"].append(site)
                continue

            cvars = checked_vars(cond)
            win = forward_window(lines, c.get("insertion_after_line",
                                              c.get("if_line", 1)), args.window)
            used = [v for v in cvars if var_in_subscript_or_memop(v, win)]
            if not used:
                buckets["B2_no_memory_use"].append(site)
                continue

            ctx = enclosing_function_text(lines, c.get("if_line", 1))
            tainted = any(
                TAINT_SRC_RE.search(ln) and any(
                    re.search(r"\b%s\b" % re.escape(v), ln) for v in used)
                for ln in ctx.splitlines())
            if not tainted:
                buckets["B3_untainted_index"].append(site)
            else:
                buckets["B4_other"].append(site)

    print(f"TP candidates: {n_tp}   FP candidates: {n_fp}")
    print(f"{'Bucket':<24}{'Count':>7}{'% of FPs':>10}")
    print("-" * 41)
    for k, v in buckets.items():
        pct = 100.0 * len(v) / n_fp if n_fp else 0.0
        print(f"{k:<24}{len(v):>7}{pct:>9.1f}%")

    if args.dump_other:
        print("\n-- B4_other sites (manual review) --")
        for s in buckets["B4_other"]:
            print(f"  {s[0]}:{s[1]}  {s[2]}")

    if args.out_json:
        with open(args.out_json, "w") as f:
            json.dump({k: [list(s) for s in v] for k, v in buckets.items()},
                      f, indent=1)
        print(f"\nWrote {args.out_json}")

if __name__ == "__main__":
    main()
