#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

COMPARISON_RE = re.compile(r"(>=|<=|==|!=|[<>])")
EARLY_EXIT_RE = re.compile(r"^\s*(return\b|break\s*;|continue\s*;|goto\b)")
IF_HEADER_RE = re.compile(r"^\s*if\s*\(")

ARRAY_ACCESS_RE = re.compile(
    r"([A-Za-z_]\w*(?:->[A-Za-z_]\w*)?)\s*\[((?:[^\[\]]|\[[^\[\]]*\])*)\]"
)
WRITE_SUFFIX_RE = re.compile(r"\s*(\+\+|=(?!=))")

def find_matching_brace(lines, open_line_idx):
    depth = 0
    started = False
    for i in range(open_line_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    return i
    return None

def compute_function_ranges(lines):
    ranges = []
    depth = 0
    func_start = None
    for i, line in enumerate(lines):
        opens = line.count("{")
        closes = line.count("}")
        if depth == 0 and opens > 0 and func_start is None:
            func_start = i
        depth += opens - closes
        if depth == 0 and func_start is not None:
            ranges.append((func_start, i))
            func_start = None
    return ranges

def function_range_for_line(ranges, line_idx):
    for start, end in ranges:
        if start <= line_idx <= end:
            return start, end
    return None

def has_backward_guard(lines, func_start, candidate_idx, index_expr):
    index_clean = index_expr.strip()
    j = candidate_idx - 1
    while j >= func_start:
        line = lines[j]
        if IF_HEADER_RE.match(line):
            cond_text = line
            scan = j
            while "{" not in lines[scan] and scan < candidate_idx:
                scan += 1
                cond_text += " " + lines[scan]
            if "{" in lines[scan] and COMPARISON_RE.search(cond_text) and index_clean in cond_text:
                close_idx = find_matching_brace(lines, scan)
                if close_idx is not None:
                    body = lines[scan:close_idx + 1]
                    if any(EARLY_EXIT_RE.match(l) for l in body):
                        return True
        j -= 1
    return False

def detect_candidates(filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    func_ranges = compute_function_ranges(lines)
    candidates = []

    for i, line in enumerate(lines):
        for m in ARRAY_ACCESS_RE.finditer(line):
            array_name, index_expr = m.group(1), m.group(2)
            after = line[m.end():]
            wm = WRITE_SUFFIX_RE.match(after)
            if not wm:
                continue

            index_clean = index_expr.rstrip("+-").strip()
            if not index_clean:
                continue

            frange = function_range_for_line(func_ranges, i)
            if frange is None:
                continue
            func_start, _ = frange

            if not has_backward_guard(lines, func_start, i, index_clean):
                candidates.append({
                    "line": i + 1,
                    "array": array_name,
                    "index_expr": index_expr,
                    "statement": line.strip(),
                })

            rest_after_write = after[wm.end():]
            for rm in ARRAY_ACCESS_RE.finditer(rest_after_write):
                r_array, r_index = rm.group(1), rm.group(2)
                r_index_clean = r_index.rstrip("+-").strip()
                if not r_index_clean:
                    continue
                if not has_backward_guard(lines, func_start, i, r_index_clean):
                    candidates.append({
                        "line": i + 1,
                        "array": r_array,
                        "index_expr": r_index,
                        "statement": line.strip(),
                    })

    seen = set()
    deduped = []
    for c in candidates:
        key = (c["line"], c["array"], c["index_expr"])
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    return deduped

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buggy-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    all_results = {}
    total = 0
    for filepath in sorted(glob.glob(os.path.join(args.buggy_dir, "*.c"))):
        name = os.path.basename(filepath)
        candidates = detect_candidates(filepath)
        all_results[name] = candidates
        total += len(candidates)
        print(f"{name}: {len(candidates)} candidate(s)")
        for c in candidates:
            print(f"    line {c['line']}: {c['array']}[{c['index_expr']}] -> \"{c['statement'][:70]}\"")

    with open(args.out, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nTotal candidates flagged: {total}")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
