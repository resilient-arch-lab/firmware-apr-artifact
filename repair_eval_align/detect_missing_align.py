#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

ALIGN_CALL_RE = re.compile(r"ALIGN_POINTER\s*\(\s*([A-Za-z_]\w*)\s*,")
ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*[^=].*;\s*$")

def _find_matching_close(lines, open_line_idx, open_col):
    depth = 0
    for li in range(open_line_idx, len(lines)):
        start_col = open_col if li == open_line_idx else 0
        line = lines[li]
        for ci in range(start_col, len(line)):
            ch = line[ci]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return li, ci
    return len(lines) - 1, 0

def find_if_else_blocks(lines):
    i = 0
    n = len(lines)
    while i < n:
        m = re.search(r"\bif\s*\(", lines[i])
        if not m:
            i += 1
            continue
        j = i
        open_col = None
        while j < n:
            pos = lines[j].find("{")
            if pos != -1:
                open_col = pos
                break
            j += 1
        if j >= n:
            i += 1
            continue
        if_body_start = j
        close_li, close_col = _find_matching_close(lines, j, open_col)
        if_body_end = close_li

        rest_of_line = lines[close_li][close_col + 1:]
        else_line_idx = None
        if re.match(r"\s*else\b", rest_of_line):
            else_line_idx = close_li
        else:
            look = close_li + 1
            while look < n and lines[look].strip() == "":
                look += 1
            if look < n and lines[look].strip().startswith("else"):
                else_line_idx = look

        if else_line_idx is not None:
            e = else_line_idx
            e_open_col = None
            while e < n:
                pos = lines[e].find("{")
                if pos != -1:
                    e_open_col = pos
                    break
                e += 1
            if e < n:
                else_body_start = e
                eclose_li, _ = _find_matching_close(lines, e, e_open_col)
                else_body_end = eclose_li
                yield (if_body_start, if_body_end, else_body_start, else_body_end)
        i += 1

def detect_candidates(filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    candidates = []
    for (if_s, if_e, else_s, else_e) in find_if_else_blocks(lines):
        if_branch = lines[if_s:if_e + 1]
        else_branch = lines[else_s:else_e + 1]

        if_assigns = {m.group(1) for ln in if_branch
                     if (m := ASSIGN_RE.match(ln))}
        else_assigns = {m.group(1) for ln in else_branch
                       if (m := ASSIGN_RE.match(ln))}
        shared = if_assigns & else_assigns
        if not shared:
            continue

        if_aligned = {m.group(1) for ln in if_branch
                     if (m := ALIGN_CALL_RE.search(ln))}
        else_aligned = {m.group(1) for ln in else_branch
                       if (m := ALIGN_CALL_RE.search(ln))}

        for var in shared:
            in_if = var in if_aligned
            in_else = var in else_aligned
            if in_if == in_else:
                continue

            after_start = else_e + 1
            after_window = lines[after_start:after_start + 5]
            already_fixed = any(
                ALIGN_CALL_RE.search(ln) and
                re.search(r"\b%s\b" % re.escape(var), ln)
                for ln in after_window)
            if already_fixed:
                continue

            missing_branch = "else" if in_if else "if"
            candidates.append({
                "if_line": if_s + 1,
                "else_line": else_s + 1,
                "block_end_line": else_e + 1,
                "variable": var,
                "missing_branch": missing_branch,
                "if_snippet": lines[if_s].strip()[:90],
                "_span": else_e - if_s,  # used for dedup, stripped before output
            })

    best = {}
    for c in candidates:
        key = c["variable"]
        if key not in best or c["_span"] < best[key]["_span"]:
            best[key] = c
    for c in best.values():
        del c["_span"]
    return list(best.values())

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--buggy-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    results = {}
    for path in sorted(glob.glob(os.path.join(args.buggy_dir, "*.c"))):
        fname = os.path.basename(path)
        cands = detect_candidates(path)
        if cands:
            results[fname] = cands

    with open(args.out, "w") as f:
        json.dump(results, f, indent=1)

    total = sum(len(v) for v in results.values())
    print(f"Flagged {total} candidate sites across {len(results)} files")
    for fname, cands in results.items():
        print(f"  {fname}: {len(cands)}")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
