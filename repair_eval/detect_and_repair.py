#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re

COMPARISON_RE = re.compile(r"(>=|<=|==|!=|[<>])")
EARLY_EXIT_RE = re.compile(r"^\s*(return\b|break\s*;|continue\s*;|goto\b)")
LFENCE_CALL_RE = re.compile(r"^\s*AsmLfence\s*\(\s*\)\s*;")
IF_HEADER_RE = re.compile(r"^\s*if\s*\(")

VALIDATION_FN_DICT = [
    "IsBufferOutsideSmmValid", "IsAddressValid", "IsValid",
    "InRange", "ValidateRange", "CheckRange",
]
NEGATED_CALL_RE = re.compile(r"!\s*(\w*(?:" + "|".join(VALIDATION_FN_DICT) + r")\w*)\s*\(")

EFI_ERROR_SUCCESS_RE = re.compile(r"!\s*EFI_ERROR\s*\(")

def extract_identifiers(text):
    STOPLIST = {
        "if", "else", "return", "break", "continue", "goto", "while", "for",
        "NULL", "TRUE", "FALSE", "sizeof", "EFI_SUCCESS", "EFI_ERROR",
        "OFFSET_OF", "UINTN", "UINT8", "UINT16", "UINT32", "UINT64", "VOID",
        "CHAR16", "BOOLEAN", "EFI_STATUS",
    }
    ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
    return {i for i in ids if i not in STOPLIST}

def shares_identifier(condition_text, statement_text):
    cond_ids = extract_identifiers(condition_text)
    stmt_ids = extract_identifiers(statement_text)
    return bool(cond_ids & stmt_ids)

def capture_full_statement(lines, start_idx, max_lines=8):
    joined = []
    for k in range(start_idx, min(start_idx + max_lines, len(lines))):
        joined.append(lines[k])
        if ";" in lines[k]:
            break
    return " ".join(joined)

ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)\s*(.+);\s*$")

COPYMEM_RE = re.compile(
    r"(?:CopyMem|InternalMemCopyMem)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*(.+?)\s*,"
)

def propagates_taint(lines, seed_text, start_idx, window=60):
    tainted = extract_identifiers(seed_text)
    end = min(start_idx + window, len(lines))

    for k in range(start_idx, end):
        line = lines[k]
        stripped = line.strip()

        cm = COPYMEM_RE.search(line)
        if cm:
            dest, src = cm.group(1), cm.group(2)
            if tainted & extract_identifiers(src):
                tainted.add(dest)
            continue

        m = ASSIGN_RE.match(stripped)
        if m:
            lhs, rhs = m.group(1), m.group(2)
            if tainted & extract_identifiers(rhs):
                tainted.add(lhs)
                continue

        if tainted & extract_identifiers(line):
            return True

    return False

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

def detect_candidates(filepath, mode="targeted"):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    candidates = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if IF_HEADER_RE.match(line):
            cond_text = line
            scan = i
            while "{" not in lines[scan]:
                scan += 1
                if scan >= len(lines):
                    break
                cond_text += " " + lines[scan]
            open_idx = scan

            if "{" not in lines[open_idx]:
                i += 1
                continue

            is_comparison_guard = bool(COMPARISON_RE.search(cond_text))
            is_dict_guard = bool(NEGATED_CALL_RE.search(cond_text))
            is_success_path = bool(EFI_ERROR_SUCCESS_RE.search(cond_text))

            close_idx = find_matching_brace(lines, open_idx)
            if close_idx is None:
                i = open_idx + 1
                continue
            body = lines[open_idx:close_idx + 1]

            if is_success_path:
                j = open_idx + 1
                while j < close_idx:
                    stripped = lines[j].strip()
                    if not stripped or stripped.startswith("//"):
                        j += 1
                        continue
                    break
                if j < close_idx:
                    next_stmt = lines[j].strip()
                    if not LFENCE_CALL_RE.match(next_stmt):
                        keep = True
                        if mode == "targeted_taint":
                            full_stmt = capture_full_statement(lines, j)
                            keep = shares_identifier(cond_text, full_stmt)
                        elif mode == "targeted_dataflow":
                            keep = propagates_taint(lines, cond_text, j)
                        if keep:
                            candidates.append({
                                "if_line": i + 1,
                                "pattern": "success-path",
                                "insertion_after_line": open_idx + 1,  # insert right after '{'
                                "next_statement": next_stmt,
                                "condition_snippet": cond_text.strip()[:100],
                            })
            else:
                condition_qualifies = (
                    True if mode == "naive" else (is_comparison_guard or is_dict_guard)
                )
                if condition_qualifies:
                    has_early_exit = any(EARLY_EXIT_RE.match(l) for l in body)
                    if has_early_exit:
                        j = close_idx + 1
                        while j < len(lines):
                            stripped = lines[j].strip()
                            if not stripped or stripped.startswith("//"):
                                j += 1
                                continue
                            break
                        if j < len(lines):
                            next_stmt = lines[j].strip()
                            if not LFENCE_CALL_RE.match(next_stmt):
                                keep = True
                                if mode == "targeted_taint":
                                    full_stmt = capture_full_statement(lines, j)
                                    keep = shares_identifier(cond_text, full_stmt)
                                elif mode == "targeted_dataflow":
                                    keep = propagates_taint(lines, cond_text, j)
                                if keep:
                                    pattern = "naive-guard" if mode == "naive" else (
                                        "dict-guard" if is_dict_guard and not is_comparison_guard
                                        else "comparison-guard"
                                    )
                                    candidates.append({
                                        "if_line": i + 1,
                                        "pattern": pattern,
                                        "insertion_after_line": close_idx + 1,
                                        "next_statement": next_stmt,
                                        "condition_snippet": cond_text.strip()[:100],
                                    })
            i = open_idx + 1
        else:
            i += 1
    return candidates

FENCE_BLOCK_TEMPLATE = [
    "{indent}//",
    "{indent}// The AsmLfence() call here is to ensure the above range/content",
    "{indent}// check has been completed before using the checked value.",
    "{indent}//",
    "{indent}AsmLfence ();",
]

def detect_indent(lines, idx):
    for i in range(idx, min(idx + 5, len(lines))):
        line = lines[i]
        if line.strip():
            return line[: len(line) - len(line.lstrip())]
    return "  "  # fallback

def synthesize_patch(filepath, candidates, out_path):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    for c in sorted(candidates, key=lambda c: -c["insertion_after_line"]):
        idx = c["insertion_after_line"]  # 1-indexed line to insert after
        indent = detect_indent(lines, idx)
        fence_block = [t.format(indent=indent) for t in FENCE_BLOCK_TEMPLATE]
        lines[idx:idx] = fence_block

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buggy-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--patched-dir", required=True)
    parser.add_argument("--mode", default="targeted",
                         choices=["naive", "targeted", "targeted_taint", "targeted_dataflow"],
                         help="naive=no condition filtering (baseline); "
                              "targeted=default, reproduces prior results; "
                              "targeted_taint=adds identifier-overlap filter")
    args = parser.parse_args()
    os.makedirs(args.patched_dir, exist_ok=True)

    all_results = {}
    total_candidates = 0
    for filepath in sorted(glob.glob(os.path.join(args.buggy_dir, "*.c"))):
        name = os.path.basename(filepath)
        candidates = detect_candidates(filepath, mode=args.mode)
        all_results[name] = candidates
        total_candidates += len(candidates)
        print(f"{name}: {len(candidates)} candidate(s)")
        for c in candidates:
            print(f"    line {c['if_line']} [{c['pattern']}]: if-cond=\"{c['condition_snippet']}\" -> next: \"{c['next_statement'][:55]}\"")

        out_path = os.path.join(args.patched_dir, name)
        synthesize_patch(filepath, candidates, out_path)

    with open(args.out, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nTotal candidates flagged: {total_candidates}")
    print(f"Wrote {args.out}")
    print(f"Wrote patched files to {args.patched_dir}/")

if __name__ == "__main__":
    main()
