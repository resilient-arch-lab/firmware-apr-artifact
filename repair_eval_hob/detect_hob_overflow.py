#!/usr/bin/env python3
import argparse
import glob
import json
import os
import re
import subprocess

ALIGN_EXPR_RE = re.compile(
    r"\(\s*(\w+)\s*\+\s*0x7\s*\)\s*&\s*\(~0x7\)"
)

OVERFLOW_GUARD_RE = re.compile(
    r"if\s*\(\s*\w+\s*>\s*MAX_UINT16\s*-\s*0x7\s*\)"
)

COMMENT_RE = re.compile(r"^\s*//")

def detect_candidates(filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    candidates = []
    for i, line in enumerate(lines):
        m = ALIGN_EXPR_RE.search(line)
        if not m:
            continue
        hob_len_var = m.group(1)

        j = i - 1
        while j >= 0 and (not lines[j].strip() or COMMENT_RE.match(lines[j])):
            j -= 1

        if j < 0:
            preceding = ""
        else:
            preceding = lines[j].strip()

        already_guarded = bool(OVERFLOW_GUARD_RE.search(preceding))
        if not already_guarded:
            candidates.append({
                "line": i + 1,
                "variable": hob_len_var,
                "alignment_expr": line.strip(),
                "preceding_line": preceding,
                "insertion_before_line": i,  # 0-indexed: insert before this line
            })

    return candidates

def synthesize_patch(filepath, candidates, out_path):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    for c in sorted(candidates, key=lambda c: -c["insertion_before_line"]):
        idx = c["insertion_before_line"]
        var = c["variable"]
        align_line = lines[idx]
        indent = align_line[: len(align_line) - len(align_line.lstrip())]
        guard_block = [
            f"{indent}//",
            f"{indent}// Check {var} to avoid integer overflow in alignment.",
            f"{indent}//",
            f"{indent}if ({var} > MAX_UINT16 - 0x7) {{",
            f"{indent}  return NULL;",
            f"{indent}}}",
            f"{indent}",
        ]
        lines[idx:idx] = guard_block

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

def verify_structural(filepath):
    with open(filepath, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    passes, fails, details = 0, 0, []
    for i, line in enumerate(lines):
        m = ALIGN_EXPR_RE.search(line)
        if not m:
            continue
        hob_var = m.group(1)
        specific_guard_re = re.compile(
            r"if\s*\(\s*" + re.escape(hob_var) + r"\s*>\s*MAX_UINT16\s*-\s*0x7\s*\)"
        )
        window = lines[max(0, i-10):i]
        guarded = any(specific_guard_re.search(l) for l in window)
        if guarded:
            passes += 1
            details.append((i + 1, "PASS", line.strip()[:60]))
        else:
            fails += 1
            details.append((i + 1, "FAIL", line.strip()[:60]))
    return passes, fails, details

def verify_syntax(filepath):
    import tempfile, subprocess as _sp

    stubs = (
        "typedef unsigned char UINT8;\n"
        "typedef unsigned short UINT16;\n"
        "typedef unsigned int UINT32;\n"
        "typedef unsigned long long UINT64;\n"
        "typedef UINT64 UINTN;\n"
        "typedef void VOID;\n"
        "#define IN\n#define OUT\n#define CONST const\n#define EFIAPI\n"
        "#define TRUE 1\n#define FALSE 0\n#define NULL ((void*)0)\n"
        "#define ASSERT(x) ((void)(x))\n"
        "#define MAX_UINT16 ((UINT16)0xFFFF)\n"
        "#define EFI_HOB_TYPE_END_OF_HOB_LIST 0xFFFF\n"
        "typedef UINT64 EFI_PHYSICAL_ADDRESS;\n"
        "typedef struct { UINT16 HobType; UINT16 HobLength; UINT32 Reserved; }"
        " EFI_HOB_GENERIC_HEADER;\n"
        "typedef struct { EFI_HOB_GENERIC_HEADER Header; UINT32 Version;"
        " UINT32 BootMode; EFI_PHYSICAL_ADDRESS EfiFreeMemoryTop,"
        " EfiFreeMemoryBottom, EfiEndOfHobList, EfiMemoryBottom, EfiMemoryTop;"
        " } EFI_HOB_HANDOFF_INFO_TABLE;\n"
        "void* GetHobList(void);\n"
        "void* PrePeiGetHobList(void);\n"
        "void* MmGetHobList(void);\n"
    )

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            code = f.read()

        start_idx = code.find('CreateHob (')
        if start_idx == -1:
            start_idx = code.find('CreateHob(')
        if start_idx == -1:
            return None, "CreateHob() not found"

        ls = code.rfind('\n', 0, start_idx) + 1
        ls = code.rfind('\n', 0, max(0, ls - 1)) + 1

        brace_open = code.find('{', start_idx)
        if brace_open == -1:
            return None, "CreateHob() opening brace not found"

        depth = 0
        func_code = None
        for i in range(brace_open, len(code)):
            if code[i] == '{':
                depth += 1
            elif code[i] == '}':
                depth -= 1
                if depth == 0:
                    func_code = code[ls:i + 1]
                    break

        if func_code is None:
            return None, "CreateHob() closing brace not found"

        src = stubs + "\n" + func_code

        with tempfile.NamedTemporaryFile(suffix=".c", mode="w",
                                         delete=False) as tf:
            tf.write(src)
            tmp = tf.name

        r = _sp.run(["gcc", "-fsyntax-only", "-w", "-Wno-implicit-int", "-Wno-implicit-function-declaration", "-Wno-int-conversion", "-Wno-incompatible-pointer-types", "-Wno-return-type", tmp],
                    capture_output=True, text=True, timeout=15)
        os.unlink(tmp)

        if r.returncode == 0:
            return True, "CreateHob() passes gcc -fsyntax-only"
        errs = [l for l in r.stderr.splitlines() if "error:" in l]
        return False, errs[0] if errs else r.stderr.strip()

    except Exception as e:
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buggy-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--patched-dir", default=None,
                        help="If given, synthesize patches and run verifiers")
    args = parser.parse_args()

    if args.patched_dir:
        os.makedirs(args.patched_dir, exist_ok=True)

    all_results = {}
    total = 0
    for filepath in sorted(glob.glob(os.path.join(args.buggy_dir, "*.c"))):
        name = os.path.basename(filepath)
        candidates = detect_candidates(filepath)
        all_results[name] = candidates
        total += len(candidates)
        print(f"{name}: {len(candidates)} candidate(s)")
        for c in candidates:
            print(f"    line {c['line']}: {c['variable']} alignment, "
                  f"preceded by: \"{c['preceding_line'][:60]}\"")

        if args.patched_dir and candidates:
            out_path = os.path.join(args.patched_dir, name)
            synthesize_patch(filepath, candidates, out_path)

            p, f_, details = verify_structural(out_path)
            print(f"  Structural oracle: {p} PASS, {f_} FAIL")

            ok, msg = verify_syntax(out_path)
            print(f"  Syntax check (gcc -fsyntax-only): {'PASS' if ok else 'FAIL'}"
                  + (f" -- {msg}" if not ok else ""))

    with open(args.out, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nTotal candidates: {total}")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
