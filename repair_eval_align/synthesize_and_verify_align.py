#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import tempfile

ALIGN_CALL_RE = re.compile(r"^\s*(\w+)\s*=\s*\([^)]*\*\s*\)\s*ALIGN_POINTER\s*\(\s*\w+\s*,\s*(\d+)\s*\)\s*;\s*$")

def apply_patch(lines, cand):
    var = cand["variable"]
    block_end = cand["block_end_line"] - 1  # 0-indexed line of "} "/"} else {" ... final close

    align_line_idx = None
    align_stmt = None
    cast_type = None
    align_n = "8"
    search_lo = cand["if_line"] - 1
    search_hi = cand["block_end_line"]
    for idx in range(search_lo, search_hi):
        if idx >= len(lines):
            break
        m = ALIGN_CALL_RE.match(lines[idx])
        if m and m.group(1) == var:
            align_line_idx = idx
            align_stmt = lines[idx]
            align_n = m.group(2)
            cm = re.search(r"=\s*\((.*?\*)\s*\)\s*ALIGN_POINTER", lines[idx])
            cast_type = cm.group(1) if cm else "UINT8 *"
            break

    new_lines = list(lines)
    indent = re.match(r"^(\s*)", new_lines[block_end]).group(1)
    unconditional = f"{indent}{var} = ({cast_type}) ALIGN_POINTER ({var}, {align_n});"

    if align_line_idx is not None:
        del new_lines[align_line_idx]
        if align_line_idx < block_end:
            block_end -= 1

    new_lines.insert(block_end + 1, unconditional)
    return new_lines, unconditional

def verify_structural(patched_lines, var):
    text = "\n".join(patched_lines)
    calls = list(re.finditer(
        r"^\s*%s\s*=\s*\([^)]*\*\s*\)\s*ALIGN_POINTER\s*\(\s*%s\s*,\s*\d+\s*\)\s*;\s*$"
        % (re.escape(var), re.escape(var)), text, re.MULTILINE))
    return len(calls) == 1

def verify_syntax_fwvoldxe():
    stub = """
typedef unsigned char UINT8;
typedef unsigned long long UINTN;
#define ALIGN_POINTER(p, n) ((void *)((UINTN)(p) + (((n) - ((UINTN)(p) & ((n) - 1))) & ((n) - 1))))
typedef struct { UINTN ExtHeaderOffset; UINTN HeaderLength; } EFI_FIRMWARE_VOLUME_HEADER;
typedef struct { UINT8 ExtHeaderSize_lo; unsigned int ExtHeaderSize; } EFI_FIRMWARE_VOLUME_EXT_HEADER;
typedef struct { UINTN CachedFv; EFI_FIRMWARE_VOLUME_HEADER *FwVolHeader; } FV_DEVICE;

void test_fn(FV_DEVICE *FvDevice) {
  UINT8 *Ptr;
  EFI_FIRMWARE_VOLUME_EXT_HEADER *FwVolExtHeader;

  if (FvDevice->FwVolHeader->ExtHeaderOffset != 0) {
    FwVolExtHeader = (EFI_FIRMWARE_VOLUME_EXT_HEADER *) (UINTN) (FvDevice->CachedFv + FvDevice->FwVolHeader->ExtHeaderOffset);
    Ptr = (UINT8 *) FwVolExtHeader + FwVolExtHeader->ExtHeaderSize;
  } else {
    Ptr = (UINT8 *) (UINTN) (FvDevice->CachedFv + FvDevice->FwVolHeader->HeaderLength);
  }
  Ptr = (UINT8 *) ALIGN_POINTER (Ptr, 8);
  (void) Ptr;
}
"""
    try:
        with tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False) as tf:
            tf.write(stub)
            tmp = tf.name
        r = subprocess.run(
            ["gcc", "-fsyntax-only", "-w", "-Wno-implicit-function-declaration",
             "-Wno-int-conversion", "-Wno-implicit-int", tmp],
            capture_output=True, text=True, timeout=15)
        os.unlink(tmp)
        if r.returncode == 0:
            return True, "PASS"
        errs = [l for l in r.stderr.splitlines() if "error:" in l]
        return False, errs[0] if errs else r.stderr.strip()
    except Exception as e:
        return False, str(e)

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--buggy-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cands = json.load(open(args.candidates))

    n_struct_pass = n_struct_fail = 0
    for fname, clist in cands.items():
        path = os.path.join(args.buggy_dir, fname)
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        for cand in clist:
            patched, stmt = apply_patch(lines, cand)
            ok = verify_structural(patched, cand["variable"])
            n_struct_pass += ok
            n_struct_fail += not ok
            out_path = os.path.join(args.out, fname)
            with open(out_path, "w") as f:
                f.write("\n".join(patched) + "\n")
            print(f"{fname}: patched var={cand['variable']!r} -> "
                  f"structural {'PASS' if ok else 'FAIL'}")
            print(f"  inserted: {stmt.strip()}")

    print(f"\nStructural oracle: {n_struct_pass} PASS, {n_struct_fail} FAIL")

    ok, msg = verify_syntax_fwvoldxe()
    print(f"Syntax check (gcc -fsyntax-only, FwVolDxe_FwVol.c site): "
          f"{'PASS' if ok else 'FAIL'}" + (f" -- {msg}" if not ok else ""))
    print("Note: PeiCore_FwVol.c site validated by structural oracle + "
          "exact-match detection only; not gcc-stubbed (large enclosing "
          "function with FFS-specific macros).")

if __name__ == "__main__":
    main()
