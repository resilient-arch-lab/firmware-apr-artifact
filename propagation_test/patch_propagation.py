#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import tempfile

def run(cmd, cwd=None, input_text=None):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd,
                       input=input_text)
    return r.returncode, r.stdout, r.stderr

def make_unified_diff(src_path, dst_path, src_label="buggy", dst_label="patched"):
    rc, out, err = run(["diff", "-u", f"--label={src_label}",
                         f"--label={dst_label}", src_path, dst_path])
    return out  # diff returns 1 if files differ, that's expected

def strategy_a(branch_file, patch_text, tmp_dir):
    target = os.path.join(tmp_dir, "target.c")
    import shutil
    shutil.copy(branch_file, target)
    patch_file = os.path.join(tmp_dir, "patch.diff")
    with open(patch_file, "w") as f:
        f.write(patch_text)
    rc, out, err = run(["patch", "--no-backup-if-mismatch", "-p0",
                         target, patch_file], cwd=tmp_dir)
    return rc == 0, err.strip()

def strategy_b(branch_file, patch_text, tmp_dir):
    target = os.path.join(tmp_dir, "target_fuzz.c")
    import shutil
    shutil.copy(branch_file, target)
    patch_file = os.path.join(tmp_dir, "patch.diff")
    with open(patch_file, "w") as f:
        f.write(patch_text)
    rc, out, err = run(["patch", "--no-backup-if-mismatch", "--fuzz=3",
                         "-p0", target, patch_file], cwd=tmp_dir)
    return rc == 0, err.strip()

def strategy_c(branch_file, detector_path, tmp_dir):
    patched_dir = os.path.join(tmp_dir, "patched_c")
    os.makedirs(patched_dir, exist_ok=True)
    buggy_dir = os.path.join(tmp_dir, "buggy_c")
    os.makedirs(buggy_dir, exist_ok=True)
    import shutil
    name = os.path.basename(branch_file)
    shutil.copy(branch_file, os.path.join(buggy_dir, name))
    cand_file = os.path.join(tmp_dir, "cands_c.json")
    rc, out, err = run([sys.executable, detector_path,
                         "--buggy-dir", buggy_dir,
                         "--out", cand_file,
                         "--patched-dir", patched_dir,
                         "--mode", "targeted_dataflow"])
    if rc != 0:
        return False, err.strip()
    try:
        import json as _json
        cands = _json.load(open(cand_file))
        total = sum(len(v) for v in cands.values())
        return total > 0, f"{total} candidates found and patched"
    except Exception as e:
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--master-buggy", required=True)
    parser.add_argument("--master-patched", required=True)
    parser.add_argument("--branch-dir", required=True)
    parser.add_argument("--detector", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    patch_text = make_unified_diff(args.master_buggy, args.master_patched)

    branch_files = sorted(f for f in os.listdir(args.branch_dir)
                           if f.endswith(".c"))

    print(f"Patch generated from master: {patch_text.count('@@')} hunks")
    print(f"Testing propagation to {len(branch_files)} stable branch files\n")

    results = {}
    print(f"{'Branch file':<30} {'Strategy A':>12} {'Strategy B':>12} {'Strategy C':>12}")
    print("-" * 70)

    for branch_file in branch_files:
        branch_path = os.path.join(args.branch_dir, branch_file)
        with tempfile.TemporaryDirectory() as tmp:
            ok_a, msg_a = strategy_a(branch_path, patch_text, tmp)
            ok_b, msg_b = strategy_b(branch_path, patch_text, tmp)
            ok_c, msg_c = strategy_c(branch_path, args.detector, tmp)

        results[branch_file] = {
            "strategy_a_direct": ok_a,
            "strategy_b_fuzzy": ok_b,
            "strategy_c_redetect": ok_c,
            "msg_a": msg_a, "msg_b": msg_b, "msg_c": msg_c,
        }
        label_a = "PASS" if ok_a else "FAIL"
        label_b = "PASS" if ok_b else "FAIL"
        label_c = "PASS" if ok_c else "FAIL"
        print(f"{branch_file:<30} {label_a:>12} {label_b:>12} {label_c:>12}")
        if not ok_a and msg_a:
            print(f"  A fail: {msg_a[:70]}")
        if not ok_c:
            print(f"  C: {msg_c[:70]}")

    print("-" * 70)
    for strategy, key in [("A (direct)", "strategy_a_direct"),
                           ("B (fuzzy)", "strategy_b_fuzzy"),
                           ("C (re-detect)", "strategy_c_redetect")]:
        n = sum(1 for r in results.values() if r[key])
        print(f"Strategy {strategy}: {n}/{len(results)} PASS")

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nWrote {args.out}")

if __name__ == "__main__":
    main()
