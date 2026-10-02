#!/usr/bin/env bash
#
# run_all.sh -- reproduce every result in the paper from a single command.
#
# Usage:
#   ./run_all.sh /path/to/edk2          (uses an existing edk2 clone)
#   ./run_all.sh                        (clones edk2 into ./edk2 if absent)
#
# Requirements: python3 (>=3.8), git, gcc. No Python packages needed.
#
set -euo pipefail

# ----------------------------------------------------------------------
# 0. Locate or clone edk2
# ----------------------------------------------------------------------
EDK2="${1:-./edk2}"
if [ ! -d "$EDK2/.git" ]; then
  echo ">> No edk2 clone at $EDK2 -- cloning (blob:none, ~1 min)..."
  git clone --filter=blob:none --no-checkout \
      https://github.com/tianocore/edk2.git "$EDK2"
fi
EDK2="$(cd "$EDK2" && pwd)"
echo ">> Using edk2 at: $EDK2"
echo

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

sep() { printf '\n========== %s ==========\n' "$1"; }

# ----------------------------------------------------------------------
# 1. Commit mining  (Table 1: backport cost)
# ----------------------------------------------------------------------
sep "Table 1  Commit mining / backport cost"
python3 scripts/mine_fix_templates.py --repo "$EDK2" \
        --min-cluster 2 --out data/fix_template_clusters.json | tail -12

# ----------------------------------------------------------------------
# 2. Spectre v1  (Table 2 rows: training + ablation)
# ----------------------------------------------------------------------
sep "Table 2  Spectre v1 (training sites + ablation)"
python3 repair_eval/extract_sites.py --repo "$EDK2" --sites repair_eval/sites.txt
python3 repair_eval/extract_ground_truth.py \
        --repo "$EDK2" --sites repair_eval/sites.txt \
        --out repair_eval/ground_truth.json
for MODE in naive targeted targeted_taint targeted_dataflow; do
  echo "-- mode: $MODE"
  python3 repair_eval/detect_and_repair.py \
          --buggy-dir repair_eval/buggy --out "repair_eval/cand_$MODE.json" \
          --patched-dir "/tmp/p_$MODE" --mode "$MODE" >/dev/null
  python3 repair_eval/evaluate.py \
          --candidates "repair_eval/cand_$MODE.json" \
          --ground-truth repair_eval/ground_truth.json | tail -2
done

# ----------------------------------------------------------------------
# 3. Spectre v1 held-out  (Table 2 held-out row + synthesis)
# ----------------------------------------------------------------------
sep "Table 2  Spectre v1 held-out + synthesis"
python3 repair_eval_heldout/extract_heldout_sites.py \
        --repo "$EDK2" --sites repair_eval_heldout/sites.txt
python3 repair_eval/detect_and_repair.py \
        --buggy-dir repair_eval_heldout/buggy \
        --out repair_eval_heldout/candidates.json \
        --patched-dir repair_eval_heldout/patched \
        --mode targeted_dataflow >/dev/null
python3 repair_eval/evaluate.py \
        --candidates repair_eval_heldout/candidates.json \
        --ground-truth repair_eval_heldout/ground_truth.json | tail -2
echo "-- synthesis correctness (training 7/7 expected):"
python3 repair_eval/synthesize_tp_only.py \
        --candidates repair_eval/cand_targeted_dataflow.json \
        --ground-truth repair_eval/ground_truth.json \
        --buggy-dir repair_eval/buggy --fixed-dir repair_eval/fixed \
        --patched-dir /tmp/p_targeted_dataflow | tail -4

# ----------------------------------------------------------------------
# 4. Precision analysis  (filter experiment)
# ----------------------------------------------------------------------
sep "Precision filter analysis (Discussion)"
python3 repair_eval/dataflow_precision_analysis.py \
        --candidates repair_eval/cand_targeted_dataflow.json \
        --ground-truth repair_eval/ground_truth.json \
        --buggy-dir repair_eval/buggy | tail -8

# ----------------------------------------------------------------------
# 5. Decompression  (Table 2 row)
# ----------------------------------------------------------------------
sep "Table 2  Decompression bounds-check"
python3 repair_eval_decompress/extract_decompress_sites.py \
        --repo "$EDK2" --sites repair_eval_decompress/sites.txt
python3 repair_eval_decompress/detect_missing_bounds_check.py \
        --buggy-dir repair_eval_decompress/buggy \
        --out repair_eval_decompress/candidates_bounds.json >/dev/null
python3 repair_eval_decompress/extract_decompress_ground_truth.py \
        --buggy-dir repair_eval_decompress/buggy \
        --fixed-dir repair_eval_decompress/fixed \
        --out repair_eval_decompress/ground_truth_bounds.json >/dev/null
python3 repair_eval_decompress/evaluate_bounds.py \
        --candidates repair_eval_decompress/candidates_bounds.json \
        --ground-truth repair_eval_decompress/ground_truth_bounds.json | tail -3

# ----------------------------------------------------------------------
# 6. RSB stuffing  (Table 2 row)
# ----------------------------------------------------------------------
sep "Table 2  RSB stuffing (x86 assembly)"
python3 repair_eval_rsb/extract_rsb_sites.py \
        --repo "$EDK2" --sites repair_eval_rsb/sites.txt
python3 repair_eval_rsb/detect_missing_stuffrsb.py \
        --buggy-dir repair_eval_rsb/buggy \
        --out repair_eval_rsb/candidates.json >/dev/null
python3 repair_eval_rsb/extract_rsb_ground_truth.py \
        --fixed-dir repair_eval_rsb/fixed \
        --out repair_eval_rsb/ground_truth.json >/dev/null
python3 repair_eval_rsb/evaluate_rsb.py \
        --candidates repair_eval_rsb/candidates.json \
        --ground-truth repair_eval_rsb/ground_truth.json \
        --buggy-dir repair_eval_rsb/buggy | tail -3

# ----------------------------------------------------------------------
# 7. HOB overflow  (Table 2 row + non-circular oracle + syntax check)
# ----------------------------------------------------------------------
sep "Table 2  HOB overflow (miner-discovered) + oracle + gcc syntax check"
python3 repair_eval_hob/extract_hob_sites.py \
        --repo "$EDK2" --sites repair_eval_hob/sites.txt
python3 repair_eval_hob/detect_hob_overflow.py \
        --buggy-dir repair_eval_hob/buggy \
        --out repair_eval_hob/candidates.json \
        --patched-dir repair_eval_hob/patched
python3 repair_eval_hob/extract_hob_ground_truth.py \
        --fixed-dir repair_eval_hob/fixed \
        --out repair_eval_hob/ground_truth.json >/dev/null
python3 repair_eval_hob/evaluate_hob.py \
        --candidates repair_eval_hob/candidates.json \
        --ground-truth repair_eval_hob/ground_truth.json | tail -3

# ----------------------------------------------------------------------
# 8. Patch propagation  (Table 3 experiment)
# ----------------------------------------------------------------------
sep "Patch propagation across stable branches"
python3 propagation_test/patch_propagation.py \
        --master-buggy repair_eval/buggy/FaultTolerantWriteSmm.c \
        --master-patched repair_eval/patched/FaultTolerantWriteSmm.c \
        --branch-dir propagation_test \
        --detector repair_eval/detect_and_repair.py \
        --out propagation_test/propagation_results.json | tail -6
echo "Note: Strategies A and B transplant a diff and are sensitive to branch"
echo "divergence across environments; Strategy C re-detects per branch and is"
echo "the robust result the paper's propagation claim relies on."

# ----------------------------------------------------------------------
# 9. Naive baseline comparison  (Table 2b)
# ----------------------------------------------------------------------
sep "Table 2b  Naive syntactic baselines vs. targeted detector"
python3 repair_eval/naive_baseline.py \
        --buggy-dir repair_eval/buggy \
        --ground-truth repair_eval/ground_truth.json --mode comparison-only | tail -2
python3 repair_eval/naive_baseline.py \
        --buggy-dir repair_eval/buggy \
        --ground-truth repair_eval/ground_truth.json --mode any-if | tail -2

# ----------------------------------------------------------------------
# 10. False-positive root-cause triage  (Table 3)
# ----------------------------------------------------------------------
sep "Table 3  False-positive root-cause triage"
echo "-- Spectre v1 (train):"
python3 repair_eval/triage_fp.py \
        --candidates repair_eval/cand_targeted_dataflow.json \
        --ground-truth repair_eval/ground_truth.json \
        --buggy-dir repair_eval/buggy | tail -7
echo "-- Spectre v1 (held-out):"
python3 repair_eval/triage_fp.py \
        --candidates repair_eval_heldout/candidates.json \
        --ground-truth repair_eval_heldout/ground_truth.json \
        --buggy-dir repair_eval_heldout/buggy | tail -7
echo "-- Decompression:"
python3 repair_eval_decompress/triage_decompress.py \
        --candidates repair_eval_decompress/candidates_bounds.json \
        --ground-truth repair_eval_decompress/ground_truth_bounds.json \
        --buggy-dir repair_eval_decompress/buggy | tail -8

# ----------------------------------------------------------------------
# 11. Fifth dictionary entry  (Section 4.4, alignment / CVE-2018-3630)
# ----------------------------------------------------------------------
sep "Section 4.4  Fifth entry: conditional-only pointer alignment"
python3 repair_eval_align/extract_align_sites.py \
        --repo "$EDK2" --sites repair_eval_align/sites.txt
python3 repair_eval_align/detect_missing_align.py \
        --buggy-dir repair_eval_align/buggy \
        --out repair_eval_align/candidates.json | tail -4
python3 repair_eval_align/synthesize_and_verify_align.py \
        --candidates repair_eval_align/candidates.json \
        --buggy-dir repair_eval_align/buggy \
        --out repair_eval_align/patched | tail -5

sep "DONE -- all results reproduced"
