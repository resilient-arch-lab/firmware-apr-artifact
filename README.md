# From Silicon to Boot Code: Artifact

Reproduction package for:

Maisha Mastora and Dean Sullivan. *From Silicon to Boot Code: Extending
Automated Program Repair to Firmware-Layer Security Workarounds.*
1st International Workshop on Firmware Testing and Analysis (FTA '26),
October 4-9, 2026, Oakland, CA, USA.

Preprint: https://arxiv.org/abs/2609.01769
(This link will be updated to the ACM proceedings version once it is live.)

This artifact reproduces every quantitative result in the paper: the
commit-mining backport table, the five-family localization table, the
Spectre v1 ablation and held-out generalization test, the synthesis
correctness check, the precision-filter analysis, the HOB non-circular
oracle (structural check plus `gcc -fsyntax-only`), and the patch
propagation experiment.

## What this studies

The paper introduces a firmware **repair dictionary**. Each entry is a
triple (bug signature, repair template, validation oracle), the firmware
analogue of a mutation operator in RTL automated program repair. A miner
discovers candidate entries from real EDK II CVE-fix history, and a
detector implements each entry to localize vulnerable sites and synthesize
patches. Five entries are included, spanning C and x86 assembly.

## Requirements

- `python3` (3.8 or newer). No third-party Python packages are needed.
- `git`
- `gcc` (used only by the HOB entry's syntax-check oracle)

The scripts read the EDK II git history. Buggy and fixed source files are
extracted from specific historical commits (recorded in each
`sites.txt`), so the exact input files are pinned and do not depend on the
current state of the upstream repository.

## Quick start

```bash
bash run_all.sh                 # clones edk2 into ./edk2 if not present, then runs everything
# or, if you already have a clone:
bash run_all.sh /path/to/edk2
```

Invoking with `bash run_all.sh` works regardless of the file's execute bit.
If you prefer `./run_all.sh`, first run `chmod +x run_all.sh`.

The clone uses `--filter=blob:none`, which fetches history without all file
blobs and takes roughly a minute. The full run completes in a few minutes;
the detectors themselves run in well under one second each (see the runtime
table in the paper).

Reproducibility note: the exact buggy and fixed source files are pinned by
commit hash in each family's `sites.txt` and fetched with `git show`, so a
downloader gets byte-identical inputs regardless of the state of edk2's HEAD
at clone time. Pinning edk2 as a git submodule at a fixed commit is an
alternative way to achieve the same guarantee.

## Layout

```
run_all.sh                     one command reproduces every table
scripts/
  mine_fix_templates.py        automated fix-template miner (Table 1 + recovery check)
repair_eval/                   Spectre v1 (CVE-2017-5753), C
  detect_and_repair.py           localizer + synthesizer, --mode {naive,targeted,targeted_taint,targeted_dataflow}
  synthesize_tp_only.py          per-site synthesis correctness (7/7 exact)
  dataflow_precision_analysis.py precision-filter experiment
  evaluate.py, extract_sites.py, extract_ground_truth.py
repair_eval_heldout/           Spectre v1 held-out (4 unseen files, 3-10x larger)
repair_eval_decompress/        decompression bounds-check family, C
repair_eval_rsb/               RSB stuffing (CVE-2017-5715), x86 assembly
repair_eval_hob/               HOB integer overflow (miner-discovered), C
  detect_hob_overflow.py         localizer + synthesizer + structural oracle + gcc syntax check
repair_eval_align/             fifth entry: conditional-only pointer alignment (CVE-2018-3630)
propagation_test/              patch propagation across 4 stable branches
ablation/                      pre-computed candidate sets for the four filter modes
data/                          mined cluster output and the site-cost CSV
```

Each family directory follows the same pattern: `extract_*_sites.py` pulls
the buggy and fixed files from the pinned commits, `detect_*.py` localizes
and synthesizes, `extract_*_ground_truth.py` derives ground truth
mechanically from the fixed files, and `evaluate_*.py` scores recall and
precision.

## Expected results

| Family | Language | Recall | Precision |
|---|---|---|---|
| Spectre v1 (training) | C | 100% | 9.7% |
| Spectre v1 (held-out) | C | 100% | 2.1% |
| Decompression | C | 100% | 15.5% |
| RSB stuffing | x86 asm | 100% | 100% |
| HOB overflow | C | 100% | 100% |
| Alignment (fifth entry) | C | 100% | 100% |

The run also reproduces Table 2b (naive baselines: 0/110 and 1/159 candidates
recalling 0% and 14.3%) and Table 3 (false-positive root-cause triage, e.g.
78.0% no-memory-use on the Spectre v1 training set).

Other checks the run prints: all three known CVE campaigns RECOVERED by the
miner without being named; the lexical-taint filter dropping recall to
71.4% (a deliberate negative result); synthesis 7/7 exact on training
sites; the HOB structural oracle and `gcc -fsyntax-only` both 3/3 PASS.

## Two notes on environment sensitivity

1. **Patch propagation, strategies A and B.** The propagation experiment
   reports three strategies. Strategy C (independent re-detection per
   branch) reproduces identically everywhere and is the robust result:
   4/4 branches. Strategies A and B (direct and fuzzy `patch(1)`
   application) depend on the exact byte layout of the synthesized patch,
   which can differ slightly between environments, so they may show 0/4 or
   4/4. The paper's claim rests on Strategy C.

2. **HOB syntax check on GCC 14+.** The HOB oracle compiles the extracted
   `CreateHob()` function with minimal type stubs. GCC 14 promotes some
   implicit-conversion diagnostics to hard errors that GCC 13 treats as
   warnings, so the detector passes suppression flags
   (`-Wno-int-conversion` and related) to keep the check portable across
   compiler versions. The structural oracle is compiler-independent.

## Data provenance

All inputs come from the public TianoCore EDK II repository
(`github.com/tianocore/edk2`). No proprietary firmware is included. The
commit hashes for every extracted file are listed in the `sites.txt` of
each family directory.
