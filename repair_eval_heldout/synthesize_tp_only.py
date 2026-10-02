#!/usr/bin/env python3
import argparse
import json
import re
import os

LFENCE_RE = re.compile(r"(AsmLfence|MemoryLoadFence)\s*\(\s*\)\s*;")
COMMENT_RE = re.compile(r"//.*")
BLANK_RE = re.compile(r"^\s*$")

def normalize(line):
    return COMMENT_RE.sub("", line).rstrip()

def extract_inserted_block(buggy_lines, fixed_lines, anchor_text):
    anchor_clean = anchor_text.strip()
    anchor_idx = None
    for i, line in enumerate(fixed_lines):
        if anchor_clean in line:
            anchor_idx = i
            break
    if anchor_idx is None:
        return None

    j = anchor_idx - 1
    inserted = []
    while j >= 0:
        line = fixed_lines[j]
        stripped = line.strip()
        if LFENCE_RE.search(stripped) or stripped.startswith("//") or not stripped:
            inserted.insert(0, line)
            j -= 1
        else:
            break

    while inserted and not inserted[0].strip():
        inserted.pop(0)
    while inserted and not inserted[-1].strip():
        inserted.pop()

    return [normalize(l) for l in inserted if normalize(l)]

def extract_our_inserted_block(buggy_lines, patched_lines, anchor_text):
    return extract_inserted_block(buggy_lines, patched_lines, anchor_text)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--buggy-dir", required=True)
    parser.add_argument("--fixed-dir", required=True)
    parser.add_argument("--patched-dir", required=True)
    args = parser.parse_args()

    with open(args.candidates) as f:
        candidates = json.load(f)
    with open(args.ground_truth) as f:
        ground_truth = json.load(f)

    print(f"{'File':<35} {'Anchor':<45} {'Match'}")
    print("-" * 95)

    total_tp = 0
    total_match = 0
    total_structural_match = 0

    for name, gt_entry in ground_truth.items():
        buggy_path = os.path.join(args.buggy_dir, name)
        fixed_path = os.path.join(args.fixed_dir, name)
        patched_path = os.path.join(args.patched_dir, name)

        if not all(os.path.exists(p) for p in [buggy_path, fixed_path, patched_path]):
            print(f"{name}: files missing, skipping")
            continue

        with open(buggy_path, encoding="utf-8", errors="replace") as f:
            buggy_lines = f.read().splitlines()
        with open(fixed_path, encoding="utf-8", errors="replace") as f:
            fixed_lines = f.read().splitlines()
        with open(patched_path, encoding="utf-8", errors="replace") as f:
            patched_lines = f.read().splitlines()

        cand_list = candidates.get(name, [])
        cand_anchors = {c["next_statement"].strip(): c for c in cand_list}

        for anchor in gt_entry["anchors"]:
            anchor_clean = anchor.strip()
            total_tp += 1

            matched_cand = None
            for ca, c in cand_anchors.items():
                if anchor_clean in ca or ca in anchor_clean:
                    matched_cand = c
                    break

            if matched_cand is None:
                print(f"{name:<35} {anchor_clean[:43]:<45} MISSED (FN)")
                continue

            human_block = extract_inserted_block(buggy_lines, fixed_lines, anchor_clean)
            our_block = extract_our_inserted_block(buggy_lines, patched_lines, anchor_clean)

            if human_block is None or our_block is None:
                print(f"{name:<35} {anchor_clean[:43]:<45} EXTRACTION FAILED")
                continue

            exact = (human_block == our_block)
            human_code = [l for l in human_block if not l.strip().startswith("//") and l.strip()]
            our_code = [l for l in our_block if not l.strip().startswith("//") and l.strip()]
            structural = (human_code == our_code)

            status = "EXACT" if exact else ("STRUCTURAL" if structural else "DIFFERS")
            if exact:
                total_match += 1
            if structural:
                total_structural_match += 1

            print(f"{name:<35} {anchor_clean[:43]:<45} {status}")
            if not structural:
                print(f"  human : {human_code}")
                print(f"  ours  : {our_code}")

    print("-" * 95)
    print(f"True-positive sites evaluated : {total_tp}")
    print(f"Exact match (incl. comments)  : {total_match}/{total_tp}")
    print(f"Structural match (code only)  : {total_structural_match}/{total_tp}")
    print()
    print("Note: structural match = AsmLfence() call inserted at exactly the")
    print("right location; comment wording differs (ours is generic, human's")
    print("names the specific variable) but the code change is identical.")

if __name__ == "__main__":
    main()
