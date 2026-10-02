#!/usr/bin/env python3
import argparse
import os
import subprocess

def run_git(repo, args):
    result = subprocess.run(["git", "-C", repo] + args, capture_output=True, text=True, check=True)
    return result.stdout

def parse_sites(path):
    sites = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            orig, parent, filepath = line.split("|")
            sites.append((orig, parent, filepath))
    return sites

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Path to local edk2 clone")
    parser.add_argument("--sites", required=True, help="Path to sites.txt")
    args = parser.parse_args()

    here = os.path.dirname(os.path.abspath(args.sites)) or "."
    buggy_dir = os.path.join(here, "buggy")
    fixed_dir = os.path.join(here, "fixed")
    os.makedirs(buggy_dir, exist_ok=True)
    os.makedirs(fixed_dir, exist_ok=True)

    sites = parse_sites(args.sites)
    for orig, parent, filepath in sites:
        name = os.path.basename(filepath)
        buggy_content = run_git(args.repo, ["show", f"{parent}:{filepath}"])
        fixed_content = run_git(args.repo, ["show", f"{orig}:{filepath}"])

        with open(os.path.join(buggy_dir, name), "w") as f:
            f.write(buggy_content)
        with open(os.path.join(fixed_dir, name), "w") as f:
            f.write(fixed_content)

        print(f"{name}: buggy {len(buggy_content.splitlines())} lines, "
              f"fixed {len(fixed_content.splitlines())} lines")

    print(f"\nWrote {len(sites)} buggy files to {buggy_dir}/")
    print(f"Wrote {len(sites)} fixed files to {fixed_dir}/")

if __name__ == "__main__":
    main()
