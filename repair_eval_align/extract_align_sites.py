import argparse, os, subprocess

def run_git(repo, args):
    return subprocess.run(["git", "-C", repo] + args, capture_output=True, text=True, check=True).stdout

def parse_sites(path):
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            fix, parent, fp = line.split("|")
            out.append((fix, parent, fp))
    return out

def unique_name(fp, seen):
    base = os.path.basename(fp)
    if base not in seen:
        seen.add(base); return base
    return fp.split("/")[0] + "_" + base

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sites", required=True)
    args = ap.parse_args()
    here = os.path.dirname(os.path.abspath(args.sites)) or "."
    bdir, fdir = os.path.join(here, "buggy"), os.path.join(here, "fixed")
    os.makedirs(bdir, exist_ok=True); os.makedirs(fdir, exist_ok=True)
    seen = set()
    for fix, parent, fp in parse_sites(args.sites):
        name = unique_name(fp, seen)
        open(os.path.join(bdir, name), "w").write(run_git(args.repo, ["show", parent + ":" + fp]))
        open(os.path.join(fdir, name), "w").write(run_git(args.repo, ["show", fix + ":" + fp]))
        print(name + ": extracted")
    print("wrote buggy/ and fixed/ under " + here)

if __name__ == "__main__":
    main()
