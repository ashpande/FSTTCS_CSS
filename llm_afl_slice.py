#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AFL++ slice on LLM programs.
Primary path: fuzz LLM targets that were fixture-clean under ASan (asan_crash==0) from build_results.jsonl.
Fallback: if no LLM san rows, read logs/llm_manifest.json and fuzz ALL LLM sources (optionally --limit N).
Outputs:
  logs/afl_slice.jsonl
  logs/afl_slice_summary.csv
"""
import argparse, json, os, shutil, subprocess, sys, hashlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

def run(cmd, cwd=None, timeout=None, env=None, stdin=None):
    return subprocess.run(cmd, cwd=cwd, timeout=timeout, env=env,
                          input=stdin, text=True, encoding="utf-8", errors="ignore",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)
def write_text(p: Path, s: str): ensure_dir(p.parent); p.write_text(s, encoding="utf-8")
def read_text(p: Path): return p.read_text(encoding="utf-8", errors="ignore")
def is_llm_path(s): s=s or ""; return ("/gen/" in s) or ("\\gen\\" in s)
def llm_slug_from_path(p: Path):
    n = p.stem
    return n.split("_", 1)[1] if "_" in n else n

def have_afl():
    return (shutil.which("afl-fuzz") is not None) and (shutil.which("afl-clang-fast") or shutil.which("afl-gcc"))

def afl_compile(src: Path, outdir: Path, binname: str):
    cc = shutil.which("afl-clang-fast") or shutil.which("afl-gcc")
    if not cc: return 1, "afl-cc not found", None
    ensure_dir(outdir)
    binpath = outdir / (binname + "-afl")
    flags = ["-O1","-g","-fsanitize=address,undefined","-fno-omit-frame-pointer","-lm"]
    cmd = [cc, "-std=c11", str(src), "-o", str(binpath)] + flags
    p = run(cmd, env=dict(os.environ, AFL_DONT_OPTIMIZE="1"))
    return p.returncode, p.stdout, binpath

def fuzz_one(job):
    src = Path(job["src"])
    ws = Path(job["ws"]); rid = job["rid"]
    out_base = ws / rid / "afl_slice" / "bins"
    run_base = ws / rid / "afl_slice" / "runs"
    fixtures_dir = Path(job["fixtures_dir"])
    seconds = int(job["seconds"])

    uid = job["uid"]; binname = f"{src.stem}-{uid}"
    rc, out, binpath = afl_compile(src, out_base/uid, binname)
    rec = {"src": str(src), "uid": uid, "afl_build_rc": rc}
    if rc != 0 or not binpath:
        rec["afl_build_tail"] = (out or "")[-4000:]
        return rec

    # seeds from fixtures/<slug>.in*
    slug = llm_slug_from_path(src)
    seeds = []
    single = fixtures_dir / f"{slug}.in"
    if single.exists(): seeds.append(single)
    seeds += sorted(fixtures_dir.glob(f"{slug}.in*"))
    in_dir = run_base/uid/"in"; out_dir = run_base/uid/"out"
    if out_dir.exists(): shutil.rmtree(out_dir)
    ensure_dir(in_dir)
    if not seeds:
        write_text(in_dir/"seed0", "")
    else:
        for i,s in enumerate(seeds):
            write_text(in_dir/f"seed{i}", read_text(s))

    cmd = ["afl-fuzz","-i",str(in_dir),"-o",str(out_dir),"-V",str(seconds),"--",str(binpath),"@@"]
    env = dict(os.environ); env.setdefault("AFL_SKIP_CPUFREQ","1")
    _ = run(cmd, cwd=run_base/uid, env=env, timeout=seconds+20)

    crashes = 0
    cdir = out_dir/"default"/"crashes"
    if cdir.exists():
        crashes = len([p for p in cdir.iterdir() if p.name.startswith("id:")])
    rec.update({"afl_seconds": seconds, "afl_crashes": int(crashes)})
    return rec

def pick_targets_from_results(results_path: Path):
    recs = []
    with open(results_path,"r",encoding="utf-8",errors="ignore") as f:
        for line in f:
            try: recs.append(json.loads(line))
            except: pass
    san_rows = [r for r in recs if r.get("profile")=="san" and is_llm_path((r.get("src") or r.get("label") or ""))]
    clean = []
    for r in san_rows:
        raw = r.get("asan_crash", 0)
        try: ac = int(raw)
        except: ac = 0 if str(raw).strip().lower() in ("","false","none") else 1
        if ac==0:
            clean.append(r.get("src") or r.get("label"))
    return san_rows, sorted(set(clean))

def pick_targets_from_manifest(logs_dir: Path):
    mp = logs_dir/"llm_manifest.json"
    if not mp.exists(): return []
    try:
        m = json.loads(read_text(mp))
        return sorted({x["path"] for x in m if "path" in x})
    except Exception:
        return []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--run_id", required=True)
    ap.add_argument("--fixtures_dir", required=True)
    ap.add_argument("--seconds", type=int, default=120)
    ap.add_argument("--parallel", type=int, default=max(8,(os.cpu_count() or 8)))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    logs = Path(args.workspace)/args.run_id/"logs"
    results_path = logs/"build_results.jsonl"
    if not results_path.exists():
        print("ERROR: cannot find", results_path); sys.exit(1)
    if not have_afl():
        print("ERROR: AFL++ not found (need afl-fuzz and afl-clang-fast/afl-gcc)"); sys.exit(2)

    san_rows, targets = pick_targets_from_results(results_path)
    if san_rows:
        print(f"[AFL slice] Using fixture-clean LLM targets from results: {len(targets)}")
    else:
        manifest_targets = pick_targets_from_manifest(logs)
        print(f"[AFL slice] No LLM san rows in results; falling back to manifest with {len(manifest_targets)} LLM sources.")
        targets = manifest_targets

    if args.limit and len(targets)>args.limit:
        targets = targets[:args.limit]
        print(f"[AFL slice] Limiting to first {args.limit} targets")

    from tqdm import tqdm
    jobs=[]
    for src in targets:
        uid = hashlib.sha1(src.encode("utf-8")).hexdigest()[:10]
        jobs.append({"src": src, "uid": uid,
                     "ws": str(Path(args.workspace).resolve()),
                     "rid": args.run_id, "fixtures_dir": args.fixtures_dir,
                     "seconds": args.seconds})

    out_jsonl = logs/"afl_slice.jsonl"
    out_csv   = logs/"afl_slice_summary.csv"

    hits=0
    with ProcessPoolExecutor(max_workers=args.parallel) as ex, open(out_jsonl,"w",encoding="utf-8") as outf:
        futs = [ex.submit(fuzz_one, j) for j in jobs]
        for fut in tqdm(as_completed(futs), total=len(futs), desc="AFL slice"):
            rec = fut.result()
            outf.write(json.dumps(rec)+"\n")
            if rec.get("afl_crashes",0)>0: hits += 1

    total=len(jobs)
    pct=(100.0*hits/total) if total else 0.0

    try:
        import pandas as pd
        pd.DataFrame([{
            "targets_fuzzed": total,
            "targets_with_≥1_crash": hits,
            "pct_targets_with_crash_%": round(pct,2),
            "afl_seconds": args.seconds,
            "selection": "fixture-clean" if san_rows else "manifest-all"
        }]).to_csv(out_csv, index=False)
    except Exception:
        pass

    print(f"[AFL slice] Fuzzed {total} LLM targets; {hits} ({pct:.2f}%) produced ≥1 crash.")
    print("Summary:", out_csv)

if __name__ == "__main__":
    main()

