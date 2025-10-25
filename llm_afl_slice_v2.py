#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AFL++ slice on LLM programs with long fuzz budgets and richer seeds.
- Primary: fuzz fixture-clean LLM targets (asan_crash==0) from build_results.jsonl
- Fallback: fuzz all LLM sources from logs/llm_manifest.json
- Optional: filter variants (B1..B4), limit count, choose seconds (600–1200)
- Logs are timestamped so previous runs are preserved

Outputs under logs/afl_slice_<ts>/:
  - afl_slice_<ts>.jsonl             (per-target results)
  - afl_slice_summary_<ts>.csv        (summary)
  - bins/, runs/                      (AFL bins & run dirs)

Example:
  python3 llm_afl_slice_v2.py \
    --workspace /var/lib/ansible/ashutosh/study \
    --run_id big_combo_v2 \
    --fixtures_dir /var/lib/ansible/ashutosh/fixtures \
    --seconds 900 \
    --parallel 320 \
    --variants B2,B4 \
    --limit 600
"""
import argparse, json, os, re, shutil, subprocess, sys, hashlib, random
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

def run(cmd, cwd=None, timeout=None, env=None, stdin=None):
    return subprocess.run(cmd, cwd=cwd, timeout=timeout, env=env,
                          input=stdin, text=True, encoding="utf-8", errors="ignore",
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)
def write_text(p: Path, s: str): ensure_dir(p.parent); p.write_text(s, encoding="utf-8")
def read_text(p: Path): return p.read_text(encoding="utf-8", errors="ignore")

def is_llm_path(s): s=s or ""; return ("/gen/" in s) or ("\\gen\\" in s)

def path_variant(s: str):
    m = re.search(r"/gen/(B[1-4])/", s or "")
    if not m: m = re.search(r"\\gen\\(B[1-4])\\", s or "")
    return m.group(1) if m else None

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
    # Match orchestrate's oracle (ASan/UBSan) so crashes are caught deterministically
    flags = ["-O1","-g","-fsanitize=address,undefined","-fno-omit-frame-pointer","-lm"]
    cmd = [cc, "-std=c11", str(src), "-o", str(binpath)] + flags
    p = run(cmd, env=dict(os.environ, AFL_DONT_OPTIMIZE="1"))
    return p.returncode, p.stdout, binpath

GENERIC_SEEDS = [
    "", "0\n", "1\n", "-1\n", "2 3 5 7\n", "0 0 0\n",
    "2147483647\n", "-2147483648\n", "4294967295\n", "9999999999\n",
    "aaaaaaaaaa\n", ("A"*128) + "\n", ("A"*1024) + "\n", ("A"*8192) + "\n",
    "%s%s%s%s\n", "%p%p%p%p\n", "%n\n", "../../../../../etc/passwd\n",
    "../" * 20 + "file\n", " \t \n", "NaN\n", "inf\n", "-inf\n"
]

def materialize_seeds(seed_dir: Path, fixture_seeds, rng: random.Random):
    if fixture_seeds:
        for i, s in enumerate(fixture_seeds):
            write_text(seed_dir / f"fx_{i:02d}.txt", read_text(s))
    else:
        # Drop a handful of generic seeds
        picks = GENERIC_SEEDS[:]
        rng.shuffle(picks)
        for i, s in enumerate(picks[:12]):  # cap to keep corpus small
            write_text(seed_dir / f"g_{i:02d}.txt", s)

def fuzz_one(job):
    """
    job: src, uid, ws, rid, fixtures_dir, seconds, out_root
    """
    src = Path(job["src"])
    ws = Path(job["ws"]); rid = job["rid"]
    out_root = Path(job["out_root"])
    out_base = out_root / "bins"
    run_base = out_root / "runs"
    fixtures_dir = Path(job["fixtures_dir"])
    seconds = int(job["seconds"])
    rng = random.Random(int(hashlib.sha1(str(job["uid"]).encode()).hexdigest(), 16))

    uid = job["uid"]; binname = f"{src.stem}-{uid}"
    rc, out, binpath = afl_compile(src, out_base/uid, binname)
    rec = {"src": str(src), "uid": uid, "afl_build_rc": rc}
    if rc != 0 or not binpath:
        rec["afl_build_tail"] = (out or "")[-4000:]
        return rec

    # Seed corpus
    slug = llm_slug_from_path(src)
    seeds = []
    single = fixtures_dir / f"{slug}.in"
    if single.exists(): seeds.append(single)
    seeds += sorted(fixtures_dir.glob(f"{slug}.in*"))
    in_dir = run_base/uid/"in"; out_dir = run_base/uid/"out"
    if out_dir.exists(): shutil.rmtree(out_dir)
    ensure_dir(in_dir)
    materialize_seeds(in_dir, seeds, rng)

    cmd = ["afl-fuzz","-i",str(in_dir),"-o",str(out_dir),"-V",str(seconds),"--",str(binpath),"@@"]
    env = dict(os.environ); env.setdefault("AFL_SKIP_CPUFREQ","1")
    _ = run(cmd, cwd=run_base/uid, env=env, timeout=seconds+30)

    crashes = 0
    cdir = out_dir/"default"/"crashes"
    if cdir.exists():
        crashes = len([p for p in cdir.iterdir() if p.name.startswith("id:")])
    rec.update({"afl_seconds": seconds, "afl_crashes": int(crashes)})
    return rec

def pick_targets_from_results(results_path: Path, variants_filter):
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
        if ac!=0: continue
        p = r.get("src") or r.get("label")
        if variants_filter:
            v = path_variant(p)
            if v not in variants_filter: continue
        clean.append(p)
    return san_rows, sorted(set(clean))

def pick_targets_from_manifest(logs_dir: Path, variants_filter):
    mp = logs_dir/"llm_manifest.json"
    if not mp.exists(): return []
    try:
        m = json.loads(read_text(mp))
        paths = []
        for x in m:
            p = x.get("path")
            if not p: continue
            if variants_filter:
                v = path_variant(p)
                if v not in variants_filter: continue
            paths.append(p)
        return sorted(set(paths))
    except Exception:
        return []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--run_id", required=True)
    ap.add_argument("--fixtures_dir", required=True)
    ap.add_argument("--seconds", type=int, default=600, help="Fuzz time per target (e.g., 600 or 1200)")
    ap.add_argument("--parallel", type=int, default=max(8,(os.cpu_count() or 8)))
    ap.add_argument("--limit", type=int, default=0, help="Optional cap on number of targets")
    ap.add_argument("--variants", default="", help="Optional comma list of LLM variants to include, e.g., B2,B4")
    args = ap.parse_args()

    logs = Path(args.workspace)/args.run_id/"logs"
    results_path = logs/"build_results.jsonl"
    if not results_path.exists():
        print("ERROR: cannot find", results_path); sys.exit(1)
    if not have_afl():
        print("ERROR: AFL++ not found (need afl-fuzz and afl-clang-fast/afl-gcc)"); sys.exit(2)

    variants_filter = set([v.strip() for v in args.variants.split(",") if v.strip()]) if args.variants else None

    # Timestamped output root (no overwrite)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_root = logs / f"afl_slice_{ts}"
    ensure_dir(out_root)

    # Pick targets (prefer fixture-clean, else manifest)
    san_rows, targets = pick_targets_from_results(results_path, variants_filter)
    if san_rows and targets:
        print(f"[AFL slice] Using fixture-clean LLM targets from results: {len(targets)}")
        selection = "fixture-clean"
    else:
        manifest_targets = pick_targets_from_manifest(logs, variants_filter)
        print(f"[AFL slice] No (usable) LLM san rows; falling back to manifest with {len(manifest_targets)} LLM sources.")
        targets = manifest_targets
        selection = "manifest-all"

    if args.limit and len(targets)>args.limit:
        targets = targets[:args.limit]
        print(f"[AFL slice] Limiting to first {args.limit} targets")

    if not targets:
        print("[AFL slice] No targets selected."); sys.exit(0)

    out_jsonl = out_root / f"afl_slice_{ts}.jsonl"
    out_csv   = out_root / f"afl_slice_summary_{ts}.csv"

    hits=0
    from tqdm import tqdm
    jobs=[]
    for src in targets:
        uid = hashlib.sha1(src.encode("utf-8")).hexdigest()[:10]
        jobs.append({"src": src, "uid": uid,
                     "ws": str(Path(args.workspace).resolve()), "rid": args.run_id,
                     "fixtures_dir": args.fixtures_dir, "seconds": args.seconds,
                     "out_root": str(out_root)})

    with ProcessPoolExecutor(max_workers=args.parallel) as ex, open(out_jsonl,"w",encoding="utf-8") as outf:
        futs = [ex.submit(fuzz_one, j) for j in jobs]
        for fut in tqdm(as_completed(futs), total=len(futs), desc="AFL slice (long)"):
            rec = fut.result()
            outf.write(json.dumps(rec)+"\n")
            if rec.get("afl_crashes",0)>0: hits += 1

    total = len(jobs)
    pct   = (100.0*hits/total) if total else 0.0

    # Summary CSV
    try:
        import pandas as pd
        pd.DataFrame([{
            "targets_fuzzed": total,
            "targets_with_≥1_crash": hits,
            "pct_targets_with_crash_%": round(pct,2),
            "afl_seconds": args.seconds,
            "selection": selection
        }]).to_csv(out_csv, index=False)
    except Exception:
        pass

    print(f"[AFL slice] Fuzzed {total} LLM targets; {hits} ({pct:.2f}%) produced ≥1 crash.")
    print("Summary:", out_csv)
    print("Runs  :", out_root / "runs")
    print("Bins  :", out_root / "bins")

if __name__ == "__main__":
    main()

