#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sanitizer O0 vs O2 on LLM sources, with robust discovery + 'text file busy' fix.

Discovery order for LLM sources:
  1) <workspace>/<run_id>/gen/B{1..4}/**/*.c  (filesystem)
  2) <workspace>/<run_id>/logs/llm_manifest.json
  3) <workspace>/<run_id>/logs/build_results.jsonl

Outputs (timestamped, no overwrite): logs/opt_sweep_<YYYYmmdd_HHMMSS>/
  - opt_sweep_O0.jsonl, opt_sweep_O2.jsonl
  - opt_sweep_summary_<ts>.csv
"""
import argparse, json, os, re, shutil, subprocess, sys, hashlib, time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

EXTRA_LIBS = ["-lm"]

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

def san_flags(opt: str):
    of = "-O0" if opt=="O0" else "-O2"
    return [of, "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"] + EXTRA_LIBS

def detect_cc():
    clang = shutil.which("clang") or shutil.which("clang-18") or shutil.which("clang-16") or shutil.which("clang-14")
    gcc   = shutil.which("gcc")
    out=[]
    if clang: out.append(("clang", clang))
    if gcc:   out.append(("gcc", gcc))
    if not out:
        print("ERROR: no compilers found in PATH"); sys.exit(2)
    return out

def classify(out: str):
    kinds=set()
    if "ERROR: AddressSanitizer" in out: kinds.add("asan")
    if "runtime error:" in out: kinds.add("ubsan")
    return sorted(kinds)

def try_exec(bin_to_run: Path, cwd: Path, timeout: int, stdin: str):
    """
    Execute with small retries to dodge transient ETXTBUSY on some filesystems.
    """
    for attempt in range(5):
        try:
            return run([str(bin_to_run)], cwd=cwd, timeout=timeout, stdin=stdin)
        except OSError as e:
            if getattr(e, "errno", None) == 26:  # ETXTBUSY
                time.sleep(0.05 * (attempt + 1))
                continue
            raise
    # final try (let exception propagate if it fails again)
    return run([str(bin_to_run)], cwd=cwd, timeout=timeout, stdin=stdin)

def run_one(binpath: Path, rundir: Path, fixtures, timeout, uid: str):
    """
    Copy the built artifact to a private per-run path and execute that to avoid ETXTBUSY.
    """
    ensure_dir(rundir)
    # Copy binary to a unique, job-scoped path
    bin_copy = rundir / f"{binpath.name}-run-{uid}"
    try:
        shutil.copy2(binpath, bin_copy)
        os.chmod(bin_copy, 0o755)
    except Exception:
        # If copy fails, fall back to direct path (rare)
        bin_copy = binpath

    crashed=False; kinds=set(); first_rc=None; first_tail=None
    if not fixtures:
        fixtures = [None]  # single run with empty stdin

    for pf in fixtures:
        stdin_data = read_text(pf) if pf else ""
        pr = try_exec(bin_copy, rundir, timeout, stdin_data)
        out = pr.stdout or ""
        if first_rc is None:
            first_rc = pr.returncode; first_tail = out[-4000:]
        if ("ERROR: AddressSanitizer" in out) or ("runtime error:" in out) or (pr.returncode!=0):
            crashed=True; kinds.update(classify(out))
    return dict(asan_crash=int(crashed), asan_kinds=sorted(kinds),
                run_rc_first=first_rc, run_log_first_tail=first_tail)

def build_and_run(job):
    src = Path(job["src"]); ws=Path(job["ws"]); rid=job["rid"]
    cc_name=job["cc_name"]; cc_path=job["cc_path"]
    opt=job["opt"]; timeout=job["timeout"]; fixtures_dir=Path(job["fixtures_dir"])
    out_root = Path(job["out_root"]); uid=job["uid"]

    outdir = out_root/f"build_{opt}"/cc_name
    rundir = out_root/f"runs_{opt}"/cc_name
    ensure_dir(outdir); ensure_dir(rundir)

    binname=f"{src.stem}-{opt}"
    binpath=outdir/binname
    cmd=[cc_path,"-std=c11",str(src),"-o",str(binpath)]+san_flags(opt)
    p = run(cmd)
    rec={"src":str(src),"cc":cc_name,"opt":opt,"rc":p.returncode}
    if p.returncode!=0:
        rec["build_log_tail"]=(p.stdout or "")[-4000:]; return rec

    slug = llm_slug_from_path(src)
    seeds=[]
    s1 = fixtures_dir/f"{slug}.in"
    if s1.exists(): seeds.append(s1)
    seeds += sorted(fixtures_dir.glob(f"{slug}.in*"))

    res = run_one(binpath, rundir/slug, seeds, timeout, uid=uid)
    rec.update(res); return rec

def discover_llm_sources(ws: Path, rid: str):
    root = ws/rid
    candidates=set()
    gen_dir = root/"gen"
    if gen_dir.exists():
        for b in ("B1","B2","B3","B4"):
            for p in (gen_dir/b).rglob("*.c"):
                candidates.add(str(p))
    if candidates:
        print(f"[opt_sweep] Filesystem discovery found {len(candidates)} LLM sources under gen/")
        return sorted(candidates)
    logs = root/"logs"
    mp = logs/"llm_manifest.json"
    if mp.exists():
        try:
            m=json.loads(read_text(mp))
            for x in m:
                p = x.get("path")
                if p: candidates.add(p)
            if candidates:
                print(f"[opt_sweep] Manifest discovery found {len(candidates)} sources")
                return sorted(candidates)
        except Exception:
            pass
    rp = logs/"build_results.jsonl"
    if rp.exists():
        try:
            for line in read_text(rp).splitlines():
                if not line.strip(): continue
                r=json.loads(line)
                p=r.get("src") or r.get("label") or ""
                if is_llm_path(p): candidates.add(p)
            if candidates:
                print(f"[opt_sweep] Results discovery found {len(candidates)} sources")
                return sorted(candidates)
        except Exception:
            pass
    return []

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--run_id", required=True)
    ap.add_argument("--fixtures_dir", required=True)
    ap.add_argument("--opt_levels", nargs="+", default=["O0","O2"], choices=["O0","O2"])
    ap.add_argument("--parallel", type=int, default=max(8,(os.cpu_count() or 8)))
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--limit", type=int, default=0)
    args=ap.parse_args()

    ws=Path(args.workspace).resolve(); rid=args.run_id
    logs = ws/rid/"logs"
    ensure_dir(logs)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_root = logs/f"opt_sweep_{ts}"
    ensure_dir(out_root)

    sources = discover_llm_sources(ws, rid)
    if args.limit and len(sources)>args.limit:
        sources = sources[:args.limit]
        print(f"[opt_sweep] Limiting to first {args.limit} LLM sources")
    if not sources:
        print("[opt_sweep] No LLM sources found via filesystem/manifest/results."); sys.exit(0)

    compilers = detect_cc()
    from tqdm import tqdm
    # stable uid per (src, opt, cc) to avoid name collisions
    def uid_for(src, opt, cc): return hashlib.sha1(f"{src}|{opt}|{cc}".encode()).hexdigest()[:10]

    out_jsonl = {opt: out_root/f"opt_sweep_{opt}.jsonl" for opt in args.opt_levels}
    for opt in args.opt_levels:
        jobs=[{"src":s,"cc_name":n,"cc_path":p,"opt":opt,
               "timeout":args.timeout,"fixtures_dir":args.fixtures_dir,
               "ws":str(ws),"rid":rid,"out_root":str(out_root),
               "uid": uid_for(s,opt,n)}
              for s in sources for (n,p) in compilers]
        with ProcessPoolExecutor(max_workers=args.parallel) as ex, open(out_jsonl[opt],"w",encoding="utf-8") as outf:
            for fut in tqdm(as_completed([ex.submit(build_and_run,j) for j in jobs]),
                            total=len(jobs), desc=f"Opt sweep {opt}"):
                r=fut.result(); outf.write(json.dumps(r)+"\n")

    # Summarize
    import pandas as pd
    rows=[]
    for opt in args.opt_levels:
        p=out_jsonl[opt]
        if not p.exists(): continue
        d=pd.DataFrame([json.loads(x) for x in read_text(p).splitlines() if x.strip()])
        if d.empty: continue
        for cc,g in d.groupby("cc"):
            tot=len(g); ok=int((g["rc"]==0).sum())
            hits=int(g.get("asan_crash",0).sum()) if "asan_crash" in g else 0
            rows.append({"opt":opt,"cc":cc,"build_ok":ok,"total":tot,"asan_hits":hits,
                         "asan_rate_%": round(100.0*hits/max(1,tot),2)})
    if rows:
        summary_path = out_root/f"opt_sweep_summary_{ts}.csv"
        pd.DataFrame(rows).to_csv(summary_path, index=False)
        print("[opt_sweep] Summary:", summary_path)
        print("Outputs at:", out_root)

if __name__=="__main__":
    main()

