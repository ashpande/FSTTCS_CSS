#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
jotai.py — Jotai-only runner (parallel, multi-input, math linking, separate logs)

What it does:
1) Deterministically sample N Jotai C files (or reuse a manifest).
2) Build each source with clang & gcc under 3 profiles:
   - baseline: -O2 -Wall -Wextra
   - hardened: -O2 -Wall -Wextra -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE -pie -Wl,-z,relro -Wl,-z,now -fstack-clash-protection
   - san:      -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
3) Always link with -lm (fixes sqrt/pow/etc).
4) Run sanitizer builds with multiple inputs (default: 0,1,2). Capture crashes/timeouts.
5) Progress via tqdm; per-source unique binary/run paths (no EBUSY); separate workspace/run_id.

Outputs (per run_id):
  workspace/run_id/
    build/cc/profile/<uid>/<bin>
    runs/cc/profile/<uid>/...
    logs/build_results.jsonl
    logs/jotai_manifest.txt
    logs/all_sources.txt
    logs/run_meta.json
"""

import argparse, os, sys, json, random, shutil, subprocess, time, hashlib
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed

# ---------- flags ----------
BASELINE = ["-O2", "-Wall", "-Wextra"]
HARDENED = ["-O2","-Wall","-Wextra",
            "-D_FORTIFY_SOURCE=3","-fstack-protector-strong","-fPIE","-pie",
            "-Wl,-z,relro","-Wl,-z,now","-fstack-clash-protection"]
SAN = ["-O1","-g","-fsanitize=address,undefined","-fno-omit-frame-pointer"]

EXTRA_LINK_LIBS = ["-lm"]  # <-- key fix for Jotai

# ---------- utils ----------
def run(cmd, cwd=None, timeout=None):
    return subprocess.run(cmd, cwd=cwd, timeout=timeout, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def write_text(p: Path, s: str):
    ensure_dir(p.parent)
    p.write_text(s, encoding="utf-8")

def short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:10]

def detect_cc():
    clang = shutil.which("clang") or shutil.which("clang-18") or shutil.which("clang-16") or shutil.which("clang-14")
    gcc = shutil.which("gcc")
    if not clang or not gcc:
        print("ERROR: need both clang and gcc in PATH")
        sys.exit(1)
    return clang, gcc

def get_versions():
    def first_lines(cmd):
        try:
            p = run(cmd)
            return (p.stdout or "").splitlines()[:2]
        except Exception:
            return []
    return {
        "gcc": first_lines(["gcc","--version"]),
        "clang": first_lines(["clang","--version"]),
        "python": first_lines([sys.executable,"--version"])
    }

# ---------- worker ----------
def compile_and_run_one(job):
    """
    job keys:
      src, label, uid, binname, cc_name, cc, profile, outdir, run_dir, inputs(list[int]), timeout(int)
    returns: dict (for JSONL)
    """
    src = Path(job["src"])
    cc = job["cc"]
    profile = job["profile"]
    outdir = Path(job["outdir"]) / job["uid"]
    run_dir = Path(job["run_dir"])
    inputs = job.get("inputs") or []
    timeout = int(job.get("timeout", 30))

    flags = BASELINE if profile=="baseline" else HARDENED if profile=="hardened" else SAN
    ensure_dir(outdir)
    binpath = outdir / job["binname"]

    # compile (always link -lm to avoid Jotai math link failures)
    cmd = [cc, "-std=c11", str(src), "-o", str(binpath)] + flags + EXTRA_LINK_LIBS
    p = run(cmd)
    rec = {"src": job["label"], "cc": job["cc_name"], "profile": profile, "rc": p.returncode}
    if p.returncode != 0:
        rec["build_log_tail"] = (p.stdout or "")[-6000:]
        return rec

    # run sanitizer builds across inputs
    if profile == "san" and inputs:
        ensure_dir(run_dir)
        crash_inputs, timeouts = [], []
        first_rc, first_tail = None, None
        for inp in inputs:
            try:
                pr = run([str(binpath), str(inp)], cwd=run_dir, timeout=timeout)
                out = pr.stdout or ""
                if first_rc is None:
                    first_rc = pr.returncode
                    first_tail = out[-6000:]
                crashed = ("ERROR: AddressSanitizer" in out) or ("runtime error:" in out) or (pr.returncode != 0)
                if crashed:
                    crash_inputs.append(inp)
            except subprocess.TimeoutExpired:
                timeouts.append(inp)
        rec["asan_inputs_tested"] = inputs
        rec["asan_crash_inputs"] = crash_inputs
        rec["asan_crash"] = 1 if crash_inputs else 0
        rec["asan_timeouts"] = timeouts
        rec["run_rc_first"] = first_rc
        rec["run_log_first_tail"] = first_tail
    return rec

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Jotai-only runner (parallel, multi-input, math linking)")
    ap.add_argument("--workspace", default="study_jotai", help="Base output dir (separate area)")
    ap.add_argument("--run_id", default=None, help="Tag for this run; default timestamp")
    ap.add_argument("--clean_output", action="store_true", help="Delete workspace/run_id before starting")

    ap.add_argument("--jotai_root", default="./jotai-benchmarks", help="Root of Jotai repo")
    ap.add_argument("--sample_jotai", type=int, default=3000)
    ap.add_argument("--jotai_seed", type=int, default=1337)
    ap.add_argument("--jotai_manifest_out", default=None)
    ap.add_argument("--jotai_manifest_in", default=None)

    ap.add_argument("--inputs", default="0,1,2", help="Comma-separated input ids (e.g., 0,1,2)")
    ap.add_argument("--timeout", type=int, default=30, help="Seconds per sanitized run per input")
    ap.add_argument("--parallel", type=int, default=max(8, (os.cpu_count() or 8)))

    args = ap.parse_args()

    # tqdm (install if missing)
    try:
        from tqdm import tqdm
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "tqdm"])
        from tqdm import tqdm

    # workspace
    run_id = args.run_id or datetime.now().strftime("jotai_%Y%m%d_%H%M%S")
    ws = Path(args.workspace).resolve() / run_id
    if args.clean_output and ws.exists():
        shutil.rmtree(ws)

    d_build = ws/"build"
    d_runs  = ws/"runs"
    d_logs  = ws/"logs"
    for d in (d_build, d_runs, d_logs):
        ensure_dir(d)

    # save meta
    meta = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "args": vars(args),
        "versions": get_versions()
    }
    write_text(d_logs/"run_meta.json", json.dumps(meta, indent=2))

    clang, gcc = detect_cc()

    # discover Jotai sources
    random.seed(args.jotai_seed)
    root = Path(args.jotai_root).resolve()
    search_dirs = [root/"benchmarks"/"anghaLeaves", root/"benchmarks"/"anghaMath"]
    all_c = []
    for d in search_dirs:
        if d.exists():
            all_c.extend([str(p) for p in d.rglob("*.c")])

    if args.jotai_manifest_in and Path(args.jotai_manifest_in).exists():
        picked = [ln.strip() for ln in Path(args.jotai_manifest_in).read_text().splitlines() if ln.strip()]
    else:
        k = min(args.sample_jotai, len(all_c))
        picked = sorted(random.sample(all_c, k))
        outm = args.jotai_manifest_out or (d_logs/"jotai_manifest.txt")
        write_text(Path(outm), "\n".join(picked))
        print(f"[INFO] Jotai sample: {len(picked)}  manifest: {outm}")

    # sources list (we compile in-place from original paths; binaries go under workspace)
    sources = [Path(p) for p in picked]
    write_text(d_logs/"all_sources.txt", "\n".join(str(s) for s in sources))
    print(f"[INFO] Total sources: {len(sources)}")

    # inputs to run
    inputs = [int(x) for x in str(args.inputs).split(",") if x.strip().isdigit()]

    # jobs
    jobs = []
    for s in sources:
        rel = s.as_posix()  # we keep original absolute/relative path just for labeling
        uid = short_hash(rel)
        stem = s.stem
        binname = f"{stem}-{uid}"
        for cc_name, cc in [("clang", clang), ("gcc", gcc)]:
            for profile in ("baseline","hardened","san"):
                outdir = d_build/cc_name/profile
                run_dir = d_runs/cc_name/profile/uid
                jobs.append({
                    "src": str(s), "label": rel, "uid": uid, "binname": binname,
                    "cc_name": cc_name, "cc": cc, "profile": profile,
                    "outdir": str(outdir), "run_dir": str(run_dir),
                    "inputs": (inputs if profile=="san" else []),
                    "timeout": args.timeout
                })

    # execute
    results_path = d_logs/"build_results.jsonl"
    total = len(jobs)
    with ProcessPoolExecutor(max_workers=args.parallel) as ex, open(results_path, "w", encoding="utf-8") as outf:
        pbar = tqdm(total=total, desc="Jotai Build+Run", mininterval=0.5, smoothing=0.1)
        futs = [ex.submit(compile_and_run_one, j) for j in jobs]
        for fut in as_completed(futs):
            rec = fut.result()
            outf.write(json.dumps(rec) + "\n")
            pbar.update(1)
        pbar.close()

    print("[DONE] Workspace:", str(ws))
    print("       Results:", str(results_path))
    print("       Manifests & meta:", str(d_logs))

if __name__ == "__main__":
    main()

