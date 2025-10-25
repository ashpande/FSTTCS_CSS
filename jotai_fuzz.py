#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
jotai.py — Jotai-only runner with integer sanitizers, crash taxonomy, and optional AFL++ fuzz.

Outputs (per --workspace/--run_id):
  build/cc/profile/<uid>/<bin>
  runs/cc/profile/<uid>[/in,/out for AFL]
  logs/build_results.jsonl
  logs/jotai_manifest.txt
  logs/all_sources.txt
  logs/run_meta.json
"""

import argparse, os, sys, json, random, shutil, subprocess, time, hashlib, re
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed

# ---------- compile flag sets ----------
BASELINE = ["-O2", "-Wall", "-Wextra"]
HARDENED = [
    "-O2","-Wall","-Wextra",
    "-D_FORTIFY_SOURCE=3","-fstack-protector-strong","-fPIE","-pie",
    "-Wl,-z,relro","-Wl,-z,now","-fstack-clash-protection",
]
SAN_CORE = ["-O1","-g","-fsanitize=address,undefined","-fno-omit-frame-pointer"]
EXTRA_LINK_LIBS = ["-lm"]  # critical for Jotai (math)

def san_flags(cc_name: str, kind: str):
    if kind == "san":
        return SAN_CORE[:]
    # integer sanitizer variant
    if cc_name == "clang":
        return SAN_CORE + ["-fsanitize=integer"]
    else:  # gcc-compatible
        return SAN_CORE + ["-fsanitize=signed-integer-overflow,unsigned-integer-overflow"]
# --------------------------------------

def run(cmd, cwd=None, timeout=None, env=None):
    return subprocess.run(
        cmd, cwd=cwd, timeout=timeout, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )

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

def have_afl():
    return (shutil.which("afl-fuzz") is not None) and (shutil.which("afl-clang-fast") is not None or shutil.which("afl-gcc") is not None)

def get_versions():
    def fl(cmd):
        try:
            p = run(cmd)
            return (p.stdout or "").splitlines()[:2]
        except Exception:
            return []
    return {
        "gcc": fl(["gcc","--version"]),
        "clang": fl(["clang","--version"]),
        "python": fl([sys.executable,"--version"]),
        "afl-fuzz": fl(["afl-fuzz","-V","1"]) if shutil.which("afl-fuzz") else [],
    }

# -------- crash taxonomy ----------
ASAN_PATTERNS = [
    ("heap-use-after-free", re.compile(r"heap-use-after-free")),
    ("stack-use-after-return", re.compile(r"stack-use-after-return")),
    ("stack-use-after-scope", re.compile(r"stack-use-after-scope")),
    ("use-after-poison", re.compile(r"use-after-poison")),
    ("heap-buffer-overflow", re.compile(r"heap-buffer-overflow")),
    ("stack-buffer-overflow", re.compile(r"stack-buffer-overflow")),
    ("global-buffer-overflow", re.compile(r"global-buffer-overflow")),
    ("double-free", re.compile(r"double-free")),
    ("alloc-dealloc-mismatch", re.compile(r"alloc-dealloc-mismatch")),
    ("null-deref", re.compile(r"null pointer")),
    ("out-of-bounds", re.compile(r"out of bounds")),
]
UBSAN_PATTERNS = [
    ("integer-overflow", re.compile(r"overflow")),
    ("shift-out-of-bounds", re.compile(r"shift out of bounds")),
    ("divide-by-zero", re.compile(r"division by zero")),
    ("invalid-value", re.compile(r"load of value.*is not a valid value")),
    ("null-deref", re.compile(r"null pointer")),
    ("misaligned-access", re.compile(r"misaligned")),
]

def classify_crash(output: str):
    kinds = set()
    if "ERROR: AddressSanitizer" in output:
        for tag, rx in ASAN_PATTERNS:
            if rx.search(output):
                kinds.add(tag)
    if "runtime error:" in output:
        for tag, rx in UBSAN_PATTERNS:
            if rx.search(output):
                kinds.add(tag)
    return sorted(kinds)
# -----------------------------------

def should_fuzz(uid: str, pct: float):
    # deterministic selection by hash modulo 1000
    hv = int(hashlib.sha1(uid.encode("utf-8")).hexdigest(), 16) % 1000
    return hv < int(pct * 1000 + 0.5)

def compile_one(src: Path, cc_path: str, cc_name: str, profile: str, outdir: Path, binname: str):
    flags = BASELINE if profile=="baseline" else HARDENED if profile=="hardened" else san_flags(cc_name, "san")
    ensure_dir(outdir)
    binpath = outdir / binname
    cmd = [cc_path, "-std=c11", str(src), "-o", str(binpath)] + list(flags) + EXTRA_LINK_LIBS
    p = run(cmd)
    return p.returncode, p.stdout, binpath

def compile_one_sanint(src: Path, cc_path: str, cc_name: str, outdir: Path, binname: str):
    flags = san_flags(cc_name, "sanint")
    ensure_dir(outdir)
    binpath = outdir / (binname + "-int")
    cmd = [cc_path, "-std=c11", str(src), "-o", str(binpath)] + list(flags) + EXTRA_LINK_LIBS
    p = run(cmd)
    return p.returncode, p.stdout, binpath

def afl_compile(src: Path, outdir: Path, binname: str):
    cc = shutil.which("afl-clang-fast") or shutil.which("afl-gcc")
    if not cc:
        return 1, "afl-cc not found", None
    ensure_dir(outdir)
    binpath = outdir / (binname + "-afl")
    # Keep basic ASan for crash clarity; afl technically prefers without, but for short -V runs it's fine.
    cmd = [cc, "-std=c11", str(src), "-o", str(binpath)] + SAN_CORE + EXTRA_LINK_LIBS
    p = run(cmd, env=dict(os.environ, AFL_DONT_OPTIMIZE="1"))
    return p.returncode, p.stdout, binpath

def run_sanitized(binpath: Path, run_dir: Path, inputs, timeout: int):
    ensure_dir(run_dir)
    crash_inputs, timeouts = [], []
    kinds = set()
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
                for k in classify_crash(out):
                    kinds.add(k)
        except subprocess.TimeoutExpired:
            timeouts.append(inp)
    return {
        "asan_inputs_tested": list(inputs),
        "asan_crash_inputs": crash_inputs,
        "asan_crash": 1 if crash_inputs else 0,
        "asan_timeouts": timeouts,
        "asan_kinds": sorted(kinds),
        "run_rc_first": first_rc,
        "run_log_first_tail": first_tail,
    }

def afl_fuzz(binpath: Path, run_dir: Path, seconds: int, seed_inputs):
    if not have_afl():
        return {"afl_enabled": 0}
    in_dir = run_dir / "in"; out_dir = run_dir / "out"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    ensure_dir(in_dir)
    # seed corpus: the chosen input indexes as text files
    for i, v in enumerate(seed_inputs):
        write_text(in_dir / f"seed{i}.txt", str(v) + "\n")
    cmd = [
        "afl-fuzz", "-i", str(in_dir), "-o", str(out_dir),
        "-V", str(seconds), "--", str(binpath), "@@"
    ]
    env = dict(os.environ)
    env.setdefault("AFL_SKIP_CPUFREQ", "1")
    p = run(cmd, cwd=run_dir, env=env, timeout=seconds + 10)
    # Count crashes
    crashes = 0
    crash_dir = out_dir / "default" / "crashes"
    if crash_dir.exists():
        crashes = len([p for p in crash_dir.iterdir() if p.name.startswith("id:")])
    return {
        "afl_enabled": 1,
        "afl_seconds": seconds,
        "afl_crashes": crashes,
    }

def compile_and_run_job(job):
    """
    Job dict fields:
      src,label,uid,binname,cc_name,cc_path,profile,out_base,run_base,inputs,timeout,
      do_sanint(bool), do_afl(bool), afl_seconds(int), fuzz_pct(float)
    """
    src = Path(job["src"])
    cc_name = job["cc_name"]
    cc_path = job["cc_path"]
    profile = job["profile"]
    outdir = Path(job["out_base"]) / job["uid"]
    run_dir = Path(job["run_base"]) / job["uid"]
    binname = job["binname"]
    inputs = job.get("inputs") or []
    timeout = int(job.get("timeout", 30))
    do_sanint = bool(job.get("do_sanint", True))
    do_afl = bool(job.get("do_afl", False))
    afl_seconds = int(job.get("afl_seconds", 30))

    rec = {"src": job["label"], "cc": cc_name, "profile": profile}

    # compile
    rc, out, binpath = compile_one(src, cc_path, cc_name, profile, outdir, binname)
    rec["rc"] = rc
    if rc != 0 or not binpath:
        rec["build_log_tail"] = (out or "")[-6000:]
        return rec

    # run sanitizer(s)
    if profile == "san" and inputs:
        rec.update(run_sanitized(binpath, run_dir, inputs, timeout))

        # integer-sanitizer variant (separate binary)
        if do_sanint:
            rc2, out2, bin2 = compile_one_sanint(src, cc_path, cc_name, outdir, binname)
            rec["sanint_rc"] = rc2
            if rc2 == 0 and bin2:
                run_dir2 = run_dir / "sanint"
                res2 = run_sanitized(bin2, run_dir2, inputs, timeout)
                # prefix sanint_* fields
                rec.update({f"sanint_{k}": v for k, v in res2.items()})
            else:
                rec["sanint_build_log_tail"] = (out2 or "")[-6000:]

        # AFL++ (optional, subsample)
        if do_afl and have_afl():
            # compile AFL instrumented
            afl_out = Path(job["out_base"]) / job["uid"]
            rc3, out3, bin3 = afl_compile(src, afl_out, binname)
            rec["afl_rc"] = rc3
            if rc3 == 0 and bin3:
                afl_run_dir = Path(job["run_base"]) / job["uid"] / "afl"
                # seeds = default inputs + a couple adversarial extremes
                seeds = list(dict.fromkeys(list(inputs) + [-1, 999999]))
                afl = afl_fuzz(bin3, afl_run_dir, afl_seconds, seeds)
                rec.update(afl)
            else:
                rec["afl_build_log_tail"] = (out3 or "")[-6000:]
        elif do_afl:
            rec.update({"afl_enabled": 0, "afl_note": "afl-* tools not found"})
    return rec

def main():
    ap = argparse.ArgumentParser(description="Jotai runner with san+sanint and optional AFL fuzz")
    ap.add_argument("--workspace", default="study_jotai")
    ap.add_argument("--run_id", default=None)
    ap.add_argument("--clean_output", action="store_true")

    # Jotai dataset
    ap.add_argument("--jotai_root", default="./jotai-benchmarks")
    ap.add_argument("--sample_jotai", type=int, default=3000)
    ap.add_argument("--jotai_seed", type=int, default=1337)
    ap.add_argument("--jotai_manifest_out", default=None)
    ap.add_argument("--jotai_manifest_in", default=None)

    # Inputs & timeouts
    ap.add_argument("--inputs", default="0,1,2", help="Comma-separated input ids")
    ap.add_argument("--timeout", type=int, default=30)

    # Parallelism
    ap.add_argument("--parallel", type=int, default=max(8, (os.cpu_count() or 8)))

    # Extra dynamic depth
    ap.add_argument("--enable_sanint", action="store_true", help="Also run integer-sanitizer variant")
    ap.add_argument("--enable_afl", action="store_true", help="Fuzz a subsample with AFL++")
    ap.add_argument("--fuzz_pct", type=float, default=0.2, help="Fraction of sources to fuzz (0..1)")
    ap.add_argument("--fuzz_seconds", type=int, default=30)

    args = ap.parse_args()

    # tqdm (install if missing)
    try:
        from tqdm import tqdm
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "tqdm"])
        from tqdm import tqdm

    # Workspace
    run_id = args.run_id or datetime.now().strftime("jotai_%Y%m%d_%H%M%S")
    ws = Path(args.workspace).resolve() / run_id
    if args.clean_output and ws.exists():
        shutil.rmtree(ws)
    d_build = ws/"build"
    d_runs  = ws/"runs"
    d_logs  = ws/"logs"
    for d in (d_build, d_runs, d_logs):
        ensure_dir(d)

    # Meta
    meta = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "args": vars(args),
        "versions": get_versions(),
        "afl_available": have_afl(),
    }
    write_text(d_logs/"run_meta.json", json.dumps(meta, indent=2))

    # Toolchains
    clang, gcc = detect_cc()

    # Discover Jotai sources
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

    sources = [Path(p) for p in picked]
    write_text(d_logs/"all_sources.txt", "\n".join(str(s) for s in sources))
    print(f"[INFO] Total sources: {len(sources)}")

    # Inputs list
    inputs = [int(x) for x in str(args.inputs).split(",") if x.strip().lstrip("-").isdigit()]

    # Jobs
    jobs = []
    for s in sources:
        rel = s.as_posix()
        uid = short_hash(rel)
        stem = s.stem
        binname = f"{stem}-{uid}"
        for cc_name, cc_path in [("clang", clang), ("gcc", gcc)]:
            for profile in ("baseline","hardened","san"):
                out_base = d_build/cc_name/profile
                run_base = d_runs/cc_name/profile
                jobs.append({
                    "src": str(s), "label": rel, "uid": uid, "binname": binname,
                    "cc_name": cc_name, "cc_path": cc_path, "profile": profile,
                    "out_base": str(out_base), "run_base": str(run_base),
                    "inputs": (inputs if profile=="san" else []),
                    "timeout": args.timeout,
                    "do_sanint": bool(args.enable_sanint),
                    "do_afl": bool(args.enable_afl and should_fuzz(uid, args.fuzz_pct)),
                    "afl_seconds": args.fuzz_seconds,
                })

    # Execute
    results_path = d_logs/"build_results.jsonl"
    total = len(jobs)
    with ProcessPoolExecutor(max_workers=args.parallel) as ex, open(results_path, "w", encoding="utf-8") as outf:
        pbar = tqdm(total=total, desc="Jotai Build+Run", mininterval=0.5, smoothing=0.1)
        futs = [ex.submit(compile_and_run_job, j) for j in jobs]
        for fut in as_completed(futs):
            rec = fut.result()
            outf.write(json.dumps(rec) + "\n")
            pbar.update(1)
        pbar.close()

    print("[DONE] Workspace:", str(ws))
    print("       Results:", str(results_path))
    print("       Logs & manifests:", str(d_logs))

if __name__ == "__main__":
    main()

