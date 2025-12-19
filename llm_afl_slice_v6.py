#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import glob
import time
import json
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Configuration ---
def log(msg):
    print(f"[AFL-v6] {msg}")

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def find_c_sources(run_dir):
    # Scan gen directory
    search_pattern = str(Path(run_dir) / "gen" / "**" / "*.c")
    files = glob.glob(search_pattern, recursive=True)
    return sorted([Path(f) for f in files])

def check_afl_tools():
    afl_fuzz = shutil.which("afl-fuzz")
    afl_cc = shutil.which("afl-clang-fast")
    if not afl_fuzz or not afl_cc:
        log("ERROR: Could not find 'afl-fuzz' or 'afl-clang-fast'.")
        sys.exit(1)
    return afl_fuzz, afl_cc

def compile_target(src_path, work_dir, afl_cc):
    # Unique ID
    variant = src_path.parent.name
    stem = src_path.stem
    uid = f"{variant}_{stem}"
    
    bin_dir = work_dir / "bins"
    ensure_dir(bin_dir)
    
    # Absolute path for binary
    bin_path = (bin_dir / f"{uid}_afl").resolve()
    
    cmd = [
        afl_cc, 
        "-O1", "-g", 
        "-fno-omit-frame-pointer",
        str(src_path), 
        "-o", str(bin_path),
        "-lm"
    ]
    
    res = subprocess.run(
        cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True
    )
    
    if res.returncode != 0:
        return False, res.stdout, None, uid
        
    return True, "OK", bin_path, uid

def fuzz_target(bin_path, uid, slug, work_dir, fixtures_dir, seconds):
    # Use ABSOLUTE paths for everything to avoid CWD confusion
    fuzz_dir = (work_dir / "fuzz" / uid).resolve()
    input_dir = (fuzz_dir / "in").resolve()
    output_dir = (fuzz_dir / "out").resolve()
    
    # Clean previous
    if fuzz_dir.exists():
        shutil.rmtree(fuzz_dir)
    ensure_dir(input_dir)
    ensure_dir(output_dir)
    
    # 1. Seeds
    seeds = list(Path(fixtures_dir).glob(f"{slug}.in*"))
    if not seeds:
        (input_dir / "seed_dummy").write_text("0\n10 20\n", encoding="utf-8")
    else:
        for i, s in enumerate(seeds):
            try:
                shutil.copy(s, input_dir / f"id_{i}")
            except Exception:
                time.sleep(0.1)
                shutil.copy(s, input_dir / f"id_{i}")

    # 2. Environment
    env = os.environ.copy()
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_NO_AFFINITY"] = "1"
    env["AFL_NO_UI"] = "1"
    
    # 3. Run AFL
    # Note: We pass absolute paths to -i, -o, and the binary
    cmd = [
        "afl-fuzz",
        "-i", str(input_dir),
        "-o", str(output_dir),
        "-V", str(seconds),
        "-d", 
        "--",
        str(bin_path),
        "@@"
    ]
    
    proc = subprocess.run(
        cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT,
        cwd=fuzz_dir, # We still run inside the dir, but args are absolute
        env=env,
        timeout=seconds + 10,
        text=True
    )
    
    if proc.returncode != 0 and proc.returncode != None:
        return {
            "uid": uid,
            "status": "afl_fail",
            "log": proc.stdout
        }

    # 4. Count Crashes
    crash_dir = output_dir / "default" / "crashes"
    crashes = 0
    if crash_dir.exists():
        crashes = len([x for x in crash_dir.glob("id:*")])
        
    return {
        "uid": uid,
        "status": "fuzzed",
        "crashes": crashes
    }

def worker(task):
    src, work_dir, afl_cc, fixtures, seconds = task
    
    ok, log_msg, bin_path, uid = compile_target(src, work_dir, afl_cc)
    if not ok:
        return {"uid": uid, "status": "build_fail", "log": log_msg}
        
    try:
        slug = "_".join(src.stem.split("_")[1:])
    except:
        slug = src.stem
        
    return fuzz_target(bin_path, uid, slug, work_dir, fixtures, seconds)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--run_id", required=True)
    parser.add_argument("--fixtures_dir", required=True)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--parallel", type=int, default=8)
    args = parser.parse_args()

    # RESOLVE ABSOLUTE PATHS IMMEDIATELY
    workspace = Path(args.workspace).resolve()
    fixtures_dir = Path(args.fixtures_dir).resolve()
    
    run_dir = workspace / args.run_id
    work_dir = run_dir / "afl_v6"
    ensure_dir(work_dir)
    
    afl_fuzz, afl_cc = check_afl_tools()
    sources = find_c_sources(run_dir)
    if not sources:
        log("No sources found.")
        sys.exit(1)
        
    log(f"Found {len(sources)} sources. Starting run with {args.parallel} threads...")
    
    tasks = [(s, work_dir, afl_cc, fixtures_dir, args.seconds) for s in sources]
    
    results = []
    afl_errors_printed = 0
    
    with ProcessPoolExecutor(max_workers=args.parallel) as exc:
        futures = [exc.submit(worker, t) for t in tasks]
        
        try:
            from tqdm import tqdm
            pbar = tqdm(total=len(tasks))
        except ImportError:
            pbar = None
            
        for f in as_completed(futures):
            res = f.result()
            results.append(res)
            
            if res["status"] == "afl_fail":
                if afl_errors_printed < 3:
                    log(f"\n[!!!] AFL Failed for {res['uid']}:")
                    err_lines = res.get("log", "").strip().splitlines()[-10:]
                    print("\n".join(err_lines))
                    log("-" * 20)
                    afl_errors_printed += 1
            
            if pbar: pbar.update(1)
            
        if pbar: pbar.close()

    total_crashes = sum(r.get("crashes", 0) for r in results if r["status"] == "fuzzed")
    fails = len([r for r in results if r["status"] == "afl_fail"])
    
    log(f"Done. Total Crashes: {total_crashes}. AFL Failures: {fails}")
    
    with open(work_dir / "fuzz_report.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
