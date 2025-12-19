#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed

def run_test(bin_path, input_file):
    try:
        # READ AS BYTES (Fixes UTF-8 errors)
        input_data = input_file.read_bytes()
        
        # Run the binary
        res = subprocess.run(
            [str(bin_path)],
            input=input_data,  # Pass bytes directly
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return res
    except subprocess.TimeoutExpired:
        return "TIMEOUT"

def worker(task):
    bin_path = Path(task["bin"])
    fixture = Path(task["fixture"])
    
    outcome = run_test(bin_path, fixture)
    
    if outcome == "TIMEOUT":
        return "timeout"
    
    # --- Classification Logic ---
    
    # 1. Success
    if outcome.returncode == 0:
        return "pass"
    
    # 2. Safe Panic (Rust Safety)
    # Rust usually returns 101 for panics.
    if outcome.returncode == 101: 
        return "panic_safe"
    
    # Check stderr (need to decode bytes to string for searching)
    try:
        err_text = outcome.stderr.decode("utf-8", errors="ignore").lower()
    except:
        err_text = ""
        
    if "panic" in err_text:
        return "panic_safe"

    # 3. Unsafe Memory Error (Segfault)
    # Unix signals: -11 (SIGSEGV) or return code 139 (128 + 11)
    if outcome.returncode == -11 or outcome.returncode == 139:
        return "segfault_unsafe"
        
    # 4. Other Runtime Errors
    return "error_unknown"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run_dir", required=True, help="Path to the rust run dir")
    parser.add_argument("--fixtures", required=True, help="Path to fixtures dir")
    parser.add_argument("--parallel", type=int, default=32)
    args = parser.parse_args()
    
    run_dir = Path(args.run_dir)
    fixtures_dir = Path(args.fixtures)
    bin_root = run_dir / "bins"
    
    tasks = []
    
    print(f"Scanning {bin_root}...")
    for variant in ["B1", "B2", "B3", "B4"]:
        v_dir = bin_root / variant
        if not v_dir.exists(): continue
        
        for bin_file in v_dir.iterdir():
            # Glob for matches starting with binary name
            candidates = list(fixtures_dir.glob(f"{bin_file.name}.in*"))
            if not candidates:
                 candidates = list(fixtures_dir.glob(f"*_{bin_file.name}.in*"))
            
            if candidates:
                for fix in candidates:
                    tasks.append({
                        "bin": str(bin_file),
                        "fixture": str(fix),
                        "variant": variant
                    })
            
    print(f"Verifying {len(tasks)} Rust test cases (Binary Mode)...")
    
    stats = {
        "B1": {"pass": 0, "panic_safe": 0, "segfault_unsafe": 0, "timeout": 0, "error_unknown": 0},
        "B2": {"pass": 0, "panic_safe": 0, "segfault_unsafe": 0, "timeout": 0, "error_unknown": 0},
        "B3": {"pass": 0, "panic_safe": 0, "segfault_unsafe": 0, "timeout": 0, "error_unknown": 0},
        "B4": {"pass": 0, "panic_safe": 0, "segfault_unsafe": 0, "timeout": 0, "error_unknown": 0},
    }
    
    with ProcessPoolExecutor(max_workers=args.parallel) as exc:
        futures = {exc.submit(worker, t): t["variant"] for t in tasks}
        
        for f in as_completed(futures):
            var = futures[f]
            try:
                res = f.result()
                stats[var][res] = stats[var].get(res, 0) + 1
            except Exception as e:
                print(f"Error: {e}")

    # Summary Table
    print("\n" + "="*85)
    print(f"{'Variant':<10} | {'Pass':<8} | {'Safe Panic':<12} | {'Timeout':<8} | {'SEGFAULT (Unsafe)':<18}")
    print("-" * 85)
    
    total_safe = 0
    total_unsafe = 0
    
    for v in ["B1", "B2", "B3", "B4"]:
        s = stats[v]
        total = sum(s.values())
        if total == 0: continue
        
        print(f"{v:<10} | {s['pass']:<8} | {s['panic_safe']:<12} | {s['timeout']:<8} | {s['segfault_unsafe']:<18}")
        
        total_safe += s['panic_safe']
        total_unsafe += s['segfault_unsafe']
        
    print("="*85)
    print(f"Total Safe Panics (Rust working): {total_safe}")
    print(f"Total Unsafe Segfaults:           {total_unsafe}")
    print("="*85)

if __name__ == "__main__":
    main()
