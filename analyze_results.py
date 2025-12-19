import pandas as pd
import json
import argparse
from pathlib import Path

def get_corpus(path):
    if "gen/" in path or "/gen/" in path:
        return "LLM"
    if "seeds/" in path or "jotai" in path:
        return "Jotai"
    return "Unknown"

def get_variant(path):
    # Extracts B1, B2, B3, B4 from path like "gen/B1/file.c"
    parts = path.split("/")
    for p in parts:
        if p in ["B1", "B2", "B3", "B4"]:
            return p
    return "Unknown"

def analyze(run_dir):
    run_path = Path(run_dir)
    log_file = run_path / "logs" / "build_results.jsonl"
    
    if not log_file.exists():
        print(f"Error: Could not find {log_file}")
        return

    print(f"Loading data from {log_file}...")
    data = []
    with open(log_file, 'r') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    
    if not data:
        print("Error: Log file is empty.")
        return

    df = pd.DataFrame(data)
    
    # 1. Enrich Data
    df['corpus'] = df['src'].apply(get_corpus)
    df['variant'] = df['src'].apply(get_variant)
    
    # Ensure asan_crash is integer (0 or 1)
    df['asan_crash'] = df['asan_crash'].fillna(0).astype(int)
    
    # Filter for compiled binaries (rc == 0)
    # The paper's main metric is "Failure Rate given Compilation Success"
    built = df[df['rc'] == 0].copy()
    
    print(f"\nTotal Rows: {len(df)}")
    print(f"Successfully Built: {len(built)} ({len(built)/len(df)*100:.1f}%)")

    # --- TABLE 1: Core Metrics (LLM vs Jotai) ---
    print("\n" + "="*40)
    print(" CORE RESULTS (Matches Paper Table 2)")
    print("="*40)
    print(f"{'Corpus':<10} | {'Built':<8} | {'Crashes':<8} | {'Crash Rate (%)':<15}")
    print("-" * 50)
    
    for corpus in ["LLM", "Jotai"]:
        subset = built[built['corpus'] == corpus]
        if len(subset) == 0:
            print(f"{corpus:<10} | {'0':<8} | {'0':<8} | {'N/A':<15}")
            continue
            
        count = len(subset)
        crashes = subset['asan_crash'].sum()
        rate = (crashes / count) * 100
        print(f"{corpus:<10} | {count:<8} | {crashes:<8} | {rate:.1f}%")

    # --- TABLE 2: Prompt Variants (B1 vs B2/B4) ---
    print("\n" + "="*40)
    print(" PROMPT VARIANT ANALYSIS")
    print("="*40)
    print(f"{'Variant':<10} | {'Description':<20} | {'Crash Rate (%)':<15}")
    print("-" * 50)
    
    variants = {
        "B1": "Baseline",
        "B2": "Secure",
        "B3": "Strict",
        "B4": "Few-Shot Secure"
    }
    
    llm_built = built[built['corpus'] == "LLM"]
    
    for v in ["B1", "B2", "B3", "B4"]:
        subset = llm_built[llm_built['variant'] == v]
        if len(subset) == 0:
            continue
        
        rate = subset['asan_crash'].mean() * 100
        desc = variants.get(v, "")
        print(f"{v:<10} | {desc:<20} | {rate:.1f}%")
        
    # Check hypothesis
    b1 = llm_built[llm_built['variant'] == "B1"]['asan_crash'].mean()
    b2 = llm_built[llm_built['variant'] == "B2"]['asan_crash'].mean()
    
    print("\n" + "-"*50)
    print("VERIFICATION CHECK:")
    if abs(b1 - b2) < 0.10: # within 10%
        print(f"[✓] CONFIRMED: Secure prompting (B2) did NOT significantly reduce crashes vs Baseline (B1).")
    elif b2 < b1:
        print(f"[?] MIXED: Secure prompting reduced crashes by {((b1-b2)/b1)*100:.1f}%.")
    else:
        print(f"[!] UNEXPECTED: Secure prompting performed worse.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, help="Path to run directory (e.g., ./study_verification/run_v1)")
    args = parser.parse_args()
    analyze(args.root)
