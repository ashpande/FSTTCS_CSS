#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aggregate logs across LLM, Jotai, and Juliet and compute crash rates with 95% CI.

Outputs (under OUTDIR/agg_<timestamp>/):
  - master_rows.jsonl                (normalized union of rows with key fields)
  - metrics_core_built.csv           (LLM vs Jotai vs Juliet; denom = built)
  - metrics_core_all.csv             (LLM vs Jotai vs Juliet; denom = all)
  - llm_variants_built.csv           (B1..B4; denom = built)
  - llm_variants_all.csv             (B1..B4; denom = all)
  - llm_cc_opt_built.csv             (compiler×opt; denom = built)
  - llm_cc_opt_all.csv               (compiler×opt; denom = all)
  - juliet_cwe_built.csv             (CWE breakdown; denom = built)        [if CWE parsed]
  - juliet_cwe_all.csv               (CWE breakdown; denom = all)          [if CWE parsed]
  - fuzz_llm.csv                     (AFL slice summaries for LLM, if present)
  - fuzz_juliet.csv                  (AFL slice summaries for Juliet, if present)
  - opt_sweep_summaries.csv          (any opt sweep summaries found)

Usage:
  python3 aggregate_study.py \
    --root /var/lib/ansible/ashutosh \
    --outdir /var/lib/ansible/ashutosh/plots_acm
"""
import argparse, json, os, re, glob, time, math
from pathlib import Path
from collections import defaultdict
import pandas as pd

# ---------------- utils ----------------

def ensure_dir(p: Path): p.mkdir(parents=True, exist_ok=True)
def nowstamp(): return time.strftime("%Y%m%d_%H%M%S")

def wilson_ci(k, n, z=1.96):
    if n <= 0: return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + (z*z)/n
    centre = p + (z*z)/(2*n)
    margin = z * math.sqrt((p*(1-p) + (z*z)/(4*n)) / n)
    lo = (centre - margin) / denom
    hi = (centre + margin) / denom
    return p, max(0.0, lo), min(1.0, hi)

def read_jsonl(path: Path):
    rows=[]
    if not path.exists(): return rows
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line: continue
            try: rows.append(json.loads(line))
            except Exception: pass
    return rows

def read_text(path: Path):
    try: return path.read_text(encoding="utf-8", errors="ignore")
    except Exception: return ""

def load_csvs(patterns):
    dfs=[]
    for pat in patterns:
        for fp in glob.glob(pat):
            try: dfs.append(pd.read_csv(fp))
            except Exception: pass
    if not dfs: return pd.DataFrame()
    return pd.concat(dfs, ignore_index=True)

def is_llm_path(s: str) -> bool:
    if not s: return False
    return "/gen/" in s or "\\gen\\" in s

def llm_variant_from_path(s: str):
    if not s: return None
    m = re.search(r"/gen/(B[1-4])/", s) or re.search(r"\\gen\\(B[1-4])\\", s)
    return m.group(1) if m else None

def cwe_from_path(s: str):
    """Try multiple Juliet name/dir patterns to recover CWE id."""
    if not s:
        return None
    for pat in [r"CWE(\d{3,4})", r"_CWE(\d{3,4})_", r"/CWE(\d{3,4})/", r"-CWE(\d{3,4})-"]:
        m = re.search(pat, s)
        if m:
            return f"CWE{m.group(1)}"
    return None

# -------------- harvesting --------------

def harvest_llm(root: Path):
    logs = root/"study"/"big_combo_v2"/"logs"
    data = {
        "logs_dir": logs,
        "build_rows": read_jsonl(logs/"build_results.jsonl"),
        "opt_summaries": load_csvs([str(logs/"opt_sweep_*"/"opt_sweep_summary_*.csv")]),
        "afl_summaries": load_csvs([str(logs/"afl_slice_*"/"afl_slice_summary_*.csv"),
                                    str(logs/"afl_slice_summary.csv")]),
    }
    mp = logs/"llm_manifest.json"
    data["manifest"] = json.loads(read_text(mp)) if mp.exists() else []
    return data

def harvest_jotai(root: Path):
    logs = root/"study"/"jotai_only_fix_v1"/"logs"
    return {"logs_dir": logs, "build_rows": read_jsonl(logs/"build_results.jsonl")}

def harvest_juliet(root: Path):
    base = root/"study_juliet"
    runs=[]
    for run in base.glob("juliet_*"):
        br = run/"logs"/"build_results.jsonl"
        if br.exists():
            rows = read_jsonl(br)
            runs.append({"run_id": run.name, "rows": rows})
    afl = load_csvs([str(base/"juliet_afl_slice"/"logs"/"afl_slice_summary*.csv")])
    return {"runs": runs, "afl_summaries": afl}

# ------------- normalization -------------

def normalize_rows(rows, corpus_name):
    """Return list of normalized dicts for master_rows.jsonl"""
    out=[]
    for r in rows:
        src = r.get("src") or r.get("label") or ""
        cc  = r.get("cc") or r.get("compiler") or r.get("cc_name")
        opt = r.get("opt") or r.get("opt_level") or r.get("profile")
        prof= r.get("profile")
        rc  = r.get("rc")
        asan= r.get("asan_crash")
        if isinstance(asan, str):
            asan = 0 if asan.strip().lower() in ("","0","false","none") else 1
        row = {
            "corpus": corpus_name,
            "src": src,
            "cc": cc,
            "opt": opt,
            "profile": prof,
            "rc": rc,
            "asan_crash": int(asan) if asan is not None else None,
        }
        if corpus_name == "LLM":
            row["llm_variant"] = llm_variant_from_path(src)
        if corpus_name.startswith("Juliet"):
            row["cwe"] = cwe_from_path(src)
        out.append(row)
    return out

# --------------- metrics ----------------

def summarize_rate(df: pd.DataFrame, denom="built"):
    if df.empty:
        return dict(n_total=0, n_built=0, asan_hits=0, rate=0.0, lo=0.0, hi=0.0)
    n_total = len(df)
    built = df[df["rc"]==0] if "rc" in df.columns else df
    n_built = len(built)
    hits = int((built["asan_crash"]>0).sum()) if "asan_crash" in built else 0
    if denom == "built":
        p, lo, hi = wilson_ci(hits, max(1, n_built))
    else:
        p, lo, hi = wilson_ci(hits, max(1, n_total))
    return dict(n_total=n_total, n_built=n_built, asan_hits=hits,
                rate=100*p, lo=100*lo, hi=100*hi)

def metrics_core(master: pd.DataFrame, denom: str):
    out=[]
    for name, sub in [
        ("LLM (san)", master[master["corpus"]=="LLM"]),
        ("Jotai (san)", master[master["corpus"]=="Jotai"]),
        ("Juliet (san combined)", master[master["corpus"].astype(str).str.startswith("Juliet", na=False)])
    ]:
        m = summarize_rate(sub, denom=denom); m["group"]=name; out.append(m)
    cols = ["group","n_total","n_built","asan_hits","rate","lo","hi"]
    return pd.DataFrame(out)[cols]

def metrics_llm_variants(master: pd.DataFrame, denom: str):
    if "llm_variant" not in master.columns:
        return pd.DataFrame(columns=["variant","n_total","n_built","asan_hits","rate","lo","hi"])
    m = master[(master["corpus"]=="LLM") & master["llm_variant"].notna()]
    out=[]
    for v, sub in m.groupby("llm_variant"):
        row = summarize_rate(sub, denom=denom); row["variant"]=v; out.append(row)
    df = pd.DataFrame(out)
    if df.empty: return df
    cols = ["variant","n_total","n_built","asan_hits","rate","lo","hi"]
    return df[cols].sort_values("variant")

def metrics_llm_cc_opt(master: pd.DataFrame, denom: str):
    need_cols = {"cc","opt"}
    if not need_cols.issubset(set(master.columns)):
        return pd.DataFrame(columns=["cc","opt","n_total","n_built","asan_hits","rate","lo","hi"])
    m = master[(master["corpus"]=="LLM") & master["cc"].notna() & master["opt"].notna()]
    out=[]
    for (cc,opt), sub in m.groupby(["cc","opt"]):
        row = summarize_rate(sub, denom=denom); row["cc"]=cc; row["opt"]=opt; out.append(row)
    df = pd.DataFrame(out)
    if df.empty: return df
    cols = ["cc","opt","n_total","n_built","asan_hits","rate","lo","hi"]
    return df[cols].sort_values(["cc","opt"])

def metrics_juliet_cwe(master: pd.DataFrame, denom: str):
    # Defensive: if 'cwe' not present, return empty frame gracefully
    if "cwe" not in master.columns:
        return pd.DataFrame(columns=["cwe","n_total","n_built","asan_hits","rate","lo","hi"])
    mask = master["corpus"].astype(str).str.startswith("Juliet", na=False)
    mask = mask & master["cwe"].notna()
    m = master[mask]
    out=[]
    for cwe, sub in m.groupby("cwe"):
        row = summarize_rate(sub, denom=denom); row["cwe"]=cwe; out.append(row)
    df = pd.DataFrame(out)
    if df.empty:
        return pd.DataFrame(columns=["cwe","n_total","n_built","asan_hits","rate","lo","hi"])
    cols = ["cwe","n_total","n_built","asan_hits","rate","lo","hi"]
    return df[cols].sort_values("cwe")

# ------------------- main -------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    out_base = Path(args.outdir).resolve()
    run_dir = out_base / f"agg_{nowstamp()}"
    ensure_dir(run_dir)

    # Harvest
    llm = harvest_llm(root)
    jotai = harvest_jotai(root)
    juliet = harvest_juliet(root)

    # Normalize rows
    master_rows = []
    master_rows += normalize_rows(llm["build_rows"], "LLM")
    master_rows += normalize_rows(jotai["build_rows"], "Jotai")
    for run in juliet["runs"]:
        master_rows += normalize_rows(run["rows"], run["run_id"])

    # Save master jsonl
    master_path = run_dir/"master_rows.jsonl"
    with master_path.open("w", encoding="utf-8") as f:
        for r in master_rows:
            f.write(json.dumps(r) + "\n")

    # Build DataFrame
    master = pd.DataFrame(master_rows)

    # Metrics (built + all)
    core_built = metrics_core(master, "built"); core_built.to_csv(run_dir/"metrics_core_built.csv", index=False)
    core_all   = metrics_core(master, "all");   core_all.to_csv(run_dir/"metrics_core_all.csv", index=False)

    llm_var_b  = metrics_llm_variants(master, "built"); llm_var_b.to_csv(run_dir/"llm_variants_built.csv", index=False)
    llm_var_a  = metrics_llm_variants(master, "all");   llm_var_a.to_csv(run_dir/"llm_variants_all.csv", index=False)

    llm_ccopt_b= metrics_llm_cc_opt(master, "built"); llm_ccopt_b.to_csv(run_dir/"llm_cc_opt_built.csv", index=False)
    llm_ccopt_a= metrics_llm_cc_opt(master, "all");   llm_ccopt_a.to_csv(run_dir/"llm_cc_opt_all.csv", index=False)

    jul_cwe_b  = metrics_juliet_cwe(master, "built"); jul_cwe_b.to_csv(run_dir/"juliet_cwe_built.csv", index=False)
    jul_cwe_a  = metrics_juliet_cwe(master, "all");   jul_cwe_a.to_csv(run_dir/"juliet_cwe_all.csv", index=False)

    # Fuzz summaries and opt sweep summaries (consolidate if present)
    def normalize_ge(df):
        if df is None or df.empty: return df
        for c in list(df.columns):
            if "≥" in c or "â‰¥" in c:
                df = df.rename(columns={c: "targets_with_ge_1_crash"})
        return df

    fuzz_llm = normalize_ge(llm["afl_summaries"])
    if isinstance(fuzz_llm, pd.DataFrame) and not fuzz_llm.empty:
        fuzz_llm.to_csv(run_dir/"fuzz_llm.csv", index=False)

    fuzz_jul = normalize_ge(juliet["afl_summaries"])
    if isinstance(fuzz_jul, pd.DataFrame) and not fuzz_jul.empty:
        fuzz_jul.to_csv(run_dir/"fuzz_juliet.csv", index=False)

    opt_summ = llm["opt_summaries"]
    if isinstance(opt_summ, pd.DataFrame) and not opt_summ.empty:
        opt_summ.to_csv(run_dir/"opt_sweep_summaries.csv", index=False)

    print("[OK] Aggregation complete.")
    print("Master rows:", str(master_path))
    print("Core metrics:", run_dir/"metrics_core_built.csv", "|", run_dir/"metrics_core_all.csv")
    print("LLM variants:", run_dir/"llm_variants_built.csv", "|", run_dir/"llm_variants_all.csv")
    print("LLM cc×opt:", run_dir/"llm_cc_opt_built.csv", "|", run_dir/"llm_cc_opt_all.csv")
    print("Juliet by CWE:", run_dir/"juliet_cwe_built.csv", "|", run_dir/"juliet_cwe_all.csv")
    if isinstance(fuzz_llm, pd.DataFrame) and not fuzz_llm.empty:
        print("Fuzz LLM:", run_dir/"fuzz_llm.csv")
    if isinstance(fuzz_jul, pd.DataFrame) and not fuzz_jul.empty:
        print("Fuzz Juliet:", run_dir/"fuzz_juliet.csv")
    if isinstance(opt_summ, pd.DataFrame) and not opt_summ.empty:
        print("Opt sweep summaries:", run_dir/"opt_sweep_summaries.csv")

if __name__ == "__main__":
    main()

