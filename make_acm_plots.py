#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aggregate study logs (LLM, Jotai, Juliet) and produce ACM-style figures & tables.

- Computes build success, sanitizer crash rates (with 95% Wilson CI)
- Breakdowns by corpus, compiler, opt level, and (for LLM) prompt variant (B1..B4)
- Fuzzing uplift tables (Juliet vs LLM)
- Scatter (file size vs. crash) with 95th-percentile clipping to de-emphasize outliers
- Saves PNG+PDF plots and CSV tables to an output directory (timestamped run folder)

Tested against a layout:
  /var/lib/ansible/ashutosh/
    study/
      big_combo_v2/logs/{build_results.jsonl, llm_manifest.json, afl_slice*/... , opt_sweep_*/...}
      jotai_only_fix_v1/logs/build_results.jsonl
    study_juliet/
      juliet_*/logs/build_results.jsonl
      juliet_afl_slice/logs/afl_slice_summary*.csv

Run:
  python3 make_acm_plots.py \
    --root /var/lib/ansible/ashutosh \
    --outdir /var/lib/ansible/ashutosh/plots_acm
"""

import argparse, json, os, sys, math, re, glob, time
from pathlib import Path
from collections import defaultdict

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt
from tqdm import tqdm

try:
    import seaborn as sns  # optional
    sns.set_context("paper", font_scale=1.1)
    sns.set_style("whitegrid")
except Exception:
    pass


# ----------------------------- utils -----------------------------

def wilson_ci(k, n, z=1.96):
    """Return (p, lo, hi) for 95% Wilson interval."""
    if n <= 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + (z**2)/n
    centre = p + (z**2)/(2*n)
    margin = z * math.sqrt((p*(1-p) + (z**2)/(4*n)) / n)
    lo = (centre - margin) / denom
    hi = (centre + margin) / denom
    return p, max(0.0, lo), min(1.0, hi)

def read_jsonl(path: Path):
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows

def load_csvs(patterns):
    dfs = []
    for pat in patterns:
        for fp in glob.glob(pat):
            try:
                dfs.append(pd.read_csv(fp))
            except Exception:
                pass
    if not dfs:
        return pd.DataFrame()
    return pd.concat(dfs, ignore_index=True)

def is_llm_path(s: str) -> bool:
    if not s: return False
    return "/gen/" in s or "\\gen\\" in s

def llm_variant_from_path(s: str):
    if not s: return None
    m = re.search(r"/gen/(B[1-4])/", s) or re.search(r"\\gen\\(B[1-4])\\", s)
    return m.group(1) if m else None

def file_size_bytes(src: str):
    try:
        p = Path(src)
        return p.stat().st_size if p.exists() else None
    except Exception:
        return None

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# ---------------------------- harvesting ----------------------------

def harvest_llm(root: Path):
    """Collect LLM build/run rows (build_results.jsonl) + opt-sweep + afl slice summaries."""
    logs_dir = root/"study"/"big_combo_v2"/"logs"
    build_rows = read_jsonl(logs_dir/"build_results.jsonl")

    # If missing LLM rows in results, we can derive LLM file list from manifest or filesystem.
    llm_manifest = []
    mp = logs_dir/"llm_manifest.json"
    if mp.exists():
        try:
            llm_manifest = json.loads(mp.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            pass

    # opt sweep summaries (timestamped subfolders)
    opt_summaries = load_csvs([str(logs_dir/"opt_sweep_*"/"opt_sweep_summary_*.csv")])

    # afl slice summaries (timestamped; and possibly a flat one)
    afl_summaries = load_csvs([str(logs_dir/"afl_slice_*"/"afl_slice_summary_*.csv"),
                               str(logs_dir/"afl_slice_summary.csv")])

    return {
        "build_rows": build_rows,
        "manifest": llm_manifest,
        "opt_summaries": opt_summaries,
        "afl_summaries": afl_summaries,
        "logs_dir": logs_dir
    }

def harvest_jotai(root: Path):
    logs_dir = root/"study"/"jotai_only_fix_v1"/"logs"
    build_rows = read_jsonl(logs_dir/"build_results.jsonl")
    return {"build_rows": build_rows, "logs_dir": logs_dir}

def harvest_juliet(root: Path):
    study_juliet = root/"study_juliet"
    candidates = list(study_juliet.glob("juliet_*"))
    per_run = []
    for run in candidates:
        br = run/"logs"/"build_results.jsonl"
        if br.exists():
            per_run.append({"run_id": run.name, "rows": read_jsonl(br)})
    # afl slice summaries (optional)
    afl_summaries = load_csvs([str(study_juliet/"juliet_afl_slice"/"logs"/"afl_slice_summary*.csv")])
    return {"runs": per_run, "afl_summaries": afl_summaries}

# ---------------------------- aggregation ----------------------------

def frame_from_rows(rows, corpus_name):
    if not rows:
        return pd.DataFrame()
    recs = []
    for r in rows:
        src = r.get("src") or r.get("label") or ""
        cc  = r.get("cc") or r.get("compiler") or r.get("cc_name")
        opt = r.get("opt") or r.get("opt_level") or r.get("profile")  # 'san','base' might show
        prof = r.get("profile")
        rc = r.get("rc")
        asan = r.get("asan_crash")
        if isinstance(asan, str):
            asan = 0 if asan.strip().lower() in ("","0","false","none") else 1
        size = file_size_bytes(src) if src else None
        variant = llm_variant_from_path(src)
        recs.append({
            "corpus": corpus_name,
            "src": src,
            "cc": cc,
            "opt": opt,
            "profile": prof,
            "rc": rc,
            "asan_crash": int(asan) if asan is not None else None,
            "filesize": size,
            "llm_variant": variant
        })
    return pd.DataFrame(recs)

def rate_ci(k, n):
    p, lo, hi = wilson_ci(k, n, z=1.96)
    return round(100*p,2), round(100*lo,2), round(100*hi,2)

def summarize(df, label, denom="built"):
    if df.empty:
        return pd.DataFrame([{"group": label, "n_total": 0, "n_built": 0, "asan_hits": 0,
                              "rate_%": 0.0, "lo_%": 0.0, "hi_%": 0.0}])
    n_total = len(df)
    built_df = df[df["rc"]==0] if "rc" in df.columns else df
    n_built = len(built_df)
    asan_hits = int((built_df["asan_crash"]>0).sum()) if "asan_crash" in built_df else 0
    if denom == "built":
        rate, lo, hi = rate_ci(asan_hits, n_built)
    else:
        rate, lo, hi = rate_ci(asan_hits, n_total)
    return pd.DataFrame([{
        "group": label,
        "n_total": n_total,
        "n_built": n_built,
        "asan_hits": asan_hits,
        "rate_%": rate,
        "lo_%": lo,
        "hi_%": hi
    }])

# ----------------------------- plotting -----------------------------

def bar_with_ci(ax, df, xcol, ycol="rate_%", locol="lo_%", hicol="hi_%", title="", ylabel="Crash rate (%)"):
    x = list(df[xcol])
    y = list(df[ycol])
    lo = list(df[locol])
    hi = list(df[hicol])
    errs = [[y[i]-lo[i] for i in range(len(y))], [hi[i]-y[i] for i in range(len(y))]]
    ax.bar(x, y)
    ax.errorbar(x, y, yerr=errs, fmt='none', capsize=4, linewidth=1)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_ylim(0, max(5, min(100, max(hi)+5)))
    ax.grid(axis='y', linestyle='--', alpha=0.4)

def scatter_size_vs_crash(ax, df, title=""):
    # Clip filesize to 95th percentile to reduce axis skew
    d = df.copy()
    d = d[(d["rc"]==0) & d["filesize"].notna()]
    if d.empty:
        ax.set_title(title + " (no data)")
        return
    clip = d["filesize"].quantile(0.95)
    d["filesize_clip"] = d["filesize"].clip(upper=clip)
    # x: size (KB), y: 0/1 crash
    ax.scatter(d["filesize_clip"]/1024.0, d["asan_crash"].fillna(0), s=8)
    ax.set_xlabel("Source size (KB, clipped @95th pct)")
    ax.set_ylabel("Sanitizer crash (0/1)")
    ax.set_title(title)
    ax.grid(True, linestyle='--', alpha=0.3)

def ensure_out(outdir: Path):
    ts = time.strftime("%Y%m%d_%H%M%S")
    run_dir = outdir / f"acm_figs_{ts}"
    ensure_dir(run_dir)
    return run_dir

def save_fig(fig, run_dir: Path, name: str, tight=True):
    png = run_dir / f"{name}.png"
    pdf = run_dir / f"{name}.pdf"
    if tight:
        fig.tight_layout()
    fig.savefig(png, dpi=300)
    fig.savefig(pdf)
    plt.close(fig)
    return png, pdf

# ------------------------------ main -------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="e.g., /var/lib/ansible/ashutosh")
    ap.add_argument("--outdir", required=True, help="where to place plots/tables")
    ap.add_argument("--denom", choices=["built","all"], default="built",
                    help="denominator for crash rates (built binaries or all targets)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    outdir = Path(args.outdir).resolve()
    run_dir = ensure_out(outdir)

    # Harvest
    llm = harvest_llm(root)
    jotai = harvest_jotai(root)
    juliet = harvest_juliet(root)

    # DataFrames
    df_llm = frame_from_rows(llm["build_rows"], "LLM")
    df_jotai = frame_from_rows(jotai["build_rows"], "Jotai")
    # Juliet: multiple runs; concat
    df_juliet = pd.concat([frame_from_rows(run["rows"], run["run_id"]) for run in juliet["runs"]], ignore_index=True) \
                 if juliet["runs"] else pd.DataFrame()

    # ----------------- CORE SUMMARY (LLM vs Jotai vs Juliet) -----------------
    core = []
    core.append(summarize(df_llm, "LLM (san)", denom=args.denom))
    core.append(summarize(df_jotai, "Jotai (san)", denom=args.denom))
    if not df_juliet.empty:
        # Aggregate Juliet across runs (san-only runs usually have profile "san" or opt labels)
        df_juliet_san = df_juliet[(df_juliet["profile"].isin(["san"])) | (df_juliet["opt"].isin(["O0","O2","san"]))]
        core.append(summarize(df_juliet_san, "Juliet (san combined)", denom=args.denom))
    core_df = pd.concat(core, ignore_index=True)
    core_df.to_csv(run_dir/"core_summary.csv", index=False)

    # Plot: bar with CI for core
    fig, ax = plt.subplots(figsize=(6,4))
    bar_with_ci(ax, core_df, "group", title=f"Crash rate with 95% CI ({args.denom} denominator)")
    save_fig(fig, run_dir, "core_bar_ci")

    # ----------------- LLM PROMPT VARIANTS (B1..B4) -----------------
    llm_b = df_llm[df_llm["llm_variant"].notna()]
    if not llm_b.empty:
        rows = []
        for v, g in llm_b.groupby("llm_variant"):
            rows.append(summarize(g, f"LLM {v}", denom=args.denom))
        llm_b_df = pd.concat(rows, ignore_index=True)
        llm_b_df.to_csv(run_dir/"llm_prompt_summary.csv", index=False)

        fig, ax = plt.subplots(figsize=(6,4))
        bar_with_ci(ax, llm_b_df, "group", title=f"LLM prompt variants ({args.denom})")
        save_fig(fig, run_dir, "llm_prompts_bar_ci")

    # ----------------- COMPILER × OPT (LLM only) -----------------
    llm_co = df_llm[(df_llm["cc"].notna()) & (df_llm["opt"].notna())]
    if not llm_co.empty:
        mat = []
        for (cc, opt), g in llm_co.groupby(["cc","opt"]):
            s = summarize(g, f"{cc}@{opt}", denom=args.denom)
            s["cc"] = cc; s["opt"] = opt
            mat.append(s)
        llm_co_df = pd.concat(mat, ignore_index=True)
        llm_co_df.sort_values(["cc","opt"], inplace=True)
        llm_co_df.to_csv(run_dir/"llm_cc_opt_summary.csv", index=False)

        # Clustered bar (cc@opt)
        fig, ax = plt.subplots(figsize=(7,4))
        labels = llm_co_df["group"].tolist()
        vals   = llm_co_df["rate_%"].tolist()
        lo     = llm_co_df["lo_%"].tolist()
        hi     = llm_co_df["hi_%"].tolist()
        errs = [[vals[i]-lo[i] for i in range(len(vals))],
                [hi[i]-vals[i] for i in range(len(vals))]]
        ax.bar(labels, vals)
        ax.errorbar(labels, vals, yerr=errs, fmt='none', capsize=3, linewidth=1)
        ax.set_ylabel("Crash rate (%)")
        ax.set_title(f"LLM: compiler × opt ({args.denom})")
        ax.tick_params(axis='x', rotation=45)
        ax.grid(axis='y', linestyle='--', alpha=0.4)
        save_fig(fig, run_dir, "llm_cc_opt_bar_ci")

    # ----------------- SCATTER: FILE SIZE vs CRASH (LLM, Jotai) -----------------
    # LLM
    if not df_llm.empty and df_llm["filesize"].notna().any():
        fig, ax = plt.subplots(figsize=(6,4))
        scatter_size_vs_crash(ax, df_llm, title="LLM: size vs sanitizer crash")
        save_fig(fig, run_dir, "llm_scatter_size_crash")
    # Jotai
    if not df_jotai.empty and df_jotai["filesize"].notna().any():
        fig, ax = plt.subplots(figsize=(6,4))
        scatter_size_vs_crash(ax, df_jotai, title="Jotai: size vs sanitizer crash")
        save_fig(fig, run_dir, "jotai_scatter_size_crash")

    # ----------------- FUZZING UPLIFT TABLES -----------------
    # LLM AFL slice summaries (likely 0% crash discover)
    if isinstance(llm["afl_summaries"], pd.DataFrame) and not llm["afl_summaries"].empty:
        afl_llm = llm["afl_summaries"].copy()
        # Normalize column name if ≥ appears differently
        for c in list(afl_llm.columns):
            if "≥" in c or "â‰¥" in c:
                afl_llm = afl_llm.rename(columns={c: "targets_with_ge_1_crash"})
        afl_llm.to_csv(run_dir/"llm_afl_slice_summaries.csv", index=False)

    # Juliet AFL slice summaries (uplift expected)
    if isinstance(juliet["afl_summaries"], pd.DataFrame) and not juliet["afl_summaries"].empty:
        afl_jul = juliet["afl_summaries"].copy()
        for c in list(afl_jul.columns):
            if "≥" in c or "â‰¥" in c:
                afl_jul = afl_jul.rename(columns={c: "targets_with_ge_1_crash"})
        afl_jul.to_csv(run_dir/"juliet_afl_slice_summaries.csv", index=False)

    # ----------------- PRINT WHAT WE FOUND -----------------
    print(f"[OK] Wrote tables & figures to: {run_dir}")
    print("  - core_summary.csv, llm_prompt_summary.csv, llm_cc_opt_summary.csv (if available)")
    print("  - PNG/PDF plots: core_bar_ci, llm_prompts_bar_ci, llm_cc_opt_bar_ci, llm_scatter_size_crash, jotai_scatter_size_crash")
    if isinstance(llm["afl_summaries"], pd.DataFrame) and not llm["afl_summaries"].empty:
        print("  - llm_afl_slice_summaries.csv")
    if isinstance(juliet["afl_summaries"], pd.DataFrame) and not juliet["afl_summaries"].empty:
        print("  - juliet_afl_slice_summaries.csv")

if __name__ == "__main__":
    main()

