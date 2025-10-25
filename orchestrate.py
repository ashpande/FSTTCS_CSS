#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
orchestrate.py — Jotai + LLM, parallel, progress, multi-input sanitizer runs

What it does:
1) (optional) Generate LLM code for tasks (B1 baseline, B2 secure).
2) Sample N Jotai C benchmarks (deterministic; save manifest).
3) Compile with clang & gcc under three profiles:
   - baseline: -O2 -Wall -Wextra
   - hardened: -O2 -Wall -Wextra -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE -pie -Wl,-z,relro -Wl,-z,now -fstack-clash-protection
   - san:      -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
4) Run sanitizer builds with a list of Jotai inputs (default 0,1,2), record crashes/timeouts.
5) Quick (optional) static analysis: clang-tidy + cppcheck.
6) Progress bars via tqdm; parallel workers; run metadata; manifest files.

Outputs live under: study/<run_id>/{gen,seeds,build,logs,runs}
Logs:
  - logs/build_results.jsonl    (one JSON per compile/run job)
  - logs/llm_manifest.json      (LLM outputs)
  - logs/jotai_manifest.txt     (Jotai .c files used)
  - logs/all_sources.txt        (all source paths compiled)
  - logs/run_meta.json          (model, compilers, args, etc)
"""

import argparse, os, sys, json, random, shutil, subprocess, time, hashlib
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed

# ---------- Prompts ----------
PROMPT_BASELINE = """Write a {lang} program that {task}.
Requirements:
- Use only the standard library.
- Provide a small main() that reads from stdin and prints to stdout.
- Keep the code simple and portable.
- Add a short comment with usage.
"""

PROMPT_SECURE = """Write a defensive, memory-conscious {lang} program that {task}.
Security constraints:
- Avoid unsafe APIs (gets, unchecked strcpy/sprintf, etc.).
- Validate all inputs and indices; check return values and allocation failures.
- Initialize variables; avoid UB; handle errors with clear messages.
- Prefer snprintf/strncpy with bounds.
Provide a small main() that reads from stdin and prints to stdout.
Document assumptions in comments.
"""

# ---------- Utils ----------
def run(cmd, cwd=None, env=None, timeout=None):
    return subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout, text=True,
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

def get_versions():
    def get(cmd):
        try:
            p = run(cmd)
            return (p.stdout or "").splitlines()[:2]
        except Exception:
            return []
    return {
        "gcc": get(["gcc","--version"]),
        "clang": get(["clang","--version"]),
        "python": get([sys.executable,"--version"]),
    }

# ---------- LLM ----------
class LLMClient:
    def __init__(self, provider: str, model: str, temperature: float):
        self.provider = provider
        self.model = model
        self.temperature = float(temperature)
        if provider == "gemini":
            from google import genai
            api_key = os.environ.get("GOOGLE_GENAI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if not api_key:
                raise RuntimeError("Set GOOGLE_GENAI_API_KEY (or GOOGLE_API_KEY)")
            self.client = genai.Client(api_key=api_key)
        elif provider == "openai":
            from openai import OpenAI
            if not os.environ.get("OPENAI_API_KEY"):
                raise RuntimeError("Set OPENAI_API_KEY")
            self.client = OpenAI()
        else:
            raise ValueError("provider must be 'gemini' or 'openai'")

    def generate(self, prompt: str) -> str:
        if self.provider == "gemini":
            resp = self.client.models.generate_content(
                model=self.model, contents=prompt, config={"temperature": self.temperature}
            )
            return (resp.text or "").strip()
        else:
            resp = self.client.chat.completions.create(
                model=self.model, temperature=self.temperature,
                messages=[{"role":"user","content":prompt}]
            )
            return resp.choices[0].message.content.strip()

# ---------- Build flags ----------
BASELINE = ["-O2", "-Wall", "-Wextra"]
HARDENED = ["-O2","-Wall","-Wextra",
            "-D_FORTIFY_SOURCE=3","-fstack-protector-strong","-fPIE","-pie",
            "-Wl,-z,relro","-Wl,-z,now","-fstack-clash-protection"]
SAN = ["-O1","-g","-fsanitize=address,undefined","-fno-omit-frame-pointer"]

# ---------- Worker ----------
def compile_and_run_one(job):
    """
    job: dict with keys:
      src, label, uid, binname, cc_name, cc, profile, outdir, run_dir,
      inputs (list[int] or None), timeout
    Returns: dict (JSON-safe)
    """
    src = Path(job["src"])
    cc = job["cc"]
    profile = job["profile"]
    outdir = Path(job["outdir"])
    run_dir = Path(job["run_dir"])
    inputs = job.get("inputs") or []
    timeout = int(job.get("timeout", 30))

    flags = BASELINE if profile=="baseline" else HARDENED if profile=="hardened" else SAN

    # per-source subdir to avoid cross-process clashes
    outdir = outdir / job["uid"]
    ensure_dir(outdir)
    binpath = outdir / job["binname"]

    # compile
    cmd = [cc, "-std=c11", str(src), "-o", str(binpath)] + list(flags)
    p = run(cmd)
    rec = {"src": job["label"], "cc": job["cc_name"], "profile": profile, "rc": p.returncode}
    if p.returncode != 0:
        rec["build_log_tail"] = (p.stdout or "")[-6000:]
        return rec

    # run sanitizer builds with multiple inputs
    if profile == "san" and inputs:
        ensure_dir(run_dir)
        crash_inputs = []
        timeouts = []
        first_log = None
        first_rc = None
        for inp in inputs:
            try:
                pr = run([str(binpath), str(inp)], cwd=run_dir, timeout=timeout)
                out = pr.stdout or ""
                if first_rc is None:
                    first_rc = pr.returncode
                    first_log = out[-6000:]
                crashed = ("ERROR: AddressSanitizer" in out) or ("runtime error:" in out) or (pr.returncode != 0)
                if crashed:
                    crash_inputs.append(inp)
            except subprocess.TimeoutExpired as e:
                timeouts.append(inp)
        rec["asan_inputs_tested"] = inputs
        rec["asan_crash_inputs"] = crash_inputs
        rec["asan_crash"] = 1 if crash_inputs else 0
        rec["asan_timeouts"] = timeouts
        rec["run_rc_first"] = first_rc
        rec["run_log_first_tail"] = first_log
    return rec

# ---------- Static analyzers ----------
def run_clang_tidy(srcs, build_dir: Path, log_path: Path):
    compdb = []
    for s in srcs:
        compdb.append({
            "directory": str(Path.cwd()),
            "command": f"clang -std=c11 -O2 -Wall -Wextra -c {s}",
            "file": str(s)
        })
    write_text(build_dir/"compile_commands.json", json.dumps(compdb, indent=2))
    checks = "clang-analyzer-*,bugprone-*,cert-*,security-*"
    p = run(["clang-tidy","-p", str(build_dir), "-checks", checks] + [str(s) for s in srcs])
    write_text(log_path, p.stdout or "")

def run_cppcheck(srcs, log_path: Path):
    p = run(["cppcheck","--enable=warning,style,performance,portability","--inline-suppr","--quiet"] + [str(s) for s in srcs])
    write_text(log_path, p.stdout or "")

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="Jotai + LLM orchestrator (parallel, multi-input)")
    # Work dirs
    ap.add_argument("--workspace", default="study")
    ap.add_argument("--run_id", default=None)
    ap.add_argument("--clean_output", action="store_true")

    # LLM
    ap.add_argument("--provider", default="gemini", choices=["gemini","openai"])
    ap.add_argument("--model", default="models/gemini-2.5-flash-preview-05-20")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--tasks_json", default="tasks_json/tasks.v2.json", help="If missing, skip LLM generation")

    # Jotai
    ap.add_argument("--use_jotai", action="store_true")
    ap.add_argument("--jotai_root", default="./jotai-benchmarks")
    ap.add_argument("--sample_jotai", type=int, default=3000)
    ap.add_argument("--jotai_seed", type=int, default=1337)
    ap.add_argument("--jotai_manifest_out", default=None)
    ap.add_argument("--jotai_manifest_in", default=None)
    ap.add_argument("--jotai_inputs", default="0,1,2", help="Comma-separated input ids to run, e.g., '0,1,2'")

    # Execution knobs
    ap.add_argument("--parallel", type=int, default=max(8, (os.cpu_count() or 8)))
    ap.add_argument("--timeout", type=int, default=30, help="Seconds per sanitized run per input")
    ap.add_argument("--skip_tidy", action="store_true")
    ap.add_argument("--skip_cppcheck", action="store_true")

    args = ap.parse_args()

    # tqdm (install if missing)
    try:
        from tqdm import tqdm
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "tqdm"])
        from tqdm import tqdm

    # Resolve workspace/run_id
    run_id = args.run_id or datetime.now().strftime("run_%Y%m%d_%H%M%S")
    ws = Path(args.workspace).resolve() / run_id
    if args.clean_output and ws.exists():
        shutil.rmtree(ws)
    d_gen  = ws/"gen"
    d_seeds= ws/"seeds"
    d_build= ws/"build"
    d_logs = ws/"logs"
    d_runs = ws/"runs"
    for d in (d_gen, d_seeds, d_build, d_logs, d_runs):
        ensure_dir(d)

    # Save meta
    meta = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "args": vars(args),
        "versions": get_versions(),
        "model": {"provider": args.provider, "model": args.model, "temperature": args.temperature},
    }
    write_text(d_logs/"run_meta.json", json.dumps(meta, indent=2))

    clang, gcc = detect_cc()

    # 1) LLM generation
    llm_manifest = []
    tasks_path = Path(args.tasks_json)
    if tasks_path.exists():
        llm = LLMClient(args.provider, args.model, args.temperature)
        tasks = json.loads(tasks_path.read_text())
        with tqdm(total=len(tasks.get("tasks", []))*2, desc="LLM gen (B1/B2)") as pbar:
            for i, t in enumerate(tasks.get("tasks", []), 1):
                lang = t.get("lang","C")
                for variant, prompt in [("B1", PROMPT_BASELINE), ("B2", PROMPT_SECURE)]:
                    ptxt = prompt.format(lang=lang, task=t["task"])
                    code = llm.generate(ptxt)
                    # Extract fenced block if present
                    if "```" in code:
                        blocks, keep, cur = [], False, []
                        for line in code.splitlines():
                            if line.strip().startswith("```"):
                                if keep:
                                    blocks.append("\n".join(cur)); cur=[]; keep=False
                                else:
                                    keep=True; cur=[]
                            elif keep:
                                cur.append(line)
                        if cur: blocks.append("\n".join(cur))
                        if blocks: code = max(blocks, key=len)
                    ext = ".c" if lang.upper()=="C" else ".cpp"
                    out = d_gen/variant/f"{i:04d}_{t['slug']}{ext}"
                    write_text(out, code)
                    llm_manifest.append({"variant": variant, "slug": t["slug"], "lang": lang, "path": str(out)})
                    pbar.update(1)
        write_text(d_logs/"llm_manifest.json", json.dumps(llm_manifest, indent=2))
    else:
        print(f"[INFO] tasks file {tasks_path} not found; skipping LLM generation")

    # 2) Jotai sampling
    seeds_manifest = []
    if args.use_jotai:
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

        for i, s in enumerate(picked, 1):
            dst = d_seeds / f"jotai_{i:06d}.c"
            shutil.copyfile(s, dst)
            seeds_manifest.append(str(dst))

    # 3) Collect sources
    sources = []
    sources += list((d_gen/"B1").rglob("*.c"))
    sources += list((d_gen/"B2").rglob("*.c"))
    sources += list(d_seeds.rglob("*.c"))
    sources = [Path(s) for s in sources]
    write_text(d_logs/"all_sources.txt", "\n".join(str(s) for s in sources))
    print(f"[INFO] Total C sources: {len(sources)}")

    # 4) Build job list (unique names per source; per-source build dir)
    inputs = [int(x) for x in str(args.jotai_inputs).split(",") if x.strip().isdigit()]
    jobs = []
    for s in sources:
        rel = s.relative_to(ws).as_posix() if s.is_absolute() else s.as_posix()
        uid = short_hash(rel)
        stem = s.stem
        binname = f"{stem}-{uid}"
        for cc_name, cc in [("clang", clang), ("gcc", gcc)]:
            for profile in ("baseline", "hardened", "san"):
                outdir = d_build/cc_name/profile
                run_dir = d_runs/cc_name/profile/uid
                jobs.append({
                    "src": str(s), "label": rel, "uid": uid, "binname": binname,
                    "cc_name": cc_name, "cc": cc, "profile": profile,
                    "outdir": str(outdir), "run_dir": str(run_dir),
                    "inputs": (inputs if profile=="san" else []),
                    "timeout": args.timeout
                })

    # 5) Parallel execute with tqdm
    results_path = d_logs/"build_results.jsonl"
    total = len(jobs)
    with ProcessPoolExecutor(max_workers=args.parallel) as ex, open(results_path, "w", encoding="utf-8") as outf:
        try:
            from tqdm import tqdm
            pbar = tqdm(total=total, desc="Build+Run", mininterval=0.5, smoothing=0.1)
        except Exception:
            pbar = None
        futs = [ex.submit(compile_and_run_one, j) for j in jobs]
        for fut in as_completed(futs):
            rec = fut.result()
            outf.write(json.dumps(rec) + "\n")
            if pbar: pbar.update(1)
        if pbar: pbar.close()

    # 6) Static analyzers (optional)
    if sources:
        if not args.skip_tidy:
            print("[INFO] Running clang-tidy (may be slow)...")
            run_clang_tidy(sources, d_build/"tidydb", d_logs/"clang-tidy.txt")
        if not args.skip_cppcheck:
            print("[INFO] Running cppcheck...")
            run_cppcheck(sources, d_logs/"cppcheck.txt")

    print("[DONE] Workspace:", str(ws))
    print("       Results:", str(results_path))
    print("       Manifests & meta:", str(d_logs))

if __name__ == "__main__":
    main()

