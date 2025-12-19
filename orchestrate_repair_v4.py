#!/usr/bin/env python3
"""orchestrate_repair.py

Repairs failed C programs from a verification study run by:
1) Reading the original generated C source that failed.
2) Prompting an LLM to produce a fixed version of the code.
3) Re-compiling with sanitizers and running against available fixtures.

This file was previously corrupted by formatting/minification; this version restores
valid Python syntax, indentation, and a few safety checks (e.g., subprocess timeouts).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import hashlib
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


# --------------------
# Configuration
# --------------------

REPAIR_PROMPT_TEMPLATE = """You are an expert C programmer.
The following code failed verification.

CODE:
```c
{code}
```

ERROR:
Plaintext
{error}

TASK: Fix the error in the C code.

- If it is a memory safety error (AddressSanitizer), fix the buffer overflow/use-after-free/etc.
- If it is a compile error, fix the syntax / missing includes / type issues.
- Prefer minimal, correct changes.
- Return ONLY the fixed C code inside ONE markdown code block.
"""

# Compilation flags (should match your study configuration)
SAN_FLAGS: List[str] = [
    "-O1",
    "-g",
    "-fsanitize=address,undefined",
    "-fno-omit-frame-pointer",
]
SAN_LIBS: List[str] = ["-lm"]


# --------------------
# Helpers
# --------------------

def run_cmd(
    cmd: Sequence[str],
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    input_data: Optional[str] = None,
) -> Optional[subprocess.CompletedProcess[str]]:
    """Run a command and return CompletedProcess; return None on timeout.

    Under heavy parallelism / shared filesystems you can occasionally hit:
      - ETXTBSY (errno=26): 'Text file busy'
      - EACCES (errno=13): 'Permission denied' (often due to x-bit propagation delay)
    We retry these a few times with a short backoff.
    """

    attempts = 6
    backoff_s = 0.05

    for i in range(attempts):
        try:
            return subprocess.run(
                list(cmd),
                cwd=str(cwd) if cwd else None,
                timeout=timeout,
                input=input_data,
                text=True,
                encoding="utf-8",
                errors="ignore",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except subprocess.TimeoutExpired:
            return None
        except OSError as e:
            if e.errno in (2, 13, 26) and i < attempts - 1:
                time.sleep(backoff_s)
                backoff_s = min(backoff_s * 2, 0.5)
                continue
            raise

def extract_code(text: str) -> str:
    """Extract the content of the largest markdown fenced code block.

    If there are no fences, return the text as-is.
    """
    if "```" not in text:
        return text.strip()

    blocks: List[str] = []
    current: List[str] = []
    in_block = False

    for line in text.splitlines():
        if line.strip().startswith("```"):
            if in_block:
                blocks.append("\n".join(current).strip("\n"))
                current = []
                in_block = False
            else:
                in_block = True
                current = []
            continue

        if in_block:
            current.append(line)

    # Handle an unclosed block
    if in_block and current:
        blocks.append("\n".join(current).strip("\n"))

    if not blocks:
        return text.strip()

    # Heuristic: choose the largest block; LLMs sometimes include multiple
    return max(blocks, key=len).strip()


# --------------------
# LLM Client
# --------------------

class LLMClient:
    def __init__(self, provider: str, model: str, temperature: float, api_key: str) -> None:
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.api_key = api_key
        self.client = None

        if provider == "openai":
            from openai import OpenAI  # type: ignore
            self.client = OpenAI(api_key=api_key)
        elif provider == "gemini":
            # google-genai (recommended new client)
            from google import genai  # type: ignore
            self.client = genai.Client(api_key=api_key)
        elif provider == "anthropic":
            import anthropic  # type: ignore
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def generate(self, prompt: str) -> str:
        try:
            if self.provider == "openai":
                resp = self.client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                return resp.choices[0].message.content or ""

            if self.provider == "gemini":
                resp = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config={"temperature": self.temperature},
                )
                return getattr(resp, "text", "") or ""

            if self.provider == "anthropic":
                resp = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                # anthropic returns a list of content blocks
                return resp.content[0].text if resp.content else ""

            return ""
        except Exception as e:
            return f"// LLM Error: {e}"


# --------------------
# Worker Function
# --------------------

def repair_task(task: Dict[str, Any]) -> Dict[str, Any]:
    src_path = Path(task["src_path"])
    out_dir = Path(task["out_dir"])
    fixtures_dir = Path(task["fixtures_dir"])
    provider, model, temp, api_key = task["llm_config"]

    uid = task.get("uid") or ""
    # Many logs won't include uid/binname; avoid 'unknown' collisions under --parallel.
    if not uid or uid == "unknown":
        uid = src_path.stem

    variant = task.get("variant") or src_path.parent.name  # e.g., B1

    # Make filenames unique even if uid repeats (e.g., multiple failing cases for same slug).
    unique = hashlib.sha1(str(src_path).encode("utf-8", errors="ignore")).hexdigest()[:8]
    out_base = f"{variant}_{uid}_{unique}"

    # 1) Initialize LLM
    try:
        llm = LLMClient(provider, model, float(temp), api_key)
    except Exception as e:
        return {"uid": uid, "variant": variant, "status": "llm_init_fail", "log": str(e)}

    # 2) Read original code
    try:
        original_code = src_path.read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return {"uid": uid, "variant": variant, "status": "missing_file"}

    # 3) Prompt LLM
    error_msg = task.get("error_msg", "Unknown Error")
    prompt = REPAIR_PROMPT_TEMPLATE.format(code=original_code, error=error_msg)

    # 4) Generate fix
    fixed_code_raw = llm.generate(prompt)
    fixed_code = extract_code(fixed_code_raw)

    # 5) Save fix
    out_dir.mkdir(parents=True, exist_ok=True)
    fix_filename = f"{out_base}.c"
    fix_path = out_dir / fix_filename
    fix_path.write_text(fixed_code, encoding="utf-8")

    # 6) Verify fix (compile)
    bin_path = out_dir / f"{out_base}.bin"
    cc = shutil.which("clang") or shutil.which("gcc") or "cc"

    compile_cmd = [cc, "-x", "c", str(fix_path), "-o", str(bin_path), *SAN_FLAGS, *SAN_LIBS]
    res_build = run_cmd(compile_cmd, timeout=60)

    if res_build is None:
        return {"uid": uid, "variant": variant, "status": "fix_build_timeout", "path": str(fix_path)}

    if res_build.returncode != 0:
        return {
            "uid": uid,
            "variant": variant,
            "status": "fix_build_fail",
            "log": res_build.stdout or "",
            "path": str(fix_path),
        }

    # Ensure the output binary is executable (helps on restrictive umask / shared FS delays).
    try:
        os.chmod(bin_path, 0o755)
    except OSError:
        # Best-effort; run_cmd will retry on transient EACCES.
        pass

        # If the compiler claimed success but the binary isn't present, fail gracefully.
        if not bin_path.exists():
            listing = ""
            try:
                listing = "\\n".join(sorted(p.name for p in out_dir.glob(f"{out_base}*")))
            except Exception:
                pass
            return {
                "uid": uid,
                "variant": variant,
                "status": "fix_missing_binary",
                "log": (res_build.stdout or "") + ("\\n[dir_listing]\\n" + listing if listing else ""),
                "path": str(fix_path),
            }

    # 7) Verify fix (run against fixtures)
    # uid often looks like: 0021_checksum -> slug: checksum
    if "_" in uid:
        slug = uid.split("_", 1)[1]
    else:
        slug = uid

    fixtures = sorted(fixtures_dir.glob(f"{slug}.in*"))

    def looks_like_sanitizer_crash(out: str) -> bool:
        out = out or ""
        return ("AddressSanitizer" in out) or ("runtime error:" in out)

    crashes = 0

    # If no fixtures exist, run with empty input
    if not fixtures:
        try:
            res_run = run_cmd([str(bin_path)], input_data="", timeout=5)
        except FileNotFoundError:
            return {"uid": uid, "variant": variant, "status": "run_missing_binary", "path": str(fix_path)}
        if res_run and (res_run.returncode != 0 or looks_like_sanitizer_crash(res_run.stdout or "")):
            crashes += 1
    else:
        for f in fixtures:
            inp = f.read_text(encoding="utf-8", errors="ignore")
            try:
                res_run = run_cmd([str(bin_path)], input_data=inp, timeout=5)
            except FileNotFoundError:
                return {"uid": uid, "variant": variant, "status": "run_missing_binary", "path": str(fix_path)}
            if res_run is None:
                # timeout: don't count as crash (original behavior), but record it
                continue

            if res_run.returncode != 0 or looks_like_sanitizer_crash(res_run.stdout or ""):
                crashes += 1
                break  # fail fast

    return {
        "uid": uid,
        "variant": variant,
        "status": "repaired" if crashes == 0 else "fix_still_crashes",
        "path": str(fix_path),
    }


# --------------------
# Main
# --------------------

def _infer_api_key(provider: str) -> Tuple[str, Optional[str]]:
    """Return (env_var_name, api_key_or_None)."""
    provider = provider.lower().strip()
    env_candidates: List[str] = []

    if provider == "openai":
        env_candidates = ["OPENAI_API_KEY"]
    elif provider == "anthropic":
        env_candidates = ["ANTHROPIC_API_KEY"]
    elif provider == "gemini":
        # Common names used in practice; prefer GEMINI_API_KEY if set.
        env_candidates = ["GEMINI_API_KEY", "GOOGLE_API_KEY"]
    else:
        env_candidates = ["OPENAI_API_KEY"]

    for name in env_candidates:
        val = os.environ.get(name)
        if val:
            return name, val
    return env_candidates[0], None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run_dir",
        required=True,
        help="Path to the failed run (e.g. ./study_verification/run_gpt4o_temp02)",
    )
    parser.add_argument("--fixtures", required=True, help="Path to fixtures dir")
    parser.add_argument("--provider", default="openai")
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--parallel", type=int, default=16)
    args = parser.parse_args()

    run_path = Path(args.run_dir).expanduser().resolve()
    fixtures_dir = Path(args.fixtures).expanduser().resolve()

    log_file = run_path / "logs" / "build_results.jsonl"
    repair_dir = run_path / "repair"
    repair_dir.mkdir(parents=True, exist_ok=True)

    # API key (provider-specific)
    key_name, api_key = _infer_api_key(args.provider)
    if not api_key:
        print(f"Error: Set {key_name} environment variable for provider '{args.provider}'.")
        sys.exit(1)

    # 1) Load failures
    print(f"[Repair] Scanning {log_file}...")
    tasks: List[Dict[str, Any]] = []

    try:
        with log_file.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)

                src = rec.get("src", "")
                # Filter: must be generated/LLM code (not Jotai) and must have failed
                is_llm = "gen/" in src or ("gen" in str(src).replace("\\", "/").split("/"))
                failed = (rec.get("rc") != 0) or (rec.get("asan_crash", 0) == 1)

                if not (is_llm and failed):
                    continue

                # Resolve source path robustly relative to run_dir
                src_p = Path(src)
                if not src_p.is_absolute():
                    src_p = run_path / src_p
                src_p = src_p.resolve()

                if not src_p.exists():
                    # Fallback: if log contains "gen/B1/..." but actual path is under run_dir/gen/...
                    if "gen/" in src.replace("\\", "/"):
                        tail = src.replace("\\", "/").split("gen/", 1)[1]
                        possible = run_path / "gen" / tail
                        if possible.exists():
                            src_p = possible.resolve()

                if not src_p.exists():
                    continue

                uid = rec.get("uid") or rec.get("binname") or "unknown"
                error_msg = rec.get("build_log") if rec.get("rc") != 0 else (
                    "AddressSanitizer detected a memory safety error (buffer overflow/use-after-free/etc.)."
                )

                tasks.append(
                    {
                        "uid": uid,
                        "src_path": str(src_p),
                        "out_dir": str(repair_dir),
                        "fixtures_dir": str(fixtures_dir),
                        "error_msg": error_msg,
                        "llm_config": (args.provider, args.model, args.temperature, api_key),
                    }
                )
    except FileNotFoundError:
        print(f"Error: Could not find log file at {log_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Malformed JSONL in {log_file}: {e}")
        sys.exit(1)

    print(f"[Repair] Found {len(tasks)} failed binaries to repair.")

    # 2) Run parallel repair
    results: List[Dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=args.parallel) as exc:
        futures = [exc.submit(repair_task, t) for t in tasks]

        try:
            from tqdm import tqdm  # type: ignore
            pbar = tqdm(total=len(tasks))
        except Exception:
            pbar = None

        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                res = {"uid": "unknown", "variant": "unknown", "status": "worker_exception", "log": str(e)}
            results.append(res)
            if pbar:
                pbar.update(1)

        if pbar:
            pbar.close()

    # 3) Stats
    repaired = sum(1 for r in results if r.get("status") == "repaired")
    total = len(tasks)
    rate = (repaired / total * 100.0) if total > 0 else 0.0

    print("\n" + "=" * 40)
    print(f"REPAIR SUMMARY ({args.model})")
    print(f"Total Failures: {total}")
    print(f"Repaired:       {repaired}")
    print(f"Success Rate:   {rate:.1f}%")
    print("=" * 40)

    # Save log
    with (repair_dir / "repair_log.jsonl").open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()

