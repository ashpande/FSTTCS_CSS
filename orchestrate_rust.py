#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
import sys
import glob
import time
import logging
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from string import Template

# --- Configuration ---
PROMPT_TEMPLATES = {
    "B1": Template("""
You are an expert Rust programmer.
Write a Rust program to solve the following task.
- Read input from Standard Input (stdin).
- Write output to Standard Output (stdout).
- Do NOT output debug text, markdown, or explanations. Only the raw code.
- Ensure the code compiles with `rustc`.

TASK DESCRIPTION:
$description
"""),
    "B2": Template("""
You are an expert Rust programmer.
Write a SECURE and ROBUST Rust program to solve the following task.
- Use safe Rust (avoid `unsafe` blocks).
- Handle all potential I/O errors and parsing errors gracefully.
- Read input from Standard Input (stdin).
- Write output to Standard Output (stdout).

TASK DESCRIPTION:
$description
"""),
    "B3": Template("""
You are an expert Rust programmer.
Write a Rust program. Handle edge cases defensively.
- Read input from Standard Input (stdin).
- Write output to Standard Output (stdout).

TASK DESCRIPTION:
$description
"""),
    "B4": Template("""
You are an expert Rust programmer.
Write a Rust program.
- Read input from Standard Input (stdin).
- Write output to Standard Output (stdout).

TASK DESCRIPTION:
$description
""")
}

# --- Utils ---
def setup_logging(run_dir):
    log_file = run_dir / "orchestrator.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
    )

def extract_rust_code(text):
    """Extracts code from ```rust ... ``` blocks or returns raw text."""
    if "```" not in text: return text
    blocks = []
    current = []
    in_block = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            if in_block:
                blocks.append("\n".join(current))
                current = []
                in_block = False
            else:
                if "rust" in line.lower() or line.strip() == "```":
                    in_block = True
                    current = []
        elif in_block:
            current.append(line)
    if in_block and current: blocks.append("\n".join(current))
    return max(blocks, key=len) if blocks else text

# --- LLM Client ---
class LLMClient:
    def __init__(self, provider, model, temperature, api_key):
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.api_key = api_key
        if provider == "openai":
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key)
        elif provider == "gemini":
            from google import genai
            self.client = genai.Client(api_key=api_key)
        elif provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)

    def generate(self, prompt):
        try:
            if self.provider == "openai":
                resp = self.client.chat.completions.create(
                    model=self.model, temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.choices[0].message.content
            elif self.provider == "gemini":
                resp = self.client.models.generate_content(
                    model=self.model, contents=prompt, config={"temperature": self.temperature}
                )
                return resp.text
            elif self.provider == "anthropic":
                resp = self.client.messages.create(
                    model=self.model, max_tokens=4096, temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                return resp.content[0].text
        except Exception as e:
            return f"// LLM Error: {e}"

# --- Worker ---
def process_task(task_args):
    task_id, variant, description, run_dir, provider, model, temp, api_key = task_args
    
    # 1. Setup Paths
    # To match your previous naming convention (e.g. 0001_sum-ints), we need to ensure IDs align.
    # Your JSON has "sum-ints", but previous runs used "0001_sum-ints".
    # We will just use the slug from JSON directly: "B1_sum-ints"
    
    uid = f"{variant}_{task_id}"
    gen_dir = run_dir / "gen" / variant
    gen_dir.mkdir(parents=True, exist_ok=True)
    src_path = gen_dir / f"{task_id}.rs" 
    bin_dir = run_dir / "bins" / variant
    bin_dir.mkdir(parents=True, exist_ok=True)
    bin_path = bin_dir / f"{task_id}"

    # 2. Check if already done
    if bin_path.exists():
        return {"uid": uid, "status": "exists", "rc": 0}

    # 3. Generate
    llm = LLMClient(provider, model, temp, api_key)
    prompt = PROMPT_TEMPLATES[variant].safe_substitute(description=description)
    raw_text = llm.generate(prompt)
    code = extract_rust_code(raw_text)
    src_path.write_text(code, encoding="utf-8")

    # 4. Compile (rustc)
    cmd = ["rustc", "-O", str(src_path), "-o", str(bin_path)]
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"uid": uid, "status": "compile_timeout", "rc": -1}

    if res.returncode != 0:
        return {"uid": uid, "status": "build_fail", "rc": res.returncode, "log": res.stdout}

    return {"uid": uid, "status": "success", "rc": 0, "path": str(bin_path)}

# --- Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--run_id", required=True)
    parser.add_argument("--tasks_json", required=True)
    parser.add_argument("--provider", default="openai")
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--parallel", type=int, default=16)
    args = parser.parse_args()

    # Setup
    workspace = Path(args.workspace).resolve()
    run_dir = workspace / args.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(run_dir)
    
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        print("Set API Key env var (OPENAI_API_KEY or GOOGLE_API_KEY)")
        sys.exit(1)

    # Load Tasks
    print(f"Loading tasks from {args.tasks_json}...")
    with open(args.tasks_json) as f:
        data = json.load(f)
    
    # Handle the specific structure: {"tasks": [...]}
    if isinstance(data, dict) and "tasks" in data:
        tasks_list = data["tasks"]
    elif isinstance(data, list):
        tasks_list = data
    else:
        print("Error: JSON must be a list or a dict containing a 'tasks' list.")
        sys.exit(1)

    print(f"Loaded {len(tasks_list)} items from JSON.")

    # Prepare Work
    work_items = []
    variants = ["B1", "B2", "B3", "B4"]
    
    skipped = 0
    for i, item in enumerate(tasks_list):
        # Map specific keys from your file
        task_uid = item.get("slug")
        desc = item.get("task")
        
        if not task_uid or not desc:
            skipped += 1
            continue
            
        for v in variants:
            work_items.append((task_uid, v, desc, run_dir, args.provider, args.model, args.temperature, api_key))

    print(f"Prepared {len(work_items)} Rust tasks (Skipped {skipped}).")
    
    results = []
    with ProcessPoolExecutor(max_workers=args.parallel) as exc:
        futures = [exc.submit(process_task, w) for w in work_items]
        
        count = 0
        total = len(work_items)
        print(f"Processing {total} tasks...")
        
        for f in as_completed(futures):
            res = f.result()
            results.append(res)
            count += 1
            if count % 10 == 0:
                print(f"Progress: {count}/{total}")

    # Save Build Results
    build_log = run_dir / "logs" / "build_results.jsonl"
    build_log.parent.mkdir(exist_ok=True)
    with open(build_log, "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    # Summary
    success = len([r for r in results if r["rc"] == 0])
    print(f"\nDone. Built: {success}/{len(results)}")

if __name__ == "__main__":
    main()
