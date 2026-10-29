"""Automated secrets safety scanner for PrivacyLens.

Validates that real credentials never leak into tracked files, git history,
or non-ignored workspace files.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

from dotenv import dotenv_values

GENERIC_PATTERNS = {
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    "OpenAI Secret Key": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Personal Access Token": re.compile(r"ghp_[A-Za-z0-9]{36}"),
}

EXEMPT_DIRS = {Path("testsite"), Path("eval")}


def run_git_cmd(args: list[str]) -> str:
    """Run git command and return standard output."""
    res = subprocess.run(["git"] + args, capture_output=True, text=True, encoding="utf-8")
    return res.stdout


def check_env_ignored() -> list[str]:
    """Verify that .env is untracked and properly git-ignored."""
    errors: list[str] = []

    # Check if tracked
    tracked = run_git_cmd(["ls-files", ".env"]).strip()
    if tracked:
        errors.append("CRITICAL: .env is tracked in git index!")

    # Check if ignored
    ignored = run_git_cmd(["check-ignore", ".env"]).strip()
    if not ignored:
        errors.append("CRITICAL: .env is NOT ignored by git!")

    return errors


def get_candidate_files() -> list[Path]:
    """Retrieve all tracked and untracked-not-ignored files."""
    tracked_output = run_git_cmd(["ls-files"])
    untracked_output = run_git_cmd(["ls-files", "--others", "--exclude-standard"])

    all_files = set()
    for line in (tracked_output + "\n" + untracked_output).splitlines():
        line = line.strip()
        if line:
            p = Path(line)
            if p.exists() and p.is_file():
                all_files.add(p)
    return sorted(all_files)


def is_exempt(path: Path) -> bool:
    """Check if file belongs to synthetic test/eval fixture directories."""
    for parent in [path] + list(path.parents):
        if parent in EXEMPT_DIRS:
            return True
    return False


def main() -> int:
    """Execute secrets safety scan."""
    violations: list[str] = []

    # 1. Verify .env tracking/ignored status
    env_errors = check_env_ignored()
    violations.extend(env_errors)

    # 2. Load GEMINI_API_KEY in-process
    env_path = Path(".env")
    gemini_key: str | None = None
    if env_path.exists():
        env_vals = dotenv_values(env_path)
        gemini_key = env_vals.get("GEMINI_API_KEY")

    if not gemini_key:
        gemini_key = os.environ.get("GEMINI_API_KEY")

    candidate_files = get_candidate_files()

    # 3. If a real key is configured, search for its exact value
    if gemini_key and len(gemini_key.strip()) > 8 and gemini_key != "your_key_here":
        key_strip = gemini_key.strip()

        # Check candidate files
        for fpath in candidate_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                if key_strip in content:
                    violations.append(f"GEMINI_API_KEY found in file: {fpath}")
            except Exception as err:
                print(f"Warning: Could not read {fpath}: {err}", file=sys.stderr)

        # Check git log history
        git_history = run_git_cmd(["log", "-p", "--all"])
        if key_strip in git_history:
            violations.append("GEMINI_API_KEY found in git commit history (git log -p --all)!")

    # 4. Scan candidate files outside testsite/ and eval/ for generic credential patterns
    pattern_hits = 0
    for fpath in candidate_files:
        if is_exempt(fpath):
            continue

        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, start=1):
                    for pat_name, pat in GENERIC_PATTERNS.items():
                        if pat.search(line):
                            violations.append(
                                f"Secret pattern [{pat_name}] detected at {fpath}:{line_num}"
                            )
                            pattern_hits += 1
        except Exception as err:
            print(f"Warning: Could not scan {fpath}: {err}", file=sys.stderr)

    # Output results
    if violations:
        print("FAIL: Secrets safety check failed with violations:")
        for v in violations:
            print(f"  - {v}")
        return 1

    print("PASS: Secrets safety checks passed (0 leaks, 0 exposed credentials).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
