"""
Fix Reachable Vulnerabilities: Use an LLM to fix only the CVEs that are
actually reachable in the codebase. The LLM receives two inputs —
reachable CVEs and the application source code — then:
  1. Updates only the used packages in requirements_fixed.txt
  2. Analyzes whether those version bumps introduce breaking API changes
  3. Produces app_fixed.py with all compatibility fixes applied
"""

import json
import os
import sys
from pathlib import Path
from groq import Groq

# ---------------------------------------------------------------------------
# Input: folder name (e.g. sample1) passed as first CLI argument
# ---------------------------------------------------------------------------
if len(sys.argv) < 2:
    print("Usage: python fix_reachable_vuls.py <folder_name>")
    sys.exit(1)

FOLDER = sys.argv[1]

# ---------------------------------------------------------------------------
# Configuration (override via environment variables)
# ---------------------------------------------------------------------------
REACHABLE_VULNS_PATH = os.environ.get("REACHABLE_VULNS_PATH", "reachable_vulns.json")
REQUIREMENTS_PATH = os.environ.get("REQUIREMENTS_PATH", FOLDER + "/requirements.txt")
APP_PATH = os.environ.get("APP_PATH", FOLDER + "/app.py")
REQUIREMENTS_FIXED_PATH = os.environ.get("REQUIREMENTS_FIXED_PATH", FOLDER + "/requirements_fixed.txt")
APP_FIXED_PATH = os.environ.get("APP_FIXED_PATH", FOLDER + "/app_fixed.py")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
MODEL_ID = os.environ.get("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------
def load_reachable_vulns(path: str) -> list[dict]:
    """Load the reachable vulnerabilities JSON produced by reachability_analysis.py."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("details", [])


def load_text_file(path: str) -> str:
    """Read a text file and return its contents."""
    with open(path, encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------
def build_fix_prompt(
    used_vulns: list[dict],
    requirements_content: str,
    app_content: str,
) -> str:
    """Build prompt for the LLM: fix dependency CVEs + check breaking changes."""
    vuln_list = [
        {
            "VulnerabilityID": v["VulnerabilityID"],
            "PkgName": v["PkgName"],
            "InstalledVersion": v["InstalledVersion"],
            "FixedVersion": v["FixedVersion"],
            "Severity": v["Severity"],
        }
        for v in used_vulns
    ]

    prompt = f"""You are a security and compatibility expert. You will FIX ALL REACHABLE CVE VULNERABILITIES without breaking the application.

You are given:
  A) REACHABLE_CVES — a list of CVEs for packages that are actually USED in the code.
  B) The current requirements.txt and app.py source code.

STEP 1 — UPDATE REQUIREMENTS (only for packages that have reachable CVEs)
- For each package listed in REACHABLE_CVES, update its version in requirements.txt to the FixedVersion (or a compatible safe version).
- Leave ALL other packages in requirements.txt UNCHANGED (same version as the current file).
- Preserve comments and line order. Output the COMPLETE requirements_fixed.txt content.

STEP 2 — BREAKING CHANGE ANALYSIS
- After the version updates, consider whether the NEW versions introduce breaking API changes:
  • Renamed or removed functions/classes
  • Changed function signatures (parameters, order, removed/added args)
  • Deprecated APIs that were removed or changed behavior
  • Import path or module structure changes
- Use your knowledge of Flask, Werkzeug, PyYAML, Jinja2, and other common Python libs.
  For each upgraded package, list any breaking changes that could affect the provided app.py.

STEP 3 — FIX THE CODE (breaking-change compatibility only)
- Produce a full app_fixed.py that:
  a) Updates any calls/imports to match the NEW package APIs so the app runs with the updated requirements (breaking-change fixes).
  b) Keeps ALL application logic and routes intact — the app should still work, just with safe dependency versions.
- Do NOT fix code-level issues (SQL injection, XSS, etc.) — focus only on making the code compatible with the updated packages.
- Do NOT change runtime configuration such as host bindings, port numbers, or debug settings — keep them exactly as in the original code.

OUTPUT FORMAT — use these exact delimiters so your response can be parsed:

---REQUIREMENTS_FIXED---
(complete contents of requirements_fixed.txt, line by line)
---REQUIREMENTS_FIXED---

---BREAKING_CHANGE_ANALYSIS---
(plain text: list any breaking changes for the upgraded packages that affect app.py, or "No breaking changes detected.")
---BREAKING_CHANGE_ANALYSIS---

---APP_FIXED---
(complete contents of app_fixed.py — full Python source)
---APP_FIXED---

REACHABLE_CVES (fix ONLY these packages in requirements):
{json.dumps(vuln_list, indent=2)}

CURRENT requirements.txt:
```
{requirements_content}
```

CURRENT app.py:
```python
{app_content}
```"""
    return prompt


# ---------------------------------------------------------------------------
# LLM response parser
# ---------------------------------------------------------------------------
def parse_llm_fix_response(content: str):
    """Extract requirements_fixed, breaking_change_analysis, and app_fixed from LLM response."""

    section_markers = [
        "---REQUIREMENTS_FIXED---",
        "---BREAKING_CHANGE_ANALYSIS---",
        "---APP_FIXED---",
    ]

    def extract(text: str, marker: str) -> str:
        start = text.find(marker)
        if start == -1:
            return ""
        start += len(marker)
        end = text.find(marker, start)
        # If no closing marker, stop at the next *different* section marker
        if end == -1:
            for other in section_markers:
                if other == marker:
                    continue
                pos = text.find(other, start)
                if pos != -1 and (end == -1 or pos < end):
                    end = pos
        if end == -1:
            return text[start:].strip()
        return text[start:end].strip()

    requirements_fixed = extract(content, "---REQUIREMENTS_FIXED---")
    breaking_analysis = extract(content, "---BREAKING_CHANGE_ANALYSIS---")
    app_fixed = extract(content, "---APP_FIXED---")

    # Strip markdown code fences the LLM may have wrapped around the code
    for block in ("```python", "```txt", "```"):
        if app_fixed.startswith(block):
            lines = app_fixed.split("\n")
            if lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            app_fixed = "\n".join(lines)
            break

    # Also strip fences from requirements if present
    for block in ("```txt", "```"):
        if requirements_fixed.startswith(block):
            lines = requirements_fixed.split("\n")
            if lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            requirements_fixed = "\n".join(lines)
            break

    return requirements_fixed, breaking_analysis, app_fixed


# ---------------------------------------------------------------------------
# LLM caller
# ---------------------------------------------------------------------------
def ask_groq_generate_fixes(prompt: str, api_key: str, model: str) -> str:
    """Call Groq to generate requirements_fixed.txt, breaking-change analysis, and app_fixed.py."""
    if not api_key:
        raise ValueError("GROQ_API_KEY not set. Set it via environment variable.")

    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a Python packaging and security expert. "
                    "You know the exact API changes across versions of popular Python packages. "
                    "Respond with ONLY the requested output format — no extra commentary."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=8192,
    )
    return response.choices[0].message.content.strip()


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def main() -> None:
    """Load reachable CVEs + source code, call LLM, write fixed outputs."""
    reachable_path = Path(REACHABLE_VULNS_PATH)
    requirements_path = Path(REQUIREMENTS_PATH)
    app_path = Path(APP_PATH)

    if not reachable_path.exists():
        raise FileNotFoundError(f"Reachable vulns not found: {reachable_path}")
    if not requirements_path.exists():
        raise FileNotFoundError(f"Requirements file not found: {requirements_path}")
    if not app_path.exists():
        raise FileNotFoundError(f"App source not found: {app_path}")

    # --- Load inputs ---
    used_vulns = load_reachable_vulns(REACHABLE_VULNS_PATH)
    requirements_content = load_text_file(REQUIREMENTS_PATH)
    app_content = load_text_file(APP_PATH)

    if not used_vulns:
        print("No reachable vulnerabilities found. Nothing to fix.")
        return

    print(f"Loaded {len(used_vulns)} reachable CVE(s):")
    for v in used_vulns:
        print(f"  - {v['VulnerabilityID']}  ({v['PkgName']} {v['InstalledVersion']} -> {v['FixedVersion']}, {v['Severity']})")

    # --- Build prompt & call LLM ---
    prompt = build_fix_prompt(used_vulns, requirements_content, app_content)
    print(f"\nPrompt length: {len(prompt)} chars")
    print("Calling LLM to generate fixes...")

    raw_response = ask_groq_generate_fixes(prompt, GROQ_API_KEY, MODEL_ID)
    requirements_fixed, breaking_analysis, app_fixed = parse_llm_fix_response(raw_response)

    # --- Validate outputs ---
    if not requirements_fixed:
        print("WARNING: Could not parse REQUIREMENTS_FIXED from LLM response.")
    if not app_fixed:
        print("WARNING: Could not parse APP_FIXED from LLM response. Using original app.py as fallback.")
        app_fixed = app_content

    # --- Print breaking-change analysis ---
    print("\n" + "=" * 60)
    print("BREAKING CHANGE ANALYSIS")
    print("=" * 60)
    print(breaking_analysis if breaking_analysis else "No analysis returned.")

    # --- Write outputs ---
    if requirements_fixed:
        with open(REQUIREMENTS_FIXED_PATH, "w", encoding="utf-8") as f:
            f.write(requirements_fixed + "\n")
        print(f"\nWritten: {REQUIREMENTS_FIXED_PATH}")

    with open(APP_FIXED_PATH, "w", encoding="utf-8") as f:
        f.write(app_fixed + "\n")
    print(f"Written: {APP_FIXED_PATH}")

    print("\nDone.")


if __name__ == "__main__":
    main()
