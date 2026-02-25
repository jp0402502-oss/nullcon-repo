"""
Reachability Analysis: Use an LLM to identify which Trivy vulnerabilities
are actually reachable (used in code) based on the application's call graph.
"""

import json
import os
import re
from pathlib import Path
from groq import Groq

# Paths (override via environment or change defaults)
TRIVY_PATH = os.environ.get("TRIVY_PATH", "trivy_results.json")
CALLGRAPH_PATH = os.environ.get("CALLGRAPH_PATH", "callgraph.json")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
MODEL_ID = os.environ.get("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")

# Max chars for call graph in prompt to avoid token limits
MAX_CALLGRAPH_CHARS = 25000

def load_trivy_vulnerabilities(path: str) -> list[dict]:
    """Load Trivy JSON and return a flat list of vulnerability dicts (with target/package info)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    vulns = []
    results = data.get("Results", data) if isinstance(data, dict) else data
    if not isinstance(results, list):
        results = [results]

    for result in results:
        if not isinstance(result, dict):
            continue
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            vulns.append({
                "VulnerabilityID": v.get("VulnerabilityID", ""),
                "PkgName": v.get("PkgName", ""),
                "InstalledVersion": v.get("InstalledVersion", ""),
                "FixedVersion": v.get("FixedVersion", ""),
                "Severity": v.get("Severity", ""),
                "Title": v.get("Title", ""),
                "Target": target,
                "_raw": v,
            })

    return vulns


def load_callgraph(path: str) -> dict:
    """Load call graph JSON as-is for the LLM to reason about."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_prompt(vulns: list[dict], callgraph: dict) -> str:
    """Build the prompt for the LLM to decide which vulnerabilities are used in code."""
    vuln_summary = [
        {
            "VulnerabilityID": v["VulnerabilityID"],
            "PkgName": v["PkgName"],
            "InstalledVersion": v["InstalledVersion"],
            "Severity": v["Severity"],
        }
        for v in vulns
    ]

    cg_str = json.dumps(callgraph, indent=2, default=str)
    if len(cg_str) > MAX_CALLGRAPH_CHARS:
        cg_str = cg_str[:MAX_CALLGRAPH_CHARS] + "\n... (truncated)"

    return f"""You are a security analyst. You have two inputs:

1) A list of VULNERABILITIES from a Trivy scan (PkgName = PyPI/distribution name, version, CVE, severity).
2) A CALL GRAPH of a Python codebase. It typically contains:
   - "call_graph": function names → list of callees (e.g. "flask.request.args.get", "yaml.load")
   - "import_map": import names → module names (e.g. "Flask" → "flask", "yaml" → "yaml")

Task: Return ONLY those vulnerabilities where the vulnerable PACKAGE is actually USED in the code according to the call graph.

CRITICAL - Import name vs distribution name: In Python, the name in "import X" often DIFFERS from the PyPI/Trivy package name. Treat them as the same when matching:
- Trivy "pillow" = code "import PIL" or "from PIL import ..."
- Trivy "opencv-python" = code "import cv2"
- Trivy "scikit-learn" = code "import sklearn"
- Trivy "PyYAML" = code "import yaml"
- Trivy "beautifulsoup4" = code "import bs4"
- Trivy "python-dateutil" = code "import dateutil"
Use your knowledge of common Python package-to-import mappings. If the call graph shows any import or call that corresponds to the vulnerable distribution (even under a different name), INCLUDE that vulnerability. Submodules count (e.g. "from PIL.Image import open" means pillow is used). If the call graph shows no corresponding import/call under either PkgName or its known import name, do NOT include it.

Respond with a single JSON object of this exact form (no markdown, no extra text):
{{"used_vulnerability_ids": ["CVE-2023-1234", "GHSA-xxxx"], "reason": "brief explanation"}}

List ONLY the VulnerabilityID values that are used. If none are used, use an empty list: {{"used_vulnerability_ids": [], "reason": "..."}}

---

VULNERABILITIES:
{json.dumps(vuln_summary, indent=2)}

---

CALL GRAPH (Python repo):
{cg_str}"""


def _extract_json_from_response(content: str) -> dict:
    """Extract JSON from LLM response, handling markdown fences and extra text."""
    content = content.strip()
    # Strip markdown code fences
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*\n?", "", content)
        content = re.sub(r"\n?```\s*$", "", content)
        content = content.strip()
    # Try to find JSON object
    start = content.find("{")
    if start >= 0:
        depth = 0
        for i, c in enumerate(content[start:], start):
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return json.loads(content[start : i + 1])
    raise ValueError("No valid JSON object found in response")


def ask_llm_reachability(
    prompt: str,
    api_key: str,
    model: str,
    system_prompt: str | None = None,
) -> dict:
    """Call Groq LLM to identify which vulnerabilities are reachable in the call graph."""
    if not api_key:
        raise ValueError("GROQ_API_KEY is required. Set it via environment variable.")

    client = Groq(api_key=api_key)
    default_system = (
        "You are a Python packaging and security expert. You know the exact mapping "
        "between every PyPI distribution name and its Python import name. "
        "Respond with ONLY valid JSON — no markdown fences, no extra text."
    )
    messages = [
        {"role": "system", "content": system_prompt or default_system},
        {"role": "user", "content": prompt},
    ]

    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0,
        seed=42,
        max_tokens=8192,
    )

    content = response.choices[0].message.content.strip()
    return _extract_json_from_response(content)


def main() -> None:
    """Load data, call LLM, and output reachable vulnerabilities."""
    trivy_path = Path(TRIVY_PATH)
    callgraph_path = Path(CALLGRAPH_PATH)

    if not trivy_path.exists():
        raise FileNotFoundError(f"Trivy results not found: {trivy_path}")
    if not callgraph_path.exists():
        raise FileNotFoundError(f"Call graph not found: {callgraph_path}")

    all_vulns = load_trivy_vulnerabilities(TRIVY_PATH)
    callgraph = load_callgraph(CALLGRAPH_PATH)

    if not all_vulns:
        print("No vulnerabilities found in Trivy results. Exiting.")
        return

    print(f"Loaded {len(all_vulns)} vulnerabilities from Trivy.")
    cg_keys = list(callgraph.keys()) if isinstance(callgraph, dict) else "root is list"
    print(f"Call graph keys: {cg_keys}")

    prompt = build_prompt(all_vulns, callgraph)
    print(f"Prompt length: {len(prompt)} chars")

    try:
        result = ask_llm_reachability(prompt, GROQ_API_KEY, MODEL_ID)
    except json.JSONDecodeError as e:
        print(f"Failed to parse LLM response as JSON: {e}")
        raise
    except ValueError as e:
        print(f"LLM response error: {e}")
        raise

    used_ids = set(result.get("used_vulnerability_ids") or [])
    reason = result.get("reason", "")

    print("\n" + "=" * 60)
    print("REACHABLE VULNERABILITIES (used in code)")
    print("=" * 60)
    print(f"Reason: {reason}\n")

    if not used_ids:
        print("None of the vulnerabilities are reachable in the codebase.")
        return

    # Build lookup for full vuln details
    vuln_by_id = {v["VulnerabilityID"]: v for v in all_vulns}

    for vid in sorted(used_ids):
        v = vuln_by_id.get(vid, {})
        pkg = v.get("PkgName", "?")
        ver = v.get("InstalledVersion", "?")
        sev = v.get("Severity", "?")
        print(f"  • {vid}  ({pkg} {ver}, {sev})")

    print(f"\nTotal: {len(used_ids)} reachable out of {len(all_vulns)} vulnerabilities")

    # Optionally write results to JSON
    output_path = Path(os.environ.get("OUTPUT_PATH", "reachable_vulns.json"))
    output_data = {
        "used_vulnerability_ids": sorted(used_ids),
        "reason": reason,
        "details": [
            vuln_by_id[vid] for vid in sorted(used_ids) if vid in vuln_by_id
        ],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)
    print(f"\nResults written to {output_path}")


if __name__ == "__main__":
    main()
