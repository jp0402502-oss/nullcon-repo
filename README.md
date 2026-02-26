# AI-Native Security Analysis Pipeline

**Nullcon Workshop — Vulnerability Detection, Reachability Analysis & AI-Powered Remediation**

A complete, executable security analysis pipeline that scans dependencies for CVEs, builds a call graph for reachability analysis, runs static code analysis and uses an LLM to generate fixed code — all in a single notebook.


## Pipeline Overview

```
sample1/                          (intentionally vulnerable Flask app)
├── requirements.txt  ──→  ① Trivy        ──→  CVEs in dependencies
├── app.py            ──→  ② AST Call-Graph ──→  Which APIs are actually called
├── app.py            ──→  ③ Bandit (SAST) ──→  Code-level security issues
│
├── ④ LLM Reachability (Trivy + Call-Graph)
│   └──→  Filters CVEs to only those reachable in code
│
├── ⑤ LLM Fix — Reachable CVEs
│   └──→  sample1_reachable_fixed/   (upgraded deps + compatibility fixes)
│
└── ⑥ LLM Fix — Exploitable Issues (Bandit findings)
    └──→  sample1_exploitable_fixed/ (code-level security fixes)
```



## Prerequisites

| Requirement | Details |
|---|---|
| **Google Account** | Required to run the notebook in Google Colab |
| **Groq API Key** | Free key from [console.groq.com](https://console.groq.com) (used for LLM calls) |

No local installs are needed when using Colab — the notebook installs all dependencies (Trivy, Bandit, Groq SDK) automatically.


## Quick Start (Google Colab)

1. **Open the notebook in Google Colab**
   - Upload `nullcon_security_pipeline.ipynb` to [Google Colab](https://colab.research.google.com/), or open it directly from GitHub using `File → Open notebook → GitHub`.

2. **Get a free Groq API key**
   - Go to [console.groq.com](https://console.groq.com) and create an account.
   - Generate an API key from the dashboard.

3. **Paste your API key**
   - Find the cell that contains:
     ```python
     GROQ_API_KEY = 'gsk_YOUR_KEY_HERE'  # <── replace this
     ```
   - Replace `gsk_YOUR_KEY_HERE` with your actual key.

4. **Run All**
   - Click `Runtime → Run all` (or `Ctrl+F9`).
   - The entire pipeline runs in approximately **5 minutes**.

5. **Check the output**
   - `sample1_reachable_fixed/` — upgraded dependencies + compatibility fixes
   - `sample1_exploitable_fixed/` — code-level security fixes


## Quick Start (Local)

```bash
git clone https://github.com/jp0402502-oss/nullcon-repo.git
cd nullcon-repo
```

### Environment Setup

Ensure Python 3.10 or later is installed.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install groq bandit
```

### Groq API Key

1. Go to [console.groq.com](https://console.groq.com) and create a free account.
2. Generate an API key from the dashboard.
3. Set it as an environment variable:

```bash
export GROQ_API_KEY="<PASTE-YOUR-GROQ-API-KEY>"
```


### 1. Install Trivy

```bash
# macOS
brew install trivy

# Windows
1. Download trivy_x.xx.x_windows-64bit.zip file from releases page.
2. Unzip file and copy to any folder.

# Ubuntu/Debian
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

### 2. Scan with Trivy

```bash
# Print results to terminal
trivy fs --severity HIGH,CRITICAL ./sample1

# Save JSON report for the pipeline
trivy fs --severity HIGH,CRITICAL --format json --output ./report/trivy_results.json ./sample1
```

### 3. Generate Call Graph & Run Reachability Analysis

```bash
# Build an AST call graph from the sample app
python3 call_graph_generator.py ./sample1

# Use the LLM to identify which Trivy CVEs are actually reachable in code
python3 reachability_analysis.py
```

> **Output:** `report/callgraph.json` and `report/reachable_vulns.json`

### 4. Fix Reachable Vulnerabilities with AI

```bash
python3 fix_reachable_vuls.py sample1
```

> **Output:** `sample1_reachable_fixed/` containing `requirements.txt` (upgraded deps) and `app.py` (compatibility fixes)

### 5. Detect and Fix Exploitable Issues with AI

```bash
# Run Bandit static analysis
python3 bandit.py ./sample1

# Use the LLM to fix the exploitable findings
python3 fix_exploitable_vuls.py ./sample1
```

> **Output:** `report/app_bandit_report.json` and `sample1_exploitable_fixed/app.py`
