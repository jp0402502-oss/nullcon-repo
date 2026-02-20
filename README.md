# AI-Native Security Analysis Pipeline

**Nullcon Workshop — Vulnerability Detection, Reachability Analysis & AI-Powered Remediation**

A complete, executable security analysis pipeline that scans dependencies for CVEs, builds a call graph for reachability analysis, runs static code analysis and uses an LLM to generate fixed code — all in a single notebook.


## Pipeline Architecture

```mermaid
sequenceDiagram
    participant Setup as Vulnerable App Setup
    participant Trivy as Trivy (CVE Scan)
    participant AST as AST Call Graph (Reachability)
    participant Bandit as Bandit (Static Analysis)
    participant LLM as LLaMA 3.3 70B (Groq)
    participant Output as Fixed Files

    Setup->>Setup: Create vulnerable_app/ (requirements.txt + app.py)
    Setup->>Trivy: Scan requirements.txt
    Trivy-->>AST: 12 CVEs (1 Critical, 11 High)
    Setup->>AST: Parse app.py into AST
    AST-->>AST: Build call graph (12 functions, 40 edges)
    Setup->>Bandit: Run static analysis on app.py
    Bandit-->>LLM: 7 issues (3 High, 4 Medium)
    AST-->>LLM: Reachability data (5 reachable, 7 deprioritized)
    Trivy-->>LLM: CVE list
    LLM->>LLM: Correlate all findings + generate fixes
    LLM-->>Output: requirements_fixed.txt + app_fixed.py
```
