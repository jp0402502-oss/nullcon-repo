# 📊 COMBINED COVERAGE MATRIX — Trivy × AST × Bandit → LLM Fix

## Pipeline: vulnerable_app/ → Trivy + AST Call-Graph + Bandit → LLM (LLaMA 3.3 70B) → Fixed Files

---

### Full Coverage Matrix

| # | Vulnerability | Trivy (CVE) | AST (Reachable) | Bandit (Code) | LLM Fix Applied | Match |
|---|--------------|-------------|-----------------|---------------|-----------------|-------|
| 1 | yaml.load unsafe (Arbitrary Code Exec) | CVE-2020-14343 | ✅ Reachable | B506 / CWE-20 / MEDIUM | ✅ PyYAML 5.3.1→5.4 + yaml.safe_load | 🔴 TRIPLE |
| 2 | Flask debug=True (Remote Code Execution) | CVE-2023-30861 | ✅ Reachable | B201 / CWE-94 / HIGH | ✅ Flask 2.0.1→2.3.2 + debug=False | 🔴 TRIPLE |
| 3 | subprocess shell=True (Command Injection) | — | ✅ Reachable | B602 / CWE-78 / HIGH | ✅ subprocess list args (no shell) | 🟠 Bandit+AST |
| 4 | pickle.loads (Insecure Deserialization) | — | ✅ Reachable | B301 / CWE-502 / MEDIUM | ✅ json.loads (no pickle) | 🟠 Bandit+AST |
| 5 | hashlib.md5 (Weak Cryptography) | — | ✅ Reachable | B324 / CWE-327 / HIGH | ✅ bcrypt (no MD5) | 🟠 Bandit+AST |
| 6 | SQL f-string (SQL Injection) | — | ✅ Reachable | B608 / CWE-89 / MEDIUM | ✅ parameterized query | 🟠 Bandit+AST |
| 7 | host=0.0.0.0 (Bind All Interfaces) | — | ✅ Reachable | B104 / CWE-605 / MEDIUM | ✅ host=localhost | 🟠 Bandit+AST |
| 8 | Werkzeug 2.0.1 (2 CVEs) | CVE-2023-25577, CVE-2024-34069 | ❌ Not used | — | ⏭️ Skipped (not used) | ⚪ Trivy only |
| 9 | certifi 2021.5.30 (1 CVE) | CVE-2023-37920 | ❌ Not used | — | ⏭️ Skipped (not used) | ⚪ Trivy only |
| 10 | cryptography 3.3.2 (3 CVEs) | CVE-2023-0286, CVE-2023-50782, CVE-2026-26007 | ❌ Not used | — | ⏭️ Skipped (not used) | ⚪ Trivy only |
| 11 | urllib3 1.26.5 (4 CVEs) | CVE-2023-43804, CVE-2025-66418, CVE-2025-66471, CVE-2026-21441 | ❌ Not used | — | ⏭️ Skipped (not used) | ⚪ Trivy only |

---

### Summary

| Category | Count | Action Taken |
|----------|-------|-------------|
| 🔴 Triple match (Trivy + AST + Bandit) | 2 | LLM upgraded dependency + fixed code |
| 🟠 Bandit + AST match | 5 | LLM fixed code-level vulnerability |
| ⚪ Trivy only (not in code) | 4 | LLM skipped (no risk to application) |
| **✅ Total fixed by LLM** | **7** | |
| **⏭️ Skipped (safe to ignore)** | **4** | |

---

### Match Categories Explained

#### 🔴 TRIPLE — Highest Priority (Trivy + AST + Bandit all confirm)

These vulnerabilities are confirmed by **all three tools**:
- **Trivy** found a CVE in the dependency version
- **AST Call-Graph** proved the vulnerable API is called in the code
- **Bandit** identified the exact insecure code pattern

**LLM Action:** Upgraded the dependency version in `requirements_fixed.txt` AND fixed the code pattern in `app_fixed.py`.

| Finding | Trivy | AST Evidence | Bandit | LLM Fix |
|---------|-------|-------------|--------|---------|
| yaml.load unsafe | CVE-2020-14343 (PyYAML 5.3.1, CRITICAL) | `yaml.load` called by `app.parse_config()` | B506: "Use of unsafe yaml load" (CWE-20) | PyYAML 5.3.1→5.4 + `yaml.load()` → `yaml.safe_load()` |
| Flask debug=True | CVE-2023-30861 (Flask 2.0.1, HIGH) | `flask.session.get`, `flask.session.clear`, `flask.redirect` called by `login()`, `dashboard()`, `logout()` | B201: "Flask app run with debug=True" (CWE-94) | Flask 2.0.1→2.3.2 + `debug=True` → `debug=False` |

#### 🟠 Bandit + AST — Code-Level Bugs (no dependency CVE)

These are **application-level security bugs** found by Bandit in code that AST confirms is reachable via Flask routes. Trivy can't find these because they are in your source code, not in third-party packages.

| Finding | Bandit ID | CWE | Code Before | Code After |
|---------|-----------|-----|-------------|------------|
| Command Injection | B602 | CWE-78 | `subprocess.check_output(f'ping -c 1 {host}', shell=True)` | `subprocess.check_output(['ping', '-c', '1', host])` |
| Insecure Deserialization | B301 | CWE-502 | `pickle.loads(data.encode('latin1'))` | `json.loads(data)` |
| Weak Cryptography | B324 | CWE-327 | `hashlib.md5(password.encode()).hexdigest()` | `bcrypt.hashpw(password.encode(), bcrypt.gensalt())` |
| SQL Injection | B608 | CWE-89 | `f"DELETE FROM users WHERE id={user_id}"` | `cursor.execute("DELETE FROM users WHERE id=?", (user_id,))` |
| Bind All Interfaces | B104 | CWE-605 | `app.run(host='0.0.0.0')` | `app.run(host='localhost')` |

#### ⚪ Trivy Only — Deprioritized (not reachable in code)

These dependency CVEs exist but the vulnerable package APIs are **never called** in `app.py`. The LLM correctly skipped them.

| Package | CVEs | Why Skipped |
|---------|------|-------------|
| Werkzeug 2.0.1 | CVE-2023-25577, CVE-2024-34069 | Indirect Flask dependency — no direct Werkzeug API calls |
| certifi 2021.5.30 | CVE-2023-37920 | Certificate store — not imported or called in app.py |
| cryptography 3.3.2 | CVE-2023-0286, CVE-2023-50782, CVE-2026-26007 | Not imported or used in app.py |
| urllib3 1.26.5 | CVE-2023-43804, CVE-2025-66418, CVE-2025-66471, CVE-2026-21441 | Not imported or used in app.py |

---

### Output Files

| File | Description |
|------|-------------|
| `vulnerable_app/requirements_fixed.txt` | Updated dependency versions (only Flask and PyYAML upgraded) |
| `vulnerable_app/app_fixed.py` | Complete fixed source code with all 7 security fixes applied |

---

### Pipeline Flow

```
vulnerable_app/
├── requirements.txt ──→ ① Trivy ──→ 12 CVEs found
├── app.py ──→ ② AST Call-Graph ──→ Reachability map (which APIs are called)
├── app.py ──→ ③ Bandit ──→ 7 code-level issues found
│
├── LLM Call #1 (Trivy + AST) ──→ Filter: 2 used in code, 10 not used
│
└── LLM Call #2 (2 used CVEs + 7 Bandit findings + source code)
    ├── ✅ requirements_fixed.txt (Flask 2.0.1→2.3.2, PyYAML 5.3.1→5.4)
    └── ✅ app_fixed.py (all 7 Bandit issues fixed + breaking change safe)
```
