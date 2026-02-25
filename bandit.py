import subprocess, sys, os, json
from pathlib import Path


def print_findings(json_report_path):
    """Read a Bandit JSON report and print findings sorted by severity."""
    with open(json_report_path, 'r') as f:
        data = json.load(f)

    issues = data.get('results', [])
    if not issues:
        print('  No issues found.')
        return

    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    issues.sort(key=lambda x: severity_order.get(x['issue_severity'], 3))

    print(f'\n  FINDINGS ({len(issues)} issues)')
    print(f'  {"=" * 70}')
    for issue in issues:
        cwe_id = issue.get('issue_cwe', {}).get('id', '?')
        print(f'\n  [{issue["issue_severity"]}] {issue["test_id"]} -- CWE-{cwe_id}')
        print(f'  {issue["issue_text"]}')
        print(f'  Line {issue["line_number"]}: {issue["code"].strip()}')
        print(f'  {"-" * 70}')


def run_bandit(file_path, output_dir='bandit_analysis_results'):
    """Run Bandit on a single file, save JSON report, and print findings."""
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(file_path))[0]
    json_out = os.path.join(output_dir, f'{base}_bandit_report.json')

    result = subprocess.run(
        ['bandit', '-f', 'json', '-ll',
         '--confidence-level', 'medium', file_path],
        capture_output=True, text=True, timeout=60,
    )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        data = {'results': []}

    with open(json_out, 'w') as f:
        json.dump(data, f, indent=2)

    issues = data.get('results', [])
    sev = {}
    for i in issues:
        s = i['issue_severity']
        sev[s] = sev.get(s, 0) + 1
    sev_str = ', '.join(f'{k}: {v}' for k, v in sorted(sev.items()))
    print(f'  {base}: {len(issues)} issues' + (f' ({sev_str})' if sev_str else ''))

    print_findings(json_out)


# ── Main ──
if len(sys.argv) < 2:
    print(f'Usage: python3 {sys.argv[0]} <folder_name>')
    sys.exit(1)

folder_name = sys.argv[1]
if not os.path.isdir(folder_name):
    print(f'Error: "{folder_name}" is not a valid directory')
    sys.exit(1)

app_file = Path(folder_name) / 'app.py'
if not app_file.exists():
    print(f'Error: "{app_file}" not found in folder "{folder_name}"')
    sys.exit(1)

print(f'\nRunning Bandit on {app_file}:\n')
run_bandit(str(app_file))

print(f'\nBandit report saved to bandit_analysis_results/')
