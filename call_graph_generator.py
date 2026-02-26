import ast
import os
import sys
import json
from collections import defaultdict
from pathlib import Path

OUTPUT_FILE = './report/callgraph.json'


class CallGraphAnalyzer(ast.NodeVisitor):
    """
    Walks the AST to build a detailed call graph including full attribute chains
    and import resolution. E.g. request.args.get(...) → flask.request.args.get
    """

    def __init__(self, module_name=''):
        self.module_name = module_name
        self.current_function = None
        self.function_stack = []
        self.functions = set()
        self.call_graph = defaultdict(set)
        self.function_info = {}
        # name -> module for resolving calls (e.g. "request" -> "flask")
        self.import_map = {}

    # ── Import tracking (so we can resolve request.args.get → flask.request.args.get) ──

    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname or alias.name
            # "import foo" or "import foo.bar" → map to top-level module
            base = alias.name.split('.')[0]
            self.import_map[name] = base
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ''
        for alias in node.names:
            name = alias.asname or alias.name
            # "from flask import request" → request -> "flask"
            self.import_map[name] = module
        self.generic_visit(node)

    # ── Visitors ──

    def visit_FunctionDef(self, node):
        func_name = f'{self.module_name}.{node.name}' if self.module_name else node.name
        self.functions.add(func_name)
        self.function_info[func_name] = {
            'lineno': node.lineno,
            'col_offset': node.col_offset,
            'args': [arg.arg for arg in node.args.args],
            'decorators': [self._decorator_name(d) for d in node.decorator_list],
        }
        self.function_stack.append(self.current_function)
        self.current_function = func_name
        self.generic_visit(node)
        self.current_function = self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        if self.current_function:
            called = self._called_name_detailed(node)
            if called:
                self.call_graph[self.current_function].add(called)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        old = self.module_name
        self.module_name = f'{self.module_name}.{node.name}' if self.module_name else node.name
        self.generic_visit(node)
        self.module_name = old

    # ── Helpers ──

    def _decorator_name(self, node):
        if isinstance(node, ast.Name):      return node.id
        if isinstance(node, ast.Attribute): return node.attr
        return str(node)

    def _attr_chain(self, node):
        """Build full attribute chain for an expression, e.g. request.args.get -> ['request','args','get']."""
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Attribute):
            chain = self._attr_chain(node.value)
            chain.append(node.attr)
            return chain
        return []

    def _called_name_detailed(self, node):
        """
        Extract detailed call target: full attribute chain + import resolution.
        - import sqlite3; sqlite3.connect(...) -> 'sqlite3.connect' (no double prefix)
        - from flask import request; request.args.get(...) -> 'flask.request.args.get'
        """
        chain = self._attr_chain(node.func)
        if not chain:
            return None
        dotted = '.'.join(chain)
        first = chain[0]
        if first in self.import_map:
            module = self.import_map[first]
            # Only prefix when the name is not already the module (e.g. "request" from flask
            # gets "flask.request.args.get"; "sqlite3" from import sqlite3 stays "sqlite3.connect")
            if first != module:
                dotted = f'{module}.{dotted}'
        return dotted

def generate_call_graph(inputs):
    """Analyze Python files from the given paths (folders or .py files) and produce a call graph JSON."""
    python_files = []
    for inp in inputs:
        p = Path(inp)
        if p.is_dir():
            python_files.extend(sorted(p.glob('**/*.py')))
        elif p.suffix == '.py' and p.exists():
            python_files.append(p)
    python_files = sorted(set(python_files))
    if not python_files:
        print('No Python files found. Provide a folder path or .py file paths.')
        sys.exit(1)
    print(f'[*] Analyzing {len(python_files)} Python file(s)')

    all_functions = set()
    all_calls = defaultdict(set)
    all_info = {}
    all_import_maps = {}

    for py_file in python_files:
        module = str(py_file.with_suffix('')).replace(os.sep, '.')
        print(f'    📄 {py_file.name}  (module: {module})')
        try:
            source = py_file.read_text(encoding='utf-8')
            tree = ast.parse(source, filename=str(py_file))
            analyzer = CallGraphAnalyzer(module)
            analyzer.visit(tree)
            all_functions.update(analyzer.functions)
            for func, calls in analyzer.call_graph.items():
                all_calls[func].update(calls)
            all_info.update(analyzer.function_info)
            all_import_maps.update(analyzer.import_map)   # ← NEW
        except Exception as e:
            print(f'    ⚠️  Error: {e}')

    # Build output (convert sets -> sorted lists for JSON)
    cg = {f: sorted(all_calls.get(f, set())) for f in sorted(all_functions)}
    output = {
        'call_graph': cg,
        'import_map': dict(all_import_maps),   # ← NEW: alias → module mapping
        'function_info': all_info,
        'statistics': {
            'total_functions': len(all_functions),
            'total_calls': sum(len(v) for v in cg.values()),
            'files_analyzed': len(python_files),
        },
    }
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(output, f, indent=2)

    print(f'\n✅ Call graph saved to {OUTPUT_FILE}')
    print(f'   {output["statistics"]["total_functions"]} functions, '
          f'{output["statistics"]["total_calls"]} call edges')
    return output


# ── Generate it ──
input_files = sys.argv[1:] if len(sys.argv) > 1 else []
if not input_files:
    print('Usage: python call_graph_generator.py <folder> or <file1.py> [file2.py] ...')
    sys.exit(1)
callgraph_output = generate_call_graph(input_files)

# ── Pretty-print the call graph ──
cg = callgraph_output['call_graph']

print('\n📈 CALL GRAPH  (function → APIs it calls)')
print('=' * 65)
for func in sorted(cg.keys()):
    callees = cg[func]
    if not callees:
        print(f'  {func}  (no outgoing calls)')
    else:
        print(f'\n  {func}')
        for c in callees:
            print(f'    └─▶ {c}')
