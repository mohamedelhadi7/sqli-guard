"""Static SQL-injection checker for Python code.

Flags calls like cursor.execute(...) whose SQL text is built from variable
data (string concatenation, f-strings, str.format, % formatting) instead of
using parameterized queries.

Usage:  python checker.py path/to/file_or_folder
Exit code: 0 = nothing found, 1 = findings.
"""
import ast
import sys
from pathlib import Path

EXECUTE_NAMES = {"execute", "executemany", "executescript"}

FIX = ('Use a parameterized query: execute("... WHERE x = ?", (value,)) '
       "and never build SQL from user input.")


def unsafe_reason(node, tainted):
    """Return why `node` (an expression used as SQL text) is unsafe, or None."""
    # "..." + username
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if not (is_const(node.left) and is_const(node.right)):
            return "string concatenation with a variable"
    # "... %s" % username
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            return "% string formatting"
    # f"... {username}"
    if isinstance(node, ast.JoinedStr):
        if any(isinstance(v, ast.FormattedValue) for v in node.values):
            return "f-string with an embedded variable"
    # "... {}".format(username)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)):
        return "str.format() building the query"
    # query = <unsafe>; execute(query)
    if isinstance(node, ast.Name) and node.id in tainted:
        return tainted[node.id] + " (via variable '%s')" % node.id
    return None


def is_const(node):
    return isinstance(node, ast.Constant)


def check_function(func):
    """Check one function body. Tracks simple `name = unsafe_expr` assignments."""
    tainted = {}
    findings = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            reason = unsafe_reason(node.value, tainted)
            if reason:
                tainted[node.targets[0].id] = reason
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in EXECUTE_NAMES and node.args):
            reason = unsafe_reason(node.args[0], tainted)
            if reason:
                findings.append((node.lineno, reason))
    return findings


def check_source(source, filename="<string>"):
    tree = ast.parse(source, filename)
    results = []
    funcs = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for f in funcs:
        results += check_function(f)
    return sorted(set(results))


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    target = Path(argv[1])
    files = [target] if target.is_file() else sorted(target.rglob("*.py"))
    total = 0
    for path in files:
        for lineno, reason in check_source(path.read_text(), str(path)):
            total += 1
            print(f"{path}:{lineno}: possible SQL injection - {reason}")
            print(f"    fix: {FIX}")
    print(f"\n{total} finding(s) in {len(files)} file(s).")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
