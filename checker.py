"""Static multi-vulnerability checker for Python code.

Reads source with the `ast` module and flags, per function:
  - SQL injection: a cursor.execute()-style call whose query text is built
    from variable data (concatenation, f-strings, str.format, % formatting)
    instead of a parameterized query.
  - Command injection: os.system / os.popen / subprocess.* calls where the
    command is a shell string built from variable data.
  - Path traversal: open() / os.path.join() where a path comes straight
    from variable data with no validation in the same function.
  - Weak hashing for passwords: hashlib.md5()/sha1() applied to a variable
    whose name suggests a password or secret.
  - Insecure deserialization: pickle.load(s) or yaml.load() without
    SafeLoader on data that isn't a literal.

Each finding reports file, line, category and a one-line fix.

Usage:  python checker.py path/to/file_or_folder
Exit code: 0 = nothing found, 1 = findings.
"""
import ast
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def is_const(node):
    return isinstance(node, ast.Constant)


def call_name(node):
    """Dotted call name for ast.Call, e.g. 'os.system' or 'cur.execute'."""
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        parts = []
        cur = f
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def built_from_variable(node):
    """True if `node` is an expression built from non-constant data:
    string concatenation, f-string, str.format(), % formatting, or
    os.path.join() with a non-constant component."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return not (is_const(node.left) and is_const(node.right))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return isinstance(node.left, ast.Constant) and isinstance(node.left.value, str)
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Constant)):
        return True
    if isinstance(node, ast.Call) and call_name(node) == "os.path.join":
        return any(not is_const(a) for a in node.args)
    return False


def how_built(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "string concatenation with a variable"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "% string formatting"
    if isinstance(node, ast.JoinedStr):
        return "f-string with an embedded variable"
    if isinstance(node, ast.Call) and call_name(node) == "os.path.join":
        return "os.path.join() with a variable component"
    return "str.format() building the text"


# ---------------------------------------------------------------------------
# Per-category detectors. Each takes (call_node, name, tainted) and the
# tainted dict mapping variable name -> reason string, and returns a
# (category, reason) tuple or None.
# ---------------------------------------------------------------------------

EXECUTE_NAMES = {"execute", "executemany", "executescript"}
SHELL_CALL_SUFFIXES = {"system", "popen"}
SUBPROCESS_NAMES = {"subprocess.run", "subprocess.call", "subprocess.Popen",
                     "subprocess.check_call", "subprocess.check_output"}
HASH_FUNCS = {"md5", "sha1"}
SECRET_NAME_HINTS = ("password", "passwd", "pwd", "secret", "token", "pin")


def arg_reason(node, tainted):
    """Why `node` (an argument expression) is unsafe, or None."""
    if built_from_variable(node):
        return how_built(node)
    if isinstance(node, ast.Name) and node.id in tainted:
        return tainted[node.id] + " (via variable '%s')" % node.id
    return None


def check_sql_injection(node, name, tainted):
    if name is None:
        return None
    short = name.split(".")[-1]
    if short in EXECUTE_NAMES and node.args:
        reason = arg_reason(node.args[0], tainted)
        if reason:
            return ("sql_injection", reason,
                    'Use a parameterized query: execute("... WHERE x = ?", '
                    "(value,)) and never build SQL from user input.")
    return None


def check_command_injection(node, name, tainted):
    if name is None:
        return None
    short = name.split(".")[-1]
    if name == "os.system" or (name == "os.popen"):
        if node.args:
            reason = arg_reason(node.args[0], tainted)
            if reason:
                return ("command_injection", reason,
                        "Avoid a shell string built from input: use "
                        "subprocess.run([...], shell=False) with a list of "
                        "arguments, or shlex.quote() if a shell is required.")
    if name in SUBPROCESS_NAMES and node.args:
        first = node.args[0]
        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant)
            and kw.value.value is True for kw in node.keywords)
        if shell_true:
            reason = arg_reason(first, tainted)
            if reason:
                return ("command_injection", reason,
                        "subprocess(..., shell=True) with input in the "
                        "command string is a shell-injection risk: build "
                        "the command as a list and drop shell=True.")
    return None


PATH_SINKS = {"open", "os.remove", "os.unlink", "send_file",
              "send_from_directory"}


def check_path_traversal(node, name, tainted):
    if name not in PATH_SINKS or not node.args:
        return None
    reason = arg_reason(node.args[0], tainted)
    if reason:
        return ("path_traversal", reason,
                "Validate and resolve the path (e.g. os.path.realpath + "
                "check it stays under a known base directory) before "
                "opening it with user-supplied input.")
    return None


def underlying_name(node):
    """Best-effort variable name behind `node`: `x` -> 'x', `x.encode()` ->
    'x', `x.encode('utf-8')` -> 'x'. Returns None if there isn't one."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return underlying_name(node.func.value)
    return None


def check_weak_hash(node, name, tainted):
    if name in ("hashlib.md5", "hashlib.sha1") and node.args:
        var_name = underlying_name(node.args[0])
        if var_name and any(h in var_name.lower() for h in SECRET_NAME_HINTS):
            return ("weak_hash",
                    "%s() used on '%s', which looks like a password/secret"
                    % (name.split(".")[-1], var_name),
                    "Use a password-hashing function with a salt and work "
                    "factor (e.g. bcrypt, scrypt, or hashlib.pbkdf2_hmac), "
                    "never a fast general-purpose hash for passwords.")
    return None


def check_insecure_deserialize(node, name, tainted):
    if name in ("pickle.load", "pickle.loads") and node.args:
        arg = node.args[0]
        if not is_const(arg):
            var_name = underlying_name(arg)
            reason = (tainted.get(var_name) + " (via variable '%s')" % var_name
                       if var_name and var_name in tainted
                       else "data read from a variable, not a fixed literal")
            return ("insecure_deserialization", reason,
                    "pickle can execute arbitrary code on load; use a safe "
                    "format (json) or verify/sign the data before "
                    "unpickling it.")
    if name == "yaml.load" and node.args:
        has_safe_loader = any(
            kw.arg == "Loader" and isinstance(kw.value, ast.Attribute)
            and kw.value.attr == "SafeLoader" for kw in node.keywords)
        if not has_safe_loader:
            return ("insecure_deserialization",
                    "yaml.load() without Loader=yaml.SafeLoader",
                    "Use yaml.safe_load() (or Loader=yaml.SafeLoader): "
                    "plain yaml.load() can construct arbitrary Python "
                    "objects from the input.")
    return None


DETECTORS = [check_sql_injection, check_command_injection,
             check_path_traversal, check_weak_hash,
             check_insecure_deserialize]


# ---------------------------------------------------------------------------
# AST walk
# ---------------------------------------------------------------------------

def check_function(func):
    """Check one function body. Tracks simple `name = unsafe_expr`
    assignments so taint flows through one hop of local variables."""
    tainted = {}
    findings = []  # (lineno, category, reason, fix)
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            if built_from_variable(node.value):
                tainted[node.targets[0].id] = how_built(node.value)
        if isinstance(node, ast.Call):
            name = call_name(node)
            for detector in DETECTORS:
                result = detector(node, name, tainted)
                if result:
                    category, reason, fix = result
                    findings.append((node.lineno, category, reason, fix))
    return findings


def check_source(source, filename="<string>"):
    tree = ast.parse(source, filename)
    results = []
    funcs = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for f in funcs:
        results += check_function(f)
    return sorted(set(results))


def check_path(path):
    """Check a single .py file or every .py file under a directory.
    Returns a list of (filename, lineno, category, reason, fix)."""
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.rglob("*.py"))
    all_findings = []
    for f in files:
        try:
            source = f.read_text()
            tree_ok = True
            ast.parse(source, str(f))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for lineno, category, reason, fix in check_source(source, str(f)):
            all_findings.append((str(f), lineno, category, reason, fix))
    return all_findings


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    target = argv[1]
    findings = check_path(target)
    if not findings:
        print("No issues found.")
        return 0
    by_category = {}
    for filename, lineno, category, reason, fix in findings:
        by_category.setdefault(category, []).append(
            (filename, lineno, reason, fix))
    for category, items in sorted(by_category.items()):
        print("== %s (%d) ==" % (category, len(items)))
        for filename, lineno, reason, fix in items:
            print("  %s:%d - %s" % (filename, lineno, reason))
            print("    fix: %s" % fix)
    print("\n%d finding(s) across %d categor%s."
          % (len(findings), len(by_category),
             "y" if len(by_category) == 1 else "ies"))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
