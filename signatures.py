"""Signature database: known SQL-injection formats, stored in SQLite.

Each row: name, attack type, severity, regex (applied to the NORMALISED input).
Add your own with add_signature(); the detector reads the table at start-up.
"""
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
    pattern TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT,
    field TEXT,
    payload TEXT,
    signature TEXT,
    severity TEXT,
    is_bot INTEGER NOT NULL DEFAULT 0
);
"""

# (name, attack_type, severity, regex)  - regexes run on lower-case, decoded input
DEFAULT_SIGNATURES = [
    ("quote_then_comment", "auth_bypass", "high", r"'\s*(--|#)"),
    ("quote_or_tautology", "auth_bypass", "high",
     r"['\"]\s*\)*\s*or\s+\(*\s*['\"]?\w*['\"]?\s*\)*\s*=\s*\(*\s*['\"]?\w*"),
    ("numeric_tautology", "boolean", "high",
     r"\b(or|and)\s+\d+\s*=\s*\d+|\bor\s+\d+\s*(<>|!=|<=|>=|<|>)\s*\d+"),
    ("union_select", "union", "high", r"\bunion\b(\s+all)?\s+select\b"),
    ("stacked_query", "stacked", "high",
     r";\s*(drop|delete|insert|update|create|alter|truncate|select)\b"),
    ("time_delay_function", "time_blind", "high",
     r"\b(sleep|pg_sleep|benchmark)\s*\("),
    ("waitfor_delay", "time_blind", "high", r"\bwaitfor\s+delay\b"),
    ("error_based_function", "error_based", "high",
     r"\b(extractvalue|updatexml)\s*\("),
    ("schema_enumeration", "enumeration", "high",
     r"information_schema|sqlite_master|pg_catalog"),
    ("char_extraction", "boolean_blind", "medium",
     r"\b(substring|substr|mid|ascii)\s*\("),
    ("order_by_probe", "enumeration", "low", r"\border\s+by\s+\d+"),
    ("char_encoding", "obfuscation", "medium",
     r"\b(char|chr)\s*\(\s*\d+|0x[0-9a-f]{6,}"),
    ("file_access", "file_ops", "high",
     r"\bload_file\b|\binto\s+(outfile|dumpfile)\b"),
    ("version_probe", "enumeration", "medium",
     r"@@version|\bsqlite_version\s*\(\)|\bversion\s*\(\)|\bdatabase\s*\(\)"),
    ("group_by_having", "error_based", "medium",
     r"\bgroup\s+by\b.+\bhaving\b"),
         ("subquery_probe", "subquery", "high",
     r"\bexists\s*\(\s*select\b|\(\s*select\b.{0,80}?\bfrom\b"),
    ("convert_cast_error", "error_based", "medium",
     r"\bconvert\s*\(\s*(int|integer)\b"),
]


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def seed(conn):
    for name, kind, sev, pattern in DEFAULT_SIGNATURES:
        conn.execute(
            "INSERT OR IGNORE INTO signatures (name, attack_type, severity, pattern)"
            " VALUES (?, ?, ?, ?)", (name, kind, sev, pattern))
    conn.commit()


def add_signature(conn, name, attack_type, severity, pattern):
    conn.execute(
        "INSERT INTO signatures (name, attack_type, severity, pattern)"
        " VALUES (?, ?, ?, ?)", (name, attack_type, severity, pattern))
    conn.commit()
