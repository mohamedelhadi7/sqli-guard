v6 (static checker expanded to 5 vulnerability classes): checker.py now
detects command injection, path traversal, weak password hashing and
insecure deserialization alongside SQL injection, each with a textual fix
suggestion. Added samples/vulnerable_other.py + fixed_other.py, a new
test file (tests/test_checker_other.py), a 38-example multi-class benchmark
(eval/benchmark_corpus.py + eval/benchmark.py -> 100% recall/precision
across all 5 categories, see README caveat on this number), and a GitHub
Actions workflow that runs the tests, the benchmark, and the checker
against its own source on every push.

v1: recall 80.6% (54/67), false alarms 0% (0/58)  [61 original + 6 own attack cases, 1 own normal case]
v2 (parenthesised bypass): recall 83.6% (56/67), false alarms 0% (0/58)
v3 (stacked select): recall 85.1% (57/67), false alarms 0% (0/58)
v4 (or + comparison operators): recall 86.6% (58/67), false alarms 0% (0/58)
v5 (subquery + convert signatures): recall 91.0% (61/67), false alarms 0% (0/58)
