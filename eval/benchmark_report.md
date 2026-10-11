# Benchmark results

| Category | Vulnerable examples | Recall | False positives (on safe code) |
|---|---|---|---|
| sql_injection | 6 | 6/6 = 100% | 0 |
| command_injection | 5 | 5/5 = 100% | 0 |
| path_traversal | 3 | 3/3 = 100% | 0 |
| weak_hash | 3 | 3/3 = 100% | 0 |
| insecure_deserialization | 4 | 4/4 = 100% | 0 |

- Vulnerable examples: 21, safe examples: 17, total: 38
- Overall recall: 21/21 = 100.0%
- Overall precision: 21/21 = 100.0%
