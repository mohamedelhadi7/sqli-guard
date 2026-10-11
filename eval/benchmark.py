"""Multi-class benchmark for checker.py.

Runs every labeled snippet in eval/benchmark_corpus.py through the static
checker and reports, per category: how many vulnerable examples were
caught (recall) and how many safe examples were wrongly flagged in that
category (false positives). This is separate from eval/run_eval.py, which
benchmarks the runtime signature detector on raw SQLi payload strings
rather than the static AST checker on source code.

Usage:  python eval/benchmark.py
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from checker import check_source
from benchmark_corpus import CORPUS

CATEGORIES = ["sql_injection", "command_injection", "path_traversal",
              "weak_hash", "insecure_deserialization"]


def run():
    # per category: true positives, false negatives, false positives
    tp = defaultdict(int)
    fn = defaultdict(int)
    fp = defaultdict(int)
    vulnerable_total = defaultdict(int)
    safe_total = 0
    mislabeled = []  # (name, expected, found) for anything wrong

    for name, expected, source in CORPUS:
        found_categories = {cat for (_lineno, cat, _reason, _fix)
                             in check_source(source)}
        if expected == "safe":
            safe_total += 1
            if found_categories:
                for cat in found_categories:
                    fp[cat] += 1
                mislabeled.append((name, expected, sorted(found_categories)))
        else:
            vulnerable_total[expected] += 1
            if expected in found_categories:
                tp[expected] += 1
            else:
                fn[expected] += 1
                mislabeled.append((name, expected, sorted(found_categories)))

    lines = []
    lines.append("# Benchmark results\n")
    lines.append("| Category | Vulnerable examples | Recall | False positives (on safe code) |")
    lines.append("|---|---|---|---|")
    total_tp = total_fn = total_fp = 0
    for cat in CATEGORIES:
        n = vulnerable_total[cat]
        recall = tp[cat] / n if n else float("nan")
        lines.append("| %s | %d | %d/%d = %.0f%% | %d |"
                      % (cat, n, tp[cat], n, recall * 100 if n else 0, fp[cat]))
        total_tp += tp[cat]
        total_fn += fn[cat]
        total_fp += fp[cat]

    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0
    lines.append("")
    lines.append("- Vulnerable examples: %d, safe examples: %d, total: %d"
                  % (sum(vulnerable_total.values()), safe_total, len(CORPUS)))
    lines.append("- Overall recall: %d/%d = %.1f%%"
                  % (total_tp, total_tp + total_fn, overall_recall * 100))
    lines.append("- Overall precision: %d/%d = %.1f%%"
                  % (total_tp, total_tp + total_fp, precision * 100))
    if mislabeled:
        lines.append("\n## Misses and false positives\n")
        for name, expected, found in mislabeled:
            lines.append("- `%s` (expected `%s`): checker found %s"
                          % (name, expected, found if found else "nothing"))

    report = "\n".join(lines)
    print(report)
    out = Path(__file__).resolve().parent / "benchmark_report.md"
    out.write_text(report + "\n")
    print("\nWritten to %s" % out)
    return 0 if not mislabeled else 1


if __name__ == "__main__":
    sys.exit(run())
