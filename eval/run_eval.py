"""Measure the detector on a labelled set.

Usage:
  python eval/run_eval.py            # development set (dataset.py)
  python eval/run_eval.py heldout    # held-out set (heldout.py)
"""
import importlib
import sys
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detector import Detector
name = sys.argv[1] if len(sys.argv) > 1 else "dataset"
_data = importlib.import_module(name)
ATTACKS, BENIGN = _data.ATTACKS, _data.BENIGN
print(f"Set: {name}")
if not ATTACKS or not BENIGN:
    sys.exit(f"{name}.py needs at least one attack and one normal input.")

det = Detector()
rows = [(t, 1, c) for t, c in ATTACKS] + [(t, 0, c) for t, c in BENIGN]
tp = fn = fp = tn = 0
missed, false_alarms = [], []
by_cat = defaultdict(lambda: [0, 0])      # category -> [caught, total]

for text, label, cat in rows:
    hit = bool(det.scan(text))
    if label:
        by_cat[cat][1] += 1
        if hit:
            tp += 1; by_cat[cat][0] += 1
        else:
            fn += 1; missed.append((cat, text))
    else:
        if hit:
            fp += 1; false_alarms.append((cat, text, det.scan(text)))
        else:
            tn += 1

n_att, n_ben = tp + fn, fp + tn
print(f"Attacks: {n_att}   Normal inputs: {n_ben}\n")
print(f"Detection rate (recall): {tp}/{n_att} = {tp / n_att:.1%}")
print(f"False-alarm rate:        {fp}/{n_ben} = {fp / n_ben:.1%}")
prec = tp / (tp + fp) if tp + fp else 0
print(f"Precision:               {tp}/{tp + fp} = {prec:.1%}\n")

print("Per attack category (caught/total):")
for cat, (c, t) in sorted(by_cat.items()):
    print(f"  {cat:24s} {c}/{t}")

print("\nMISSED attacks:")
for cat, text in missed:
    print(f"  [{cat}] {text!r}")
print("\nFALSE ALARMS:")
for cat, text, sigs in false_alarms:
    print(f"  [{cat}] {text!r} -> {[s for s, _ in sigs]}")
