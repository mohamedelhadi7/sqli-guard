import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from checker import check_source

ROOT = Path(__file__).resolve().parent.parent / "samples"

def test_vulnerable_file_is_flagged():
    found = check_source((ROOT / "vulnerable.py").read_text())
    assert len(found) == 4   # concat, f-string, format, percent

def test_fixed_file_is_clean():
    assert check_source((ROOT / "fixed.py").read_text()) == []
