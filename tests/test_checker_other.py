import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from checker import check_source

ROOT = Path(__file__).resolve().parent.parent / "samples"


def categories(found):
    return [c for (_lineno, c, _reason, _fix) in found]


def test_vulnerable_other_is_flagged():
    found = categories(check_source((ROOT / "vulnerable_other.py").read_text()))
    assert found.count("command_injection") == 3   # system, popen, shell=True
    assert found.count("path_traversal") == 1
    assert found.count("weak_hash") == 2            # md5, sha1
    assert found.count("insecure_deserialization") == 2  # pickle, unsafe yaml


def test_fixed_other_is_clean():
    assert check_source((ROOT / "fixed_other.py").read_text()) == []
