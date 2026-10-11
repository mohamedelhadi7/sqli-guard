import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest
from detector import Detector, normalise

ATTACKS = [
    "admin' --",
    "' OR 1=1 --",
    "x' or '1'='1",
    "1 UNION SELECT username, password FROM users",
    "1; DROP TABLE users",
    "1 AND SLEEP(5)",
    "' UNION ALL SELECT null,null--",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1 UNION SELECT name FROM sqlite_master",
    "admin'#",
    "1 ORDER BY 7",
    "%27%20OR%201%3D1%20--%20",          # URL-encoded
    "1/**/UNION/**/SELECT/**/1,2",       # comment obfuscation
    "1 AND ASCII(SUBSTR(password,1,1))>64",
]

BENIGN = [
    "Mohamed Hedi", "O'Brien", "alice", "john.doe@example.com",
    "I want to select a seat", "Rock & Roll", "supersecret123",
    "union members meeting", "order 66", "Karavaevskaya street 34",
]


@pytest.fixture
def det():
    return Detector()


@pytest.mark.parametrize("payload", ATTACKS)
def test_attack_detected(det, payload):
    assert det.inspect("1.1.1.1", "Mozilla/5.0", {"username": payload}).attack


@pytest.mark.parametrize("text", BENIGN)
def test_benign_not_flagged(det, text):
    assert not det.inspect("2.2.2.2", "Mozilla/5.0", {"q": text}).attack


def test_normalise_decodes_and_strips_comments():
    assert normalise("UNION/**/SELECT") == "union select"
    assert normalise("%27%20OR%201%3D1") == "' or 1=1"


def test_scanner_user_agent_is_bot(det):
    v = det.inspect("3.3.3.3", "sqlmap/1.7", {"id": "1' OR 1=1--"})
    assert v.is_bot and "scanner_user_agent" in v.bot_signals


def test_many_payloads_and_rate_flag_bot(det):
    payloads = ["' OR 1=1--", "1 UNION SELECT 1", "1; DROP TABLE x", "1 AND SLEEP(2)"]
    last = None
    for i, p in enumerate(payloads):
        last = det.inspect("4.4.4.4", "Mozilla/5.0", {"id": p}, now=100 + i * 0.1)
    assert "many_attack_payloads" in last.bot_signals


def test_rate_limit_signal(det):
    for i in range(25):
        v = det.inspect("5.5.5.5", "Mozilla/5.0", {"q": "hello"}, now=200 + i * 0.1)
    assert "high_request_rate" in v.bot_signals


def test_events_are_logged(det):
    det.inspect("6.6.6.6", "Mozilla/5.0", {"username": "admin' --"})
    rows = det.conn.execute("SELECT ip, signature FROM events").fetchall()
    assert ("6.6.6.6", "quote_then_comment") in rows
