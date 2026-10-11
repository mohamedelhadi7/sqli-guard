import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lab"))
from app import create_app, FLAG
from checker import check_source

ATTACK = {"username": "admin' --", "password": "x"}
GOOD = {"username": "admin", "password": "supersecret123"}


def post(app, data, ua="Mozilla/5.0"):
    return app.test_client().post("/login", data=data, headers={"User-Agent": ua})


def test_normal_login_works_in_every_configuration():
    for mode in ("vulnerable", "fixed"):
        for det in ("off", "monitor", "block"):
            assert post(create_app(mode, det), GOOD).get_json()["ok"]


def test_vulnerable_without_detector_is_bypassed():
    r = post(create_app("vulnerable", "off"), ATTACK).get_json()
    assert r["ok"] and r["flag"] == FLAG


def test_monitor_mode_logs_but_does_not_stop():
    app = create_app("vulnerable", "monitor")
    assert post(app, ATTACK).get_json()["ok"]
    rows = app.det.conn.execute("SELECT signature FROM events").fetchall()
    assert ("quote_then_comment",) in rows


def test_block_mode_stops_the_attack():
    r = post(create_app("vulnerable", "block"), ATTACK)
    assert r.status_code == 403


def test_fixed_app_resists_even_without_detector():
    r = post(create_app("fixed", "off"), ATTACK)
    assert r.status_code == 401


def test_scanner_is_flagged_as_bot():
    app = create_app("vulnerable", "block")
    post(app, ATTACK, ua="sqlmap/1.7")
    assert app.det.conn.execute("SELECT is_bot FROM events").fetchone() == (1,)


def test_checker_flags_only_the_vulnerable_function():
    src = (Path(__file__).resolve().parent.parent / "lab" / "app.py").read_text()
    found = check_source(src)
    assert len(found) == 1          # login_vulnerable's execute(query)
