"""Runtime SQL-injection detector with simple bot detection.

Flow for each request:
  1. normalise every input value (decode, lower-case, strip comments/spaces)
  2. match it against the signature database
  3. look for bot signals (scanner User-Agent, high request rate,
     many different attack payloads from one IP)
  4. log every match to the `events` table and return a verdict
"""
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from urllib.parse import unquote_plus

import signatures

SCANNER_AGENTS = re.compile(
    r"sqlmap|nikto|havij|acunetix|nessus|burp|zap|nmap|masscan|python-requests",
    re.I)

RATE_WINDOW = 10        # seconds
RATE_LIMIT = 20         # requests per window = suspicious
PAYLOAD_LIMIT = 3       # distinct attack payloads per window = suspicious


@dataclass
class Verdict:
    attack: bool = False
    is_bot: bool = False
    matches: list = field(default_factory=list)   # (field, signature, severity)
    bot_signals: list = field(default_factory=list)

    @property
    def block(self):
        return self.attack


def normalise(value):
    """Undo common tricks so signatures see the real text."""
    text = str(value)
    for _ in range(2):                       # double URL-encoding
        text = unquote_plus(text)
    text = text.lower()
    text = re.sub(r"/\*.*?\*/", " ", text)   # UNION/**/SELECT -> union select
    text = re.sub(r"\s+", " ", text)
    return text.strip()


class Detector:
    def __init__(self, conn=None):
        self.conn = conn or signatures.connect()
        signatures.seed(self.conn)
        self.reload()
        self._requests = defaultdict(deque)   # ip -> request times
        self._payloads = defaultdict(deque)   # ip -> (time, payload)

    def reload(self):
        rows = self.conn.execute(
            "SELECT name, severity, pattern FROM signatures").fetchall()
        self.rules = [(n, s, re.compile(p)) for n, s, p in rows]

    def scan(self, value):
        """Return [(signature, severity)] for one input value."""
        text = normalise(value)
        return [(n, s) for n, s, rx in self.rules if rx.search(text)]

    def inspect(self, ip, user_agent, params, now=None):
        now = time.time() if now is None else now
        verdict = Verdict()

        for fname, value in params.items():
            for name, sev in self.scan(value):
                verdict.attack = True
                verdict.matches.append((fname, name, sev))
                self._payloads[ip].append((now, str(value)))

        verdict.bot_signals = self._bot_signals(ip, user_agent, now)
        verdict.is_bot = ("scanner_user_agent" in verdict.bot_signals
                          or len(verdict.bot_signals) >= 2)

        for fname, name, sev in verdict.matches:
            self.conn.execute(
                "INSERT INTO events (ts, ip, user_agent, field, payload,"
                " signature, severity, is_bot) VALUES (?,?,?,?,?,?,?,?)",
                (now, ip, user_agent, fname, str(params[fname]), name, sev,
                 int(verdict.is_bot)))
        self.conn.commit()
        return verdict

    def _bot_signals(self, ip, user_agent, now):
        signals = []
        if user_agent and SCANNER_AGENTS.search(user_agent):
            signals.append("scanner_user_agent")

        reqs = self._requests[ip]
        reqs.append(now)
        while reqs and now - reqs[0] > RATE_WINDOW:
            reqs.popleft()
        if len(reqs) > RATE_LIMIT:
            signals.append("high_request_rate")

        pays = self._payloads[ip]
        while pays and now - pays[0][0] > RATE_WINDOW:
            pays.popleft()
        if len({p for _, p in pays}) >= PAYLOAD_LIMIT:
            signals.append("many_attack_payloads")
        return signals
