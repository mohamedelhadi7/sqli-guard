# SQLi Guard: static checker + signature detector for a Flask CTF lab

A small defensive toolkit built around my coursework project
"Development of a CTF task on web security based on SQL injection"
(SPbSUT, 2026). Three parts that work together:

1. **Static checker** (`checker.py`) - reads Python source with the `ast`
   module and flags SQL queries built from variable data (concatenation,
   f-strings, `str.format`, `%` formatting). Prints file, line and the fix.
2. **Signature database + runtime detector** (`signatures.py`, `detector.py`) -
   17 SQL-injection signatures stored in SQLite. Each request input is
   decoded and normalised (double URL-decoding, lower-casing, SQL comment
   stripping), matched against the signatures, and every hit is logged to an
   `events` table. Simple bot signals: scanner User-Agent (sqlmap, nikto...),
   high request rate, many different payloads from one IP.
3. **Flask lab** (`lab/app.py`) - login app with a vulnerable and a fixed
   implementation, with the detector in `off` / `monitor` / `block` mode.
   Run it only on `127.0.0.1`.

## Quick start
    pip install flask pytest
    python checker.py lab/app.py          # flags the vulnerable query
    python -m pytest tests                # 38 tests
    python eval/run_eval.py               # development-set results
    python eval/run_eval.py heldout       # held-out-set results
    python lab/app.py                     # local lab on 127.0.0.1:5000

## Results

### Development set (`eval/dataset.py`)
67 attack strings (textbook SQLi, evasion tricks, and 6 cases I added myself)
and 58 normal inputs (names with apostrophes, emails, passwords with symbols,
sentences containing SQL words, and one comparison, `2>1`).

| Metric | Result |
|---|---|
| Detection rate (recall) | 61 / 67 = 91.0% |
| False-alarm rate | 0 / 58 = 0.0% |
| Precision | 61 / 61 = 100% |

Progress over five versions is in `CHANGELOG.md` (80.6% -> 91.0% recall,
false alarms stayed at 0%).

**Important:** the signatures were tuned against this set, so 91.0% is a
*development* score and probably overstates real performance.

### Held-out set (`eval/heldout.py`)
24 attack strings collected from public references (cheat sheets, labs) and
19 normal inputs, assembled after the signatures were frozen and never used
for tuning. Run once.

| Metric | Result |
|---|---|
| Detection rate (recall) | 19 / 24 = 79.2% |
| False-alarm rate | 0 / 19 = 0.0% |

The detector caught 79.2% on unseen attacks versus 91.0% on the development
set. The 12-point gap shows the effect of tuning on the development set, so
the held-out figure is the one to trust. With 24 attacks and 19 normal inputs
the sample is small (a rough 95% range for recall is 60-91%), so both
figures are indicative only.

## What it misses (known limits)
Found on the held-out set:
- A character between the quote and the comment: `' OR username IN ('admin')--`
  (the comment signature expects the quote right before `--`).
- `HAVING` without `GROUP BY`: `' HAVING 1=1 --`.
- `CAST(... AS int)` error probes (only `CONVERT(int ...)` is covered).
- `IF (...) SELECT ... ELSE ...` conditionals.
- `||` string concatenation: `name=Bo' || 'ok`.

Found on the development set:
- Keywords split by comments (`UN/**/ION SEL/**/ECT`) and MySQL executable
  comments (`/*!UNION*/`). The normaliser replaces comments with a space,
  which fixes `UNION/**/SELECT` but not split keywords.
- Tautologies using `LIKE` or string comparison
  (`1 AND 'a' LIKE 'a'`, `1 OR 'a'>'A'`).

Trade-offs I accepted:
- `<` / `>` tautologies are only caught after `or` (so `1 and 2>1` is
  missed, but the normal sentence "5 > 3 and 2 < 4" is not flagged).
- `; select` and `(select ... from` can flag unusual normal text.

General limits:
- Signature matching cannot see payloads encoded in ways the normaliser
  does not know. It is a first layer, not a fix. **Parameterized queries
  remain the real defence.**
- The static checker follows one level of variable assignment and does not
  track data across functions.
- Both sets were assembled by me, so the numbers are indicative, not a
  benchmark. The held-out set is now spent: fixing its misses requires a new
  held-out set to stay honest.

## Ideas / next steps
- Fix the misses above, then measure on a NEW held-out set.
- Handle split-keyword and `/*! */` comments in `normalise()`.
- Compare against an existing rule set (e.g. OWASP Core Rule Set).
- Per-IP blocking and a small dashboard over the `events` table.

Educational use only. Test only systems you own or have permission to test.
