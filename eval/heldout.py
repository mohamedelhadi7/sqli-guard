"""HELD-OUT test set. Write/collect these WITHOUT looking at signatures.py,
and do NOT change any signature after seeing the result of this file
(or the score stops being an honest held-out score).

Format: (text, category). Run once:  python eval/run_eval.py heldout
"""

ATTACKS = [
    # time-based / stacked (MSSQL)
    ("1';waitfor delay '0:0:10'--", "time_blind"),
    ("1'));waitfor delay '0:0:10'--", "time_blind"),
    # URL-parameter style
    ("product.asp?name=Book' OR 'x'='x", "url_tautology"),
    ("product.asp?name=Bo' || 'ok", "url_concat_probe"),
    # building text from character codes, conditionals
    ("SELECT CONCAT(CHAR(75),CHAR(76),CHAR(77))", "char_build_mysql"),
    ("SELECT CHAR(75)+CHAR(76)+CHAR(77)", "char_build_mssql"),
    ("SELECT CHR(75)||CHR(76)||CHR(77)", "char_build_oracle"),
    ("SELECT (CHaR(75)||CHaR(76)||CHaR(77))", "char_build_mixed_case"),
    ("IF (1=1) SELECT 'true' ELSE SELECT 'false'", "conditional_mssql"),
    # error-based via HAVING / GROUP BY
    ("' HAVING 1=1 --", "error_based_having"),
    ("' GROUP BY users.id HAVING 1=1 --", "error_based_having"),
    ("' GROUP BY users.id, users.username HAVING 1=1 --", "error_based_having"),
    # error-based (4 vendors)
    ("' AND 1=CAST((SELECT current_user) AS int)--", "error_based_postgres"),
    ("' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--", "error_based_mysql"),
    ("' AND 1=CONVERT(int,(SELECT @@version))--", "error_based_mssql"),
    ("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--", "error_based_oracle"),
    # blind, boolean
    ("' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--", "blind_boolean"),
    # login-style, alternative operators instead of =
    ("' OR username LIKE 'admin'--", "login_alt_operator"),
    ("' OR username IN ('admin')--", "login_alt_operator"),
    ("' AND 'a' RLIKE 'a'--", "login_alt_operator"),
    ("' OR username BETWEEN 'admin' AND 'admin'--", "login_alt_operator"),
    # blind, time-based
    ("' AND IF(SUBSTRING(database(),1,1)='a', SLEEP(5), 0)--", "blind_time_mysql"),
    ("'; SELECT CASE WHEN (SUBSTRING(current_database(),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END--", "blind_time_postgres"),
    ("'; SELECT CASE WHEN (1=1) THEN (SELECT count(*) FROM generate_series(1,10000000)) ELSE 1 END--", "blind_time_heavy_query"),
    
]

BENIGN = [
    ("Ahmed O'Connor", "name"),
    ("Jean-Luc Picard", "name"),
    ("Привет, меня зовут Мохамед", "russian"),
    ("I'd like to order by phone, please", "sentence"),
    ("Select all that apply", "sentence"),
    ("How do I drop a class at university?", "sentence"),
    ("The union voted to delete the old rule", "sentence"),
    ("what's the difference between UNION and JOIN?", "sentence"),
    ("Meeting at 10:30; bring the report", "sentence"),
    ("x = 5 and y = 7", "math"),
    ("if (a == b) return 1;", "code"),
    ("my password is P@ss--w0rd!", "password"),
    ("name=John&age=25", "url_params"),
    ("https://example.com/search?q=sql+tutorial&page=2", "url"),
    ("Saint-Petersburg, Nevsky Prospekt 28, apt. 12", "address"),
    ("zackThestacko00", "password"),
    ("name=Adam&age=33", "url_params"),
    ("https://Uselesssite.com/search?q=sql+tutorial&page=5", "url"),
    ("New York, Liberty Street 9", "address"),
]

