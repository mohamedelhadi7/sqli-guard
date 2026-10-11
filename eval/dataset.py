"""Labelled evaluation set: (text, label, category).

label 1 = SQL-injection attempt, 0 = normal input.
Attack strings are textbook examples (OWASP-style); 'evasion' ones are
deliberately harder. Written separately from the signatures, but by the same
author - add your own cases to keep the evaluation honest.
"""

ATTACKS = [
    # auth bypass
    ("admin' --", "auth_bypass"), ("admin'--", "auth_bypass"),
    ("admin' #", "auth_bypass"), ("' or '1'='1", "auth_bypass"),
    ("' OR '1'='1' --", "auth_bypass"), ("\" or \"\"=\"", "auth_bypass"),
    ("' or 1=1--", "auth_bypass"), ("admin' or 'a'='a", "auth_bypass"),
    ("') or ('1'='1", "auth_bypass"), ("x' OR 'x'='x", "auth_bypass"),
    # boolean / tautology
    ("1 OR 1=1", "boolean"), ("1 or 2>1", "boolean"),
    ("1 AND 1=1", "boolean"), ("1 AND 1=2", "boolean"),
    ("5 OR 5=5", "boolean"), ("id=1 and 7=7", "boolean"),
    # union
    ("1 UNION SELECT NULL", "union"), ("1 union all select 1,2,3", "union"),
    ("' UNION SELECT username,password FROM users--", "union"),
    ("-1 UNION SELECT 1,@@version,3", "union"),
    ("1' UNION SELECT table_name FROM information_schema.tables--", "union"),
    ("0 UNION ALL SELECT name FROM sqlite_master", "union"),
    # stacked
    ("1; DROP TABLE users", "stacked"), ("1; DELETE FROM users", "stacked"),
    ("'; INSERT INTO users VALUES (9,'x','y','admin')--", "stacked"),
    ("1; UPDATE users SET role='admin'", "stacked"),
    ("x'; DROP TABLE users; --", "stacked"),
    # time based
    ("1 AND SLEEP(5)", "time_blind"), ("1' AND SLEEP(5)--", "time_blind"),
    ("1; WAITFOR DELAY '0:0:5'", "time_blind"),
    ("1 OR pg_sleep(5)", "time_blind"),
    ("1 AND BENCHMARK(5000000,MD5(1))", "time_blind"),
    # error based
    ("1 AND extractvalue(1,concat(0x7e,version()))", "error_based"),
    ("1 AND updatexml(1,concat(0x7e,database()),1)", "error_based"),
    ("1 GROUP BY id HAVING 1=1", "error_based"),
    # enumeration
    ("1 ORDER BY 1", "enumeration"), ("1' ORDER BY 5--", "enumeration"),
    ("SELECT sqlite_version()", "enumeration"),
    ("' AND 1=0 UNION SELECT database()--", "enumeration"),
    # blind extraction
    ("1 AND ASCII(SUBSTRING(password,1,1))=97", "boolean_blind"),
    ("1 AND SUBSTR(username,1,1)='a'", "boolean_blind"),
    ("1 AND MID(version(),1,1)=5", "boolean_blind"),
    # file ops
    ("1 UNION SELECT load_file('/etc/passwd')", "file_ops"),
    ("1 INTO OUTFILE '/tmp/x'", "file_ops"),
    # encoded / evasion
    ("%27%20OR%201%3D1%20--", "evasion_url"),
    ("%27%20or%20%271%27%3D%271", "evasion_url"),
    ("%2527%2520OR%25201%253D1", "evasion_double_url"),
    ("1/**/UNION/**/SELECT/**/1,2", "evasion_comment"),
    ("1 /*!UNION*/ /*!SELECT*/ 1", "evasion_mysql_comment"),
    ("1 UnIoN SeLeCt 1,2", "evasion_case"),
    ("1 UNION\nSELECT 1", "evasion_whitespace"),
    ("1 UNION\tSELECT 1", "evasion_whitespace"),
    ("1' AND CHAR(65)=CHAR(65)--", "evasion_char"),
    ("1 UN/**/ION SEL/**/ECT 1", "evasion_split_keyword"),
    ("username=admin'--", "mine_auth"),
    ("test; SELECT 1", "mine_stacked"),
    ('{"username":"\' OR \'1\'=\'1"}', "mine_json"),
    ("' UNION SELECT NULL,NULL,NULL --", "mine_union"),
    ("CONVERT(INTEGER, 'x')", "mine_error_based"),
    ("1 AND 5=6", "mine_boolean"),
    ("1 || (SELECT 1)", "evasion_operator"),
    ("admin'/**/--", "evasion_comment"),
    ("1 AND 'a' LIKE 'a'", "evasion_like"),
    ("1 OR 'a'>'A'", "evasion_string_compare"),
    ("' || '1'='1", "evasion_operator"),
    ("1 and (select count(*) from users)>0", "subquery"),
    ("1 and exists(select 1 from users)", "subquery"),
]

BENIGN = [
    ("Mohamed Hedi", "name"), ("O'Brien", "name"), ("D'Angelo", "name"),
    ("Anne-Marie", "name"), ("Mahroug", "name"), ("alice", "name"),
    ("john.doe@example.com", "email"), ("a.b+tag@mail.ru", "email"),
    ("supersecret123", "password"), ("P@ssw0rd!", "password"),
    ("correct horse battery staple", "password"),
    ("my#password", "password"), ("pass--word", "password_special"),
    ("it's-a-secret", "password_special"),
    ("Karavaevskaya street 34", "address"), ("Saint Petersburg, Russia", "address"),
    ("Apt 5; Building 2", "address"),
    ("I want to select a seat", "sentence"), ("Please order by phone", "sentence"),
    ("union members meeting", "sentence"), ("drop me a message", "sentence"),
    ("Where can I update my profile?", "sentence"),
    ("insert coin to continue", "sentence"),
    ("delete my account please", "sentence"),
    ("the sleep function in my app", "sentence"),
    ("create a new account", "sentence"),
    ("I love rock & roll", "sentence"), ("5 > 3 and 2 < 4", "math"),
    ("1 + 1 = 2", "math"), ("x = 5", "math"), ("a=b", "math"),
    ("3 or 4 people", "sentence"), ("1 and 1 make 2", "sentence"),
    ("order 66", "misc"), ("2026-10-10", "date"), ("12:30", "time"),
    ("+7 953 355 08 46", "phone"), ("https://example.com/a?b=1", "url"),
    ("C:\\Users\\mohamed", "path"), ("/home/user/docs", "path"),
    ("SELECT", "keyword_alone"), ("union", "keyword_alone"),
    ("benchmark results", "sentence"), ("version 2.0", "sentence"),
    ("database design course", "sentence"), ("group by country", "sentence"),
    ("Hello, world!", "sentence"), ("100% sure", "sentence"),
    ("cybersecurity", "word"), ("Bonch-Bruevich University", "name"),
    ("Why did my query fail?", "sentence"),
    ("I am 20 years old; I study CS", "sentence"),
    ("table of contents", "sentence"), ("char count: 140", "sentence"),
    ("ascii art", "sentence"), ("mid-term exam", "sentence"),
    ("substring of the text", "sentence"),
    ("2>1", "mine_math"),
]
