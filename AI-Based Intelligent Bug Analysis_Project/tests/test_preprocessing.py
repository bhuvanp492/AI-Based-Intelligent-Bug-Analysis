import pytest
from services.preprocessing import clean_text_for_ml, combine_bug_text, normalize_whitespace

def test_normalize_whitespace():
    raw = "  Hello \t\n world!   Multiple    spaces.  "
    expected = "Hello world! Multiple spaces."
    assert normalize_whitespace(raw) == expected

def test_combine_bug_text():
    title = "Login Failure"
    desc = "User cannot sign in with valid credentials."
    assert combine_bug_text(title, desc) == "Login Failure. User cannot sign in with valid credentials."
    assert combine_bug_text(title, None) == "Login Failure"
    assert combine_bug_text(None, desc) == "User cannot sign in with valid credentials."
    assert combine_bug_text("", "") == ""

def test_security_tokens_preserved():
    sqli_text = "Vulnerability: SELECT * FROM users WHERE id = '1' OR 1=1; DROP TABLE logs;"
    cleaned = clean_text_for_ml(sqli_text)
    assert "select" in cleaned
    assert "or 1=1" in cleaned
    assert "drop table" in cleaned

    xss_text = "Injecting <script>alert(document.cookie)</script> into bio"
    cleaned_xss = clean_text_for_ml(xss_text)
    assert "<script>" in cleaned_xss
    assert "alert" in cleaned_xss
    assert "document.cookie" in cleaned_xss
