import pytest
from services.security_analysis import analyze_security_aspects
from services.risk_scoring import calculate_risk_prioritization_score

def test_sql_injection_detection():
    title = "Database SQL injection vulnerability"
    desc = "User input is formatted directly into: SELECT * FROM users WHERE name = '\" + name + \"' OR 1=1"
    res = analyze_security_aspects(title, desc, ml_category="Security Issue", ml_confidence=0.92)
    assert res["is_security_related"] == 1
    assert res["indicator_count"] >= 1
    cwe_list = [ind["cwe"] for ind in res["indicators"]]
    assert "CWE-89" in cwe_list

def test_xss_detection():
    title = "Reflected XSS on user profile"
    desc = "Input contains <script>alert(document.cookie)</script> executed unescaped."
    res = analyze_security_aspects(title, desc, ml_category="Security Issue", ml_confidence=0.88)
    assert res["is_security_related"] == 1
    cwe_list = [ind["cwe"] for ind in res["indicators"]]
    assert "CWE-79" in cwe_list

def test_path_traversal_detection():
    title = "Arbitrary file download in reports"
    desc = "Requesting filename=../../../../etc/passwd dumps Linux password shadow hashes."
    res = analyze_security_aspects(title, desc)
    assert res["is_security_related"] == 1
    cwe_list = [ind["cwe"] for ind in res["indicators"]]
    assert "CWE-22" in cwe_list

def test_non_security_bug_clean_slate():
    title = "Header navbar logo pixelated on 4K display"
    desc = "The logo PNG file lacks retina 2x asset and looks blurry on high DPI screens."
    res = analyze_security_aspects(title, desc, ml_category="UI Issue", ml_confidence=0.95)
    assert res["is_security_related"] == 0
    assert res["indicator_count"] == 0

def test_risk_prioritization_scoring_bounds():
    # Critical SQL Injection in Payment module
    indicators = [{"weight": 25, "cwe": "CWE-89"}]
    calc_high = calculate_risk_prioritization_score(
        severity="Critical",
        category="Security Issue",
        category_confidence=0.95,
        affected_module="Payment",
        security_indicators=indicators
    )
    assert 81 <= calc_high["risk_score"] <= 100
    assert calc_high["risk_level"] == "Critical"

    # Low UI issue in Dashboard
    calc_low = calculate_risk_prioritization_score(
        severity="Low",
        category="UI Issue",
        category_confidence=0.90,
        affected_module="Dashboard",
        security_indicators=[]
    )
    assert 0 <= calc_low["risk_score"] <= 25
    assert calc_low["risk_level"] == "Low"
