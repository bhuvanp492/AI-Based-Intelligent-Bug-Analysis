import re
from typing import Dict, List, Any, Optional

# Security indicator rules catalog with CWE mappings, patterns, and suggested mitigations
SECURITY_RULES = [
    {
        "id": "SEC-SQLI",
        "name": "SQL Injection (SQLi)",
        "cwe": "CWE-89",
        "weight": 25,
        "patterns": [
            r"\b(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|delete\s+from|update\s+.*\s+set)\b",
            r"\b(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1'|admin'--|'--|\bexec\s*\(|\bsql\s+syntax\s+error\b)",
            r"\b(sql\s+injection|sqli|parameterized\s+query|raw\s+sql|concatenated\s+query)\b"
        ],
        "recommendation": "Adopt parameterized prepared statements or ORM queries. Never concatenate untrusted parameters directly into SQL queries."
    },
    {
        "id": "SEC-XSS",
        "name": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "weight": 20,
        "patterns": [
            r"(<script.*?>.*?</script>|<img.*?onerror=|<svg.*?onload=|javascript:)",
            r"\b(document\.cookie|window\.location|alert\(|xss|reflected\s+xss|stored\s+xss|dom\s+xss)\b",
            r"\b(unescaped\s+html|innerhtml|dangerouslysetinnerhtml)\b"
        ],
        "recommendation": "Ensure contextual HTML entity encoding on all user output. Implement a strict Content-Security-Policy (CSP) HTTP header."
    },
    {
        "id": "SEC-AUTH",
        "name": "Authentication & Credential Weakness",
        "cwe": "CWE-287",
        "weight": 25,
        "patterns": [
            r"\b(hardcoded\s+password|hardcoded\s+secret|hardcoded\s+jwt|jwt\s+none\s+alg|token\s+forgery)\b",
            r"\b(credential\s+stuffing|brute\s*force|missing\s+rate\s+limit|weak\s+password\s+policy)\b",
            r"\b(bypass\s+otp|otp\s+bypass|session\s+fixation|password\s+hash\s+exposure)\b"
        ],
        "recommendation": "Enforce strong hashing (bcrypt/argon2), implement rate limiting on authentication routes, and invalidate previous tokens upon state changes."
    },
    {
        "id": "SEC-ACCESS",
        "name": "Broken Access Control & IDOR",
        "cwe": "CWE-639",
        "weight": 25,
        "patterns": [
            r"\b(idor|insecure\s+direct\s+object\s+reference|broken\s+access\s+control|privilege\s+escalation)\b",
            r"\b(unauthorized\s+access|horizontal\s+privilege|vertical\s+privilege|tamper.*user_id)\b",
            r"\b(missing\s+authorization|role\s+bypass|elevate.*privilege)\b"
        ],
        "recommendation": "Implement server-side ownership checks on resource IDs. Validate permissions and tenant context for every requested object."
    },
    {
        "id": "SEC-UPLOAD",
        "name": "Insecure File Upload",
        "cwe": "CWE-434",
        "weight": 25,
        "patterns": [
            r"\b(arbitrary\s+file\s+upload|unrestricted\s+file\s+upload|\.php\s+upload|\.exe\s+upload)\b",
            r"\b(web\s*shell|remote\s+code\s+execution\s+via\s+upload|unvalidated\s+mime\s+type)\b",
            r"\b(insecure\s+file\s+upload|svg\s+xss\s+upload)\b"
        ],
        "recommendation": "Enforce strict server-side file extension whitelists, validate file signatures/magic bytes, and store uploads in isolated non-executable directories."
    },
    {
        "id": "SEC-PATH",
        "name": "Directory / Path Traversal",
        "cwe": "CWE-22",
        "weight": 25,
        "patterns": [
            r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)",
            r"\b(directory\s+traversal|path\s+traversal|arbitrary\s+file\s+read|arbitrary\s+file\s+download)\b"
        ],
        "recommendation": "Sanitize filenames using secure path resolution tools. Prevent user-controlled path separators (.. and /)."
    },
    {
        "id": "SEC-EXPOSURE",
        "name": "Sensitive Information Exposure",
        "cwe": "CWE-200",
        "weight": 15,
        "patterns": [
            r"\b(api_key|secret_key|private_key|aws_access_key|stripe_key|sk_live_)\b",
            r"\b(credit\s+card\s+logged|cvv\s+logged|plaintext\s+password|stack\s+trace\s+exposed|leaked\s+credentials)\b",
            r"\b(pii\s+leak|sensitive\s+data\s+exposure)\b"
        ],
        "recommendation": "Mask or redact secrets and PII in application logs. Use environment variables and secret management stores for sensitive keys."
    },
    {
        "id": "SEC-RCE",
        "name": "Command Injection / RCE",
        "cwe": "CWE-78",
        "weight": 30,
        "patterns": [
            r"\b(command\s+injection|remote\s+code\s+execution|rce|shell_exec|system\(|subprocess\.popen.*shell=true)\b",
            r"\b(arbitrary\s+command\s+execution|eval\(|os\.system)\b"
        ],
        "recommendation": "Avoid invoking shell interpreters from application code. Use parameterized API alternatives instead of string-concatenated shell commands."
    },
    {
        "id": "SEC-CSRF",
        "name": "CSRF / Session Management Weakness",
        "cwe": "CWE-352",
        "weight": 20,
        "patterns": [
            r"\b(csrf|cross-site\s+request\s+forgery|missing\s+csrf\s+token|no\s+anti-csrf)\b",
            r"\b(session\s+fixation|session\s+hijacking|cookie\s+lacks\s+httponly|cookie\s+lacks\s+secure)\b",
            r"\b(session\s+not\s+invalidated|cookie\s+theft)\b"
        ],
        "recommendation": "Implement synchronized anti-CSRF tokens for all state-altering requests. Configure cookies with SameSite=Lax, HttpOnly, and Secure flags."
    }
]

def extract_evidence_snippets(text: str, regex_pattern: str, max_snippets=2) -> List[str]:
    """Extracts concise text snippets surrounding matched security keywords."""
    snippets = []
    for match in re.finditer(regex_pattern, text, re.IGNORECASE):
        start = max(0, match.start() - 30)
        end = min(len(text), match.end() + 30)
        snippet = text[start:end].strip()
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."
        snippets.append(snippet)
        if len(snippets) >= max_snippets:
            break
    return snippets

def analyze_security_aspects(
    title: str, 
    description: str, 
    ml_category: Optional[str] = None, 
    ml_confidence: float = 0.0
) -> Dict[str, Any]:
    """
    Performs hybrid security analysis combining rule-based pattern matching
    with ML category classification.
    """
    full_text = f"{title} {description}"
    detected_indicators = []
    total_rule_weight = 0

    # Rule-based scanning
    for rule in SECURITY_RULES:
        matched_patterns = []
        snippets = []
        for pat in rule["patterns"]:
            if re.search(pat, full_text, re.IGNORECASE):
                matched_patterns.append(pat)
                extracted = extract_evidence_snippets(full_text, pat)
                snippets.extend(extracted)

        if matched_patterns:
            detected_indicators.append({
                "rule_id": rule["id"],
                "name": rule["name"],
                "cwe": rule["cwe"],
                "weight": rule["weight"],
                "evidence_snippets": list(dict.fromkeys(snippets))[:2],
                "recommendation": rule["recommendation"]
            })
            total_rule_weight += rule["weight"]

    # Hybrid determination
    is_ml_security = (ml_category == "Security Issue")
    has_rules = len(detected_indicators) > 0

    if is_ml_security and has_rules:
        detection_type = "Hybrid (ML Classifier & Pattern Matching)"
        is_security_related = 1
    elif is_ml_security and not has_rules:
        detection_type = "Model-Based (Classifier Flagged Potential Security Pattern)"
        is_security_related = 1
    elif not is_ml_security and has_rules:
        detection_type = "Rule-Based (Specific Security Indicators Detected)"
        is_security_related = 1
    else:
        detection_type = "None (No Security Indicators Found)"
        is_security_related = 0

    # Formulate prioritized recommended actions
    if detected_indicators:
        recommendations = [ind["recommendation"] for ind in detected_indicators]
        primary_action = recommendations[0]
    elif is_ml_security:
        primary_action = "Conduct focused manual code review around the affected component to verify if security logic or authorization was compromised."
    else:
        primary_action = "Standard developer bug triage and functional unit testing."

    return {
        "is_security_related": is_security_related,
        "detection_type": detection_type,
        "indicators": detected_indicators,
        "indicator_count": len(detected_indicators),
        "total_rule_weight": total_rule_weight,
        "recommended_action": primary_action,
        "disclaimer": "Automated security triage screening; indicates potential risk indicators requiring developer verification."
    }
