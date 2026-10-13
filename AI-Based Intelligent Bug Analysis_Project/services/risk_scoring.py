from typing import Dict, Any

# Module criticality weights
MODULE_CRITICALITY = {
    "Payment": 10,
    "Authentication": 10,
    "Database": 10,
    "API": 5,
    "Registration": 5,
    "Dashboard": 0,
    "UI": 0,
    "Other": 0
}

# Base severity weights
SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 25,
    "Medium": 15,
    "Low": 5
}

def calculate_risk_prioritization_score(
    severity: str,
    category: str,
    category_confidence: float,
    affected_module: str,
    security_indicators: list
) -> Dict[str, Any]:
    """
    Computes a transparent 0-100 Security Risk Prioritization Score.
    
    Formula Breakdown:
    1. Base Severity Score (Max 40 pts):
       - Critical: 40 pts, High: 25 pts, Medium: 15 pts, Low: 5 pts
    2. ML Security Classifier Factor (Max 25 pts):
       - If Category == 'Security Issue': confidence * 25
       - Otherwise: 0 pts
    3. Security Indicators Detected (Max 25 pts):
       - Sum of rule weights capped at 25 pts
    4. Affected Module Criticality (Max 10 pts):
       - Payment, Auth, Database: 10 pts
       - API, Registration: 5 pts
       - Dashboard, UI, Other: 0 pts
    
    Total Score = Min(100, Base + ML + Indicators + Module)
    """
    # 1. Base Severity
    sev_clean = severity.capitalize() if severity else "Medium"
    base_sev_score = SEVERITY_WEIGHTS.get(sev_clean, 15)

    # 2. ML Classifier Factor
    if category == "Security Issue":
        ml_score = int(round(category_confidence * 25))
    else:
        ml_score = 0

    # 3. Rule Indicators Factor
    rule_score_raw = sum(ind.get("weight", 15) for ind in security_indicators)
    rule_score = min(25, rule_score_raw)

    # 4. Module Criticality
    module_clean = affected_module.capitalize() if affected_module else "Other"
    module_score = MODULE_CRITICALITY.get(module_clean, 0)

    # Total Score
    total_score = min(100, base_sev_score + ml_score + rule_score + module_score)

    # Determine Risk Level
    if total_score >= 81:
        risk_level = "Critical"
        badge_color = "danger"
    elif total_score >= 56:
        risk_level = "High"
        badge_color = "warning"
    elif total_score >= 26:
        risk_level = "Medium"
        badge_color = "info"
    else:
        risk_level = "Low"
        badge_color = "success"

    return {
        "risk_score": total_score,
        "risk_level": risk_level,
        "badge_color": badge_color,
        "breakdown": {
            "severity_component": {
                "label": f"Severity ({sev_clean})",
                "score": base_sev_score,
                "max": 40
            },
            "ml_classifier_component": {
                "label": f"Security Classifier ({round(category_confidence * 100, 1)}%)",
                "score": ml_score,
                "max": 25
            },
            "indicator_rules_component": {
                "label": f"Detected Indicators ({len(security_indicators)})",
                "score": rule_score,
                "max": 25
            },
            "module_criticality_component": {
                "label": f"Module Impact ({module_clean})",
                "score": module_score,
                "max": 10
            }
        },
        "formula_documentation": "Risk = BaseSeverity(max 40) + SecurityML(max 25) + IndicatorRules(max 25) + ModuleImpact(max 10)"
    }
