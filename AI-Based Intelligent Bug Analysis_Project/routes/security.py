import json
from flask import Blueprint, render_template, request, redirect, url_for, flash
from models.database import query_db, execute_db, log_audit_event
from models.bug_report import VALID_TRIAGE_STATUSES
from services.security_analysis import SECURITY_RULES

security_bp = Blueprint("security", __name__)

@security_bp.route("/security")
def security_dashboard():
    triage_filter = request.args.get("triage_status", "").strip()
    risk_filter = request.args.get("risk_level", "").strip()

    where_clauses = ["is_security_related = 1"]
    params = []

    if triage_filter and triage_filter in VALID_TRIAGE_STATUSES:
        where_clauses.append("triage_status = ?")
        params.append(triage_filter)

    if risk_filter:
        where_clauses.append("risk_level = ?")
        params.append(risk_filter)

    where_sql = "WHERE " + " AND ".join(where_clauses)

    # Fetch flagged security bugs
    flagged_bugs = query_db(f"""
        SELECT id, bug_id, title, severity, category, affected_module, 
               security_indicators, risk_score, risk_level, triage_status, 
               recommended_action, created_at
        FROM bug_reports
        {where_sql}
        ORDER BY risk_score DESC, id DESC
    """, params)

    # Parse indicators for each bug
    for b in flagged_bugs:
        try:
            b["indicators_parsed"] = json.loads(b["security_indicators"]) if b["security_indicators"] else []
        except Exception:
            b["indicators_parsed"] = []

    # KPI counts for security
    total_sec = query_db("SELECT COUNT(*) as count FROM bug_reports WHERE is_security_related = 1", one=True)["count"]
    pending_sec = query_db("SELECT COUNT(*) as count FROM bug_reports WHERE is_security_related = 1 AND triage_status = 'Pending Review'", one=True)["count"]
    confirmed_sec = query_db("SELECT COUNT(*) as count FROM bug_reports WHERE is_security_related = 1 AND triage_status = 'Confirmed Vulnerability'", one=True)["count"]
    crit_risk_sec = query_db("SELECT COUNT(*) as count FROM bug_reports WHERE is_security_related = 1 AND risk_level = 'Critical'", one=True)["count"]

    # Vulnerability category breakdown
    rule_counts = {r["name"]: 0 for r in SECURITY_RULES}
    all_sec_bugs = query_db("SELECT security_indicators FROM bug_reports WHERE is_security_related = 1")
    for r in all_sec_bugs:
        if r["security_indicators"]:
            try:
                inds = json.loads(r["security_indicators"])
                for ind in inds:
                    name = ind.get("name")
                    if name in rule_counts:
                        rule_counts[name] += 1
            except Exception:
                pass

    return render_template(
        "security.html",
        bugs=flagged_bugs,
        total_sec=total_sec,
        pending_sec=pending_sec,
        confirmed_sec=confirmed_sec,
        crit_risk_sec=crit_risk_sec,
        rule_counts=rule_counts,
        security_rules=SECURITY_RULES,
        triage_filter=triage_filter,
        risk_filter=risk_filter,
        valid_statuses=VALID_TRIAGE_STATUSES
    )
