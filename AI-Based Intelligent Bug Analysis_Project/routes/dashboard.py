import json
from flask import Blueprint, render_template, jsonify
from models.database import query_db
from services.prediction import get_active_model_bundle

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
def index():
    # 1. Fetch KPI Counts
    total_bugs = query_db("SELECT COUNT(*) as count FROM bug_reports", one=True)["count"]
    high_crit_bugs = query_db("SELECT COUNT(*) as count FROM bug_reports WHERE severity IN ('High', 'Critical')", one=True)["count"]
    security_bugs = query_db("SELECT COUNT(*) as count FROM bug_reports WHERE is_security_related = 1", one=True)["count"]
    pending_triage = query_db("SELECT COUNT(*) as count FROM bug_reports WHERE is_security_related = 1 AND triage_status = 'Pending Review'", one=True)["count"]

    # 2. Severity Distribution
    sev_rows = query_db("SELECT severity, COUNT(*) as count FROM bug_reports GROUP BY severity")
    sev_dict = {r["severity"]: r["count"] for r in sev_rows}
    severity_dist = {
        "Critical": sev_dict.get("Critical", 0),
        "High": sev_dict.get("High", 0),
        "Medium": sev_dict.get("Medium", 0),
        "Low": sev_dict.get("Low", 0)
    }

    # 3. Category Distribution
    cat_rows = query_db("SELECT category, COUNT(*) as count FROM bug_reports GROUP BY category ORDER BY count DESC")
    category_labels = [r["category"] for r in cat_rows]
    category_counts = [r["count"] for r in cat_rows]

    # 4. Risk Level Distribution
    risk_rows = query_db("SELECT risk_level, COUNT(*) as count FROM bug_reports GROUP BY risk_level")
    risk_dict = {r["risk_level"]: r["count"] for r in risk_rows}
    risk_dist = {
        "Critical": risk_dict.get("Critical", 0),
        "High": risk_dict.get("High", 0),
        "Medium": risk_dict.get("Medium", 0),
        "Low": risk_dict.get("Low", 0)
    }

    # 5. Recent Reports
    recent_reports = query_db("""
        SELECT id, bug_id, title, severity, category, affected_module, is_security_related,
               risk_score, risk_level, triage_status, created_at
        FROM bug_reports
        ORDER BY id DESC
        LIMIT 8
    """)

    # 6. Model Status Info
    active_bundle = get_active_model_bundle()
    model_status = {
        "is_trained": active_bundle is not None,
        "version": active_bundle.get("version", "N/A") if active_bundle else "None",
        "trained_at": active_bundle.get("trained_at", "N/A") if active_bundle else "Not Trained",
        "sample_counts": active_bundle.get("sample_counts", {}) if active_bundle else {}
    }

    return render_template(
        "dashboard.html",
        total_bugs=total_bugs,
        high_crit_bugs=high_crit_bugs,
        security_bugs=security_bugs,
        pending_triage=pending_triage,
        severity_dist=severity_dist,
        category_labels=category_labels,
        category_counts=category_counts,
        risk_dist=risk_dist,
        recent_reports=recent_reports,
        model_status=model_status
    )

@dashboard_bp.route("/api/dashboard/stats")
def api_stats():
    """JSON stats endpoint for client-side chart refreshing."""
    sev_rows = query_db("SELECT severity, COUNT(*) as count FROM bug_reports GROUP BY severity")
    cat_rows = query_db("SELECT category, COUNT(*) as count FROM bug_reports GROUP BY category ORDER BY count DESC")
    risk_rows = query_db("SELECT risk_level, COUNT(*) as count FROM bug_reports GROUP BY risk_level")
    
    return jsonify({
        "severity": {r["severity"]: r["count"] for r in sev_rows},
        "category": {r["category"]: r["count"] for r in cat_rows},
        "risk_level": {r["risk_level"]: r["count"] for r in risk_rows}
    })
