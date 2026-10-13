import json
from flask import Blueprint, render_template, request
from models.database import query_db

audit_bp = Blueprint("audit", __name__)

@audit_bp.route("/audit")
def audit_trail():
    event_filter = request.args.get("event_type", "").strip()
    
    where_sql = "WHERE event_type = ?" if event_filter else ""
    params = [event_filter] if event_filter else []
    
    query = f"""
        SELECT id, timestamp, event_type, description, ip_address, status, metadata
        FROM audit_logs
        {where_sql}
        ORDER BY id DESC
        LIMIT 100
    """
    logs = query_db(query, params)

    # Parse metadata
    for log in logs:
        try:
            log["metadata_parsed"] = json.loads(log["metadata"]) if log["metadata"] else {}
        except Exception:
            log["metadata_parsed"] = {}

    # Distinct event types for dropdown
    event_types = query_db("SELECT DISTINCT event_type FROM audit_logs ORDER BY event_type")
    type_list = [r["event_type"] for r in event_types]

    return render_template(
        "audit.html",
        logs=logs,
        event_filter=event_filter,
        type_list=type_list
    )
