import json
import math
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, Response, jsonify
from models.database import query_db, execute_db, log_audit_event
from models.bug_report import BugReport, VALID_SEVERITIES, VALID_CATEGORIES, VALID_MODULES, VALID_TRIAGE_STATUSES
from services.preprocessing import clean_text_for_ml, combine_bug_text
from services.prediction import predict_bug_properties
from services.security_analysis import analyze_security_aspects
from services.risk_scoring import calculate_risk_prioritization_score
from services.similarity import find_similar_bugs
from services.report_export import generate_csv_report, generate_pdf_report

bugs_bp = Blueprint("bugs", __name__)

@bugs_bp.route("/bugs")
def bug_list():
    search = request.args.get("search", "").strip()
    sev_filter = request.args.get("severity", "").strip()
    cat_filter = request.args.get("category", "").strip()
    mod_filter = request.args.get("module", "").strip()
    risk_filter = request.args.get("risk_level", "").strip()
    triage_filter = request.args.get("triage_status", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = 15

    # Build safe parameterized query
    where_clauses = []
    params = []

    if search:
        where_clauses.append("(bug_id LIKE ? OR title LIKE ? OR description LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term, term])

    if sev_filter:
        where_clauses.append("severity = ?")
        params.append(sev_filter)

    if cat_filter:
        where_clauses.append("category = ?")
        params.append(cat_filter)

    if mod_filter:
        where_clauses.append("affected_module = ?")
        params.append(mod_filter)

    if risk_filter:
        where_clauses.append("risk_level = ?")
        params.append(risk_filter)

    if triage_filter:
        where_clauses.append("triage_status = ?")
        params.append(triage_filter)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Count total matching
    count_query = f"SELECT COUNT(*) as count FROM bug_reports {where_sql}"
    total_count = query_db(count_query, params, one=True)["count"]
    total_pages = max(1, math.ceil(total_count / per_page))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    # Fetch paginated rows
    fetch_query = f"""
        SELECT id, bug_id, title, severity, category, affected_module, is_security_related,
               risk_score, risk_level, triage_status, created_at
        FROM bug_reports
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    reports = query_db(fetch_query, params)

    return render_template(
        "bugs.html",
        reports=reports,
        page=page,
        total_pages=total_pages,
        total_count=total_count,
        search=search,
        sev_filter=sev_filter,
        cat_filter=cat_filter,
        mod_filter=mod_filter,
        risk_filter=risk_filter,
        triage_filter=triage_filter,
        valid_severities=VALID_SEVERITIES,
        valid_categories=VALID_CATEGORIES,
        valid_modules=VALID_MODULES,
        valid_statuses=VALID_TRIAGE_STATUSES
    )

@bugs_bp.route("/bugs/analyse", methods=["GET", "POST"])
def analyse():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        user_bug_id = request.form.get("bug_id", "").strip()
        module_hint = request.form.get("module_hint", "").strip()

        # Input validation
        if not title or not description:
            flash("Both bug title and description are required for analysis.", "danger")
            return render_template("analyse.html", title=title, description=description, valid_modules=VALID_MODULES)

        # 1. Run Machine Learning predictions
        pred = predict_bug_properties(title, description)
        
        # Determine module: use user hint if specified and valid, otherwise use ML prediction
        final_module = module_hint if module_hint in VALID_MODULES else pred["affected_module"]

        # 2. Run Security Rule & Indicator Analysis
        sec_result = analyze_security_aspects(
            title, 
            description, 
            ml_category=pred["category"], 
            ml_confidence=pred["confidence_category"]
        )

        # 3. Calculate Risk Prioritization Score
        risk_calc = calculate_risk_prioritization_score(
            severity=pred["severity"],
            category=pred["category"],
            category_confidence=pred["confidence_category"],
            affected_module=final_module,
            security_indicators=sec_result["indicators"]
        )

        # 4. Prepare BugReport object
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        report = BugReport(
            title=title,
            description=description,
            bug_id=user_bug_id if user_bug_id else None,
            clean_text=clean_text_for_ml(combine_bug_text(title, description)),
            severity=pred["severity"],
            category=pred["category"],
            affected_module=final_module,
            is_security_related=sec_result["is_security_related"],
            security_indicators=json.dumps(sec_result["indicators"]),
            risk_score=risk_calc["risk_score"],
            risk_level=risk_calc["risk_level"],
            triage_status="Pending Review",
            confidence_severity=pred["confidence_severity"],
            confidence_category=pred["confidence_category"],
            confidence_module=pred["confidence_module"],
            explanation=pred["explanation"],
            recommended_action=sec_result["recommended_action"],
            source_type="manual",
            created_at=now_str,
            updated_at=now_str
        )

        # 5. Insert into Database
        insert_sql = """
        INSERT INTO bug_reports (
            bug_id, title, description, clean_text, severity, category, affected_module,
            is_security_related, security_indicators, risk_score, risk_level, triage_status,
            confidence_severity, confidence_category, confidence_module, explanation,
            recommended_action, source_type, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            execute_db(insert_sql, (
                report.bug_id, report.title, report.description, report.clean_text,
                report.severity, report.category, report.affected_module,
                report.is_security_related, report.security_indicators,
                report.risk_score, report.risk_level, report.triage_status,
                report.confidence_severity, report.confidence_category, report.confidence_module,
                report.explanation, report.recommended_action, report.source_type,
                report.created_at, report.updated_at
            ))

            log_audit_event(
                "BUG_ANALYSIS",
                f"Analysed manual bug report '{report.bug_id}' ({report.title[:50]}). Severity: {report.severity}, Risk: {report.risk_score} ({report.risk_level}).",
                metadata={"bug_id": report.bug_id, "risk_score": report.risk_score, "is_security": report.is_security_related}
            )

            flash(f"Bug report successfully analyzed and registered as {report.bug_id}.", "success")
            return redirect(url_for("bugs.bug_detail", bug_id=report.bug_id))
        except Exception as e:
            flash(f"Database error while saving bug report: {str(e)}", "danger")
            return render_template("analyse.html", title=title, description=description, valid_modules=VALID_MODULES)

    return render_template("analyse.html", valid_modules=VALID_MODULES)

@bugs_bp.route("/bugs/<bug_id>")
def bug_detail(bug_id):
    report = query_db("SELECT * FROM bug_reports WHERE bug_id = ?", (bug_id,), one=True)
    if not report:
        flash(f"Bug report with ID '{bug_id}' not found.", "warning")
        return redirect(url_for("bugs.bug_list"))

    # Parse indicators JSON safely
    try:
        indicators = json.loads(report["security_indicators"]) if report["security_indicators"] else []
    except Exception:
        indicators = []

    # Retrieve similar bugs using TF-IDF cosine similarity
    similar_bugs = find_similar_bugs(
        f"{report['title']} {report['description']}", 
        exclude_bug_id=report["bug_id"],
        top_k=4
    )

    # Recalculate score breakdown for transparent display
    risk_calc = calculate_risk_prioritization_score(
        severity=report["severity"],
        category=report["category"],
        category_confidence=report["confidence_category"],
        affected_module=report["affected_module"],
        security_indicators=indicators
    )

    return render_template(
        "bug_detail.html",
        report=report,
        indicators=indicators,
        similar_bugs=similar_bugs,
        risk_breakdown=risk_calc["breakdown"],
        valid_statuses=VALID_TRIAGE_STATUSES
    )

@bugs_bp.route("/bugs/<bug_id>/triage", methods=["POST"])
def update_triage(bug_id):
    new_status = request.form.get("triage_status", "").strip()
    if new_status not in VALID_TRIAGE_STATUSES:
        flash("Invalid triage status selected.", "danger")
        return redirect(url_for("bugs.bug_detail", bug_id=bug_id))

    current = query_db("SELECT triage_status FROM bug_reports WHERE bug_id = ?", (bug_id,), one=True)
    if not current:
        flash("Report not found.", "danger")
        return redirect(url_for("bugs.bug_list"))

    old_status = current["triage_status"]
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    execute_db(
        "UPDATE bug_reports SET triage_status = ?, updated_at = ? WHERE bug_id = ?",
        (new_status, now_str, bug_id)
    )

    log_audit_event(
        "TRIAGE_STATUS_UPDATE",
        f"Updated triage status for {bug_id} from '{old_status}' to '{new_status}'.",
        metadata={"bug_id": bug_id, "from": old_status, "to": new_status}
    )

    flash(f"Triage status updated to '{new_status}'.", "success")
    return redirect(url_for("bugs.bug_detail", bug_id=bug_id))

@bugs_bp.route("/bugs/export/csv")
def export_csv():
    # Build filter query similar to bug_list
    search = request.args.get("search", "").strip()
    sev_filter = request.args.get("severity", "").strip()
    cat_filter = request.args.get("category", "").strip()
    risk_filter = request.args.get("risk_level", "").strip()
    triage_filter = request.args.get("triage_status", "").strip()

    where_clauses = []
    params = []
    if search:
        where_clauses.append("(bug_id LIKE ? OR title LIKE ? OR description LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if sev_filter:
        where_clauses.append("severity = ?")
        params.append(sev_filter)
    if cat_filter:
        where_clauses.append("category = ?")
        params.append(cat_filter)
    if risk_filter:
        where_clauses.append("risk_level = ?")
        params.append(risk_filter)
    if triage_filter:
        where_clauses.append("triage_status = ?")
        params.append(triage_filter)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"SELECT * FROM bug_reports {where_sql} ORDER BY id DESC"
    reports = query_db(sql, params)

    csv_content = generate_csv_report(reports)
    
    log_audit_event(
        "REPORT_EXPORT_CSV",
        f"Exported {len(reports)} bug records to CSV.",
        metadata={"record_count": len(reports)}
    )

    filename = f"bug_reports_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@bugs_bp.route("/bugs/export/pdf")
def export_pdf():
    search = request.args.get("search", "").strip()
    sev_filter = request.args.get("severity", "").strip()
    cat_filter = request.args.get("category", "").strip()
    risk_filter = request.args.get("risk_level", "").strip()
    triage_filter = request.args.get("triage_status", "").strip()

    where_clauses = []
    params = []
    if search:
        where_clauses.append("(bug_id LIKE ? OR title LIKE ? OR description LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if sev_filter:
        where_clauses.append("severity = ?")
        params.append(sev_filter)
    if cat_filter:
        where_clauses.append("category = ?")
        params.append(cat_filter)
    if risk_filter:
        where_clauses.append("risk_level = ?")
        params.append(risk_filter)
    if triage_filter:
        where_clauses.append("triage_status = ?")
        params.append(triage_filter)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    sql = f"SELECT * FROM bug_reports {where_sql} ORDER BY id DESC"
    reports = query_db(sql, params)

    pdf_bytes = generate_pdf_report(reports, title_suffix="Prioritization & Triage Audit")

    log_audit_event(
        "REPORT_EXPORT_PDF",
        f"Generated executive PDF report for {len(reports)} bug records.",
        metadata={"record_count": len(reports)}
    )

    filename = f"bug_analysis_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
