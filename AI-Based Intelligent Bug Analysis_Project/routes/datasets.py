import os
import json
from pathlib import Path
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, current_app
from werkzeug.utils import secure_filename

from models.database import query_db, execute_db, log_audit_event
from models.bug_report import BugReport
from services.data_ingestion import ingest_csv_dataset, is_allowed_file
from services.preprocessing import clean_text_for_ml, combine_bug_text
from services.prediction import predict_bug_properties, reload_model_cache
from services.security_analysis import analyze_security_aspects
from services.risk_scoring import calculate_risk_prioritization_score
from services.model_training import train_and_save_pipeline

datasets_bp = Blueprint("datasets", __name__)

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data"

@datasets_bp.route("/datasets/upload", methods=["GET", "POST"])
def upload():
    # Fetch recent ingestion history
    recent_ingestions = query_db("""
        SELECT * FROM ingestion_history ORDER BY id DESC LIMIT 5
    """)

    if request.method == "POST":
        upload_mode = request.form.get("upload_mode", "ingest_bugs")  # 'ingest_bugs' or 'train_model'
        
        if "csv_file" not in request.files:
            flash("No file part in the submitted form.", "danger")
            return render_template("upload.html", recent_ingestions=recent_ingestions)

        file = request.files["csv_file"]
        if file.filename == "":
            flash("No file selected for upload.", "danger")
            return render_template("upload.html", recent_ingestions=recent_ingestions)

        if not is_allowed_file(file.filename):
            flash("Invalid file type. Only standard CSV (.csv) files are permitted.", "danger")
            return render_template("upload.html", recent_ingestions=recent_ingestions)

        safe_name = secure_filename(file.filename)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        if upload_mode == "train_model":
            # Workflow B: Train models on uploaded dataset
            try:
                metadata = train_and_save_pipeline(file, dataset_name=safe_name)
                reload_model_cache()
                flash(f"Model successfully trained on {safe_name} ({metadata['total_samples']} samples). Version: {metadata['active_version']}.", "success")
                return redirect(url_for("evaluation.model_evaluation"))
            except Exception as e:
                flash(f"Model training failed: {str(e)}", "danger")
                return render_template("upload.html", recent_ingestions=recent_ingestions)

        else:
            # Workflow D: Ingest bug reports for batch analysis
            ingest_result = ingest_csv_dataset(file, source_type="csv_upload")
            if not ingest_result["success"]:
                flash(ingest_result["error"], "danger")
                return render_template("upload.html", recent_ingestions=recent_ingestions, result=ingest_result)

            # Process accepted records through AI & Security pipeline
            accepted_records = ingest_result["accepted_records"]
            processed_count = 0

            for rec in accepted_records:
                # 1. AI Prediction
                pred = predict_bug_properties(rec["title"], rec["description"])
                
                # Use provided severity/category/module if valid, otherwise fallback to ML predictions
                final_sev = rec["severity"] or pred["severity"]
                final_cat = rec["category"] or pred["category"]
                final_mod = rec["affected_module"] or pred["affected_module"]

                # 2. Security Analysis
                sec_res = analyze_security_aspects(
                    rec["title"],
                    rec["description"],
                    ml_category=final_cat,
                    ml_confidence=pred["confidence_category"]
                )

                # 3. Risk Prioritization Score
                risk_calc = calculate_risk_prioritization_score(
                    severity=final_sev,
                    category=final_cat,
                    category_confidence=pred["confidence_category"],
                    affected_module=final_mod,
                    security_indicators=sec_res["indicators"]
                )

                # 4. Construct BugReport
                report = BugReport(
                    title=rec["title"],
                    description=rec["description"],
                    bug_id=rec["bug_id"],
                    clean_text=rec["clean_text"],
                    severity=final_sev,
                    category=final_cat,
                    affected_module=final_mod,
                    is_security_related=sec_res["is_security_related"],
                    security_indicators=json.dumps(sec_res["indicators"]),
                    risk_score=risk_calc["risk_score"],
                    risk_level=risk_calc["risk_level"],
                    triage_status="Pending Review",
                    confidence_severity=pred["confidence_severity"],
                    confidence_category=pred["confidence_category"],
                    confidence_module=pred["confidence_module"],
                    explanation=pred["explanation"],
                    recommended_action=sec_res["recommended_action"],
                    source_type="csv_upload",
                    created_at=now_str,
                    updated_at=now_str
                )

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
                    processed_count += 1
                except Exception as ex:
                    print(f"Skipping insert for {report.bug_id}: {ex}")

            # Record Ingestion History
            rejection_details_json = json.dumps(ingest_result["rejected_records"][:50])
            execute_db("""
                INSERT INTO ingestion_history 
                (timestamp, filename, total_rows, accepted_count, rejected_count, duplicate_count, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                now_str, safe_name, ingest_result["total_rows"],
                processed_count, ingest_result["rejected_count"],
                ingest_result["duplicate_count"], rejection_details_json
            ))

            log_audit_event(
                "DATASET_UPLOAD",
                f"Ingested CSV '{safe_name}': {processed_count} accepted, {ingest_result['rejected_count']} rejected, {ingest_result['duplicate_count']} duplicates.",
                metadata={"filename": safe_name, "accepted": processed_count, "rejected": ingest_result["rejected_count"]}
            )

            flash(f"CSV Ingestion complete: {processed_count} bug reports accepted and analyzed.", "success")
            
            # Refresh recent ingestions
            recent_ingestions = query_db("SELECT * FROM ingestion_history ORDER BY id DESC LIMIT 5")
            return render_template("upload.html", recent_ingestions=recent_ingestions, result=ingest_result)

    return render_template("upload.html", recent_ingestions=recent_ingestions)

@datasets_bp.route("/datasets/load_sample", methods=["POST"])
def load_sample():
    """One-click convenience to load sample training data and bug reports."""
    action = request.form.get("action", "")
    sample_train_path = SAMPLE_DIR / "sample_training_data.csv"
    sample_bugs_path = SAMPLE_DIR / "sample_bug_reports.csv"

    if action == "train_models":
        if not sample_train_path.exists():
            flash("Sample training dataset file not found.", "danger")
            return redirect(url_for("datasets.upload"))
        try:
            meta = train_and_save_pipeline(sample_train_path, dataset_name="sample_training_data.csv")
            reload_model_cache()
            flash(f"Models successfully trained on built-in sample training dataset ({meta['total_samples']} records).", "success")
            return redirect(url_for("evaluation.model_evaluation"))
        except Exception as e:
            flash(f"Training failed: {str(e)}", "danger")
            return redirect(url_for("datasets.upload"))

    elif action == "ingest_sample_bugs":
        if not sample_bugs_path.exists():
            flash("Sample bug reports file not found.", "danger")
            return redirect(url_for("datasets.upload"))
        
        with open(sample_bugs_path, "rb") as f:
            ingest_result = ingest_csv_dataset(f, source_type="sample")

        accepted = ingest_result["accepted_records"]
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        count = 0
        for rec in accepted:
            pred = predict_bug_properties(rec["title"], rec["description"])
            final_sev = rec["severity"] or pred["severity"]
            final_cat = rec["category"] or pred["category"]
            final_mod = rec["affected_module"] or pred["affected_module"]

            sec_res = analyze_security_aspects(rec["title"], rec["description"], final_cat, pred["confidence_category"])
            risk_calc = calculate_risk_prioritization_score(final_sev, final_cat, pred["confidence_category"], final_mod, sec_res["indicators"])

            report = BugReport(
                title=rec["title"],
                description=rec["description"],
                bug_id=rec["bug_id"],
                clean_text=rec["clean_text"],
                severity=final_sev,
                category=final_cat,
                affected_module=final_mod,
                is_security_related=sec_res["is_security_related"],
                security_indicators=json.dumps(sec_res["indicators"]),
                risk_score=risk_calc["risk_score"],
                risk_level=risk_calc["risk_level"],
                triage_status="Pending Review",
                confidence_severity=pred["confidence_severity"],
                confidence_category=pred["confidence_category"],
                confidence_module=pred["confidence_module"],
                explanation=pred["explanation"],
                recommended_action=sec_res["recommended_action"],
                source_type="sample",
                created_at=now_str,
                updated_at=now_str
            )
            try:
                execute_db("""
                INSERT INTO bug_reports (
                    bug_id, title, description, clean_text, severity, category, affected_module,
                    is_security_related, security_indicators, risk_score, risk_level, triage_status,
                    confidence_severity, confidence_category, confidence_module, explanation,
                    recommended_action, source_type, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    report.bug_id, report.title, report.description, report.clean_text,
                    report.severity, report.category, report.affected_module,
                    report.is_security_related, report.security_indicators,
                    report.risk_score, report.risk_level, report.triage_status,
                    report.confidence_severity, report.confidence_category, report.confidence_module,
                    report.explanation, report.recommended_action, report.source_type,
                    report.created_at, report.updated_at
                ))
                count += 1
            except Exception:
                pass

        execute_db("""
            INSERT INTO ingestion_history 
            (timestamp, filename, total_rows, accepted_count, rejected_count, duplicate_count, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (now_str, "sample_bug_reports.csv", ingest_result["total_rows"], count, ingest_result["rejected_count"], ingest_result["duplicate_count"], "[]"))

        log_audit_event("DATASET_UPLOAD", f"Loaded {count} sample bug reports into database.")
        flash(f"Loaded {count} sample bug reports into database with AI and Security analysis.", "success")
        return redirect(url_for("bugs.bug_list"))

    flash("Unrecognized sample loading action.", "warning")
    return redirect(url_for("datasets.upload"))

@datasets_bp.route("/datasets/sample/bug_reports")
def download_sample_bugs():
    path = SAMPLE_DIR / "sample_bug_reports.csv"
    if path.exists():
        return send_file(path, as_attachment=True, download_name="sample_bug_reports.csv")
    flash("Sample file not found.", "danger")
    return redirect(url_for("datasets.upload"))

@datasets_bp.route("/datasets/sample/training_data")
def download_sample_train():
    path = SAMPLE_DIR / "sample_training_data.csv"
    if path.exists():
        return send_file(path, as_attachment=True, download_name="sample_training_data.csv")
    flash("Sample file not found.", "danger")
    return redirect(url_for("datasets.upload"))
