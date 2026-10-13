"""
Utility script to initialize development database with demonstration datasets.
Usage: py data/init_demo_data.py
"""
import os
import json
from pathlib import Path

# Adjust root
BASE_DIR = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(BASE_DIR))

from app import create_app
from services.data_ingestion import ingest_csv_dataset
from services.model_training import train_and_save_pipeline
from services.prediction import predict_bug_properties, reload_model_cache
from services.security_analysis import analyze_security_aspects
from services.risk_scoring import calculate_risk_prioritization_score
from models.database import execute_db, query_db, log_audit_event
from models.bug_report import BugReport

def main():
    app = create_app()
    with app.app_context():
        print("[1/3] Checking trained machine learning models...")
        sample_train = BASE_DIR / "data" / "sample_training_data.csv"
        meta = train_and_save_pipeline(sample_train, dataset_name="sample_training_data.csv")
        reload_model_cache()
        print(f"      Trained model pipeline {meta['active_version']} on {meta['total_samples']} samples.")

        print("[2/3] Checking demonstration bug reports in database...")
        existing = query_db("SELECT COUNT(*) as count FROM bug_reports", one=True)["count"]
        if existing == 0:
            sample_bugs = BASE_DIR / "data" / "sample_bug_reports.csv"
            with open(sample_bugs, "rb") as f:
                res = ingest_csv_dataset(f)
            
            count = 0
            for r in res["accepted_records"]:
                pred = predict_bug_properties(r["title"], r["description"])
                final_sev = r["severity"] or pred["severity"]
                final_cat = r["category"] or pred["category"]
                final_mod = r["affected_module"] or pred["affected_module"]

                sec = analyze_security_aspects(r["title"], r["description"], final_cat, pred["confidence_category"])
                risk = calculate_risk_prioritization_score(final_sev, final_cat, pred["confidence_category"], final_mod, sec["indicators"])

                b = BugReport(
                    title=r["title"],
                    description=r["description"],
                    bug_id=r["bug_id"],
                    clean_text=r["clean_text"],
                    severity=final_sev,
                    category=final_cat,
                    affected_module=final_mod,
                    is_security_related=sec["is_security_related"],
                    security_indicators=json.dumps(sec["indicators"]),
                    risk_score=risk["risk_score"],
                    risk_level=risk["risk_level"],
                    triage_status="Pending Review",
                    confidence_severity=pred["confidence_severity"],
                    confidence_category=pred["confidence_category"],
                    confidence_module=pred["confidence_module"],
                    explanation=pred["explanation"],
                    recommended_action=sec["recommended_action"],
                    source_type="sample"
                )

                execute_db("""
                INSERT INTO bug_reports (
                    bug_id, title, description, clean_text, severity, category, affected_module,
                    is_security_related, security_indicators, risk_score, risk_level, triage_status,
                    confidence_severity, confidence_category, confidence_module, explanation,
                    recommended_action, source_type, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    b.bug_id, b.title, b.description, b.clean_text,
                    b.severity, b.category, b.affected_module,
                    b.is_security_related, b.security_indicators,
                    b.risk_score, b.risk_level, b.triage_status,
                    b.confidence_severity, b.confidence_category, b.confidence_module,
                    b.explanation, b.recommended_action, b.source_type,
                    b.created_at, b.updated_at
                ))
                count += 1
            print(f"      Successfully populated {count} sample bug reports into database.")
            log_audit_event("DATASET_UPLOAD", f"Populated {count} initial demonstration bug reports.")
        else:
            print(f"      Database already contains {existing} bug reports.")

        print("[3/3] Initialization complete! System is ready.")

if __name__ == "__main__":
    main()
