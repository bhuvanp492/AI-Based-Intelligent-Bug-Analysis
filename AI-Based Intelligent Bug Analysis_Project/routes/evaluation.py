import json
from pathlib import Path
from flask import Blueprint, render_template, request, redirect, url_for, flash
from models.database import query_db, log_audit_event
from services.model_training import train_and_save_pipeline
from services.prediction import get_active_model_bundle, reload_model_cache

evaluation_bp = Blueprint("evaluation", __name__)
MODELS_DIR = Path(__file__).resolve().parent.parent / "trained_models"

@evaluation_bp.route("/evaluation")
def model_evaluation():
    # Read active model metadata
    meta_path = MODELS_DIR / "active_model_meta.json"
    metadata = None
    if meta_path.exists():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception:
            metadata = None

    # Fetch training history records
    history = query_db("""
        SELECT * FROM model_training_history ORDER BY id DESC LIMIT 10
    """)
    for h in history:
        try:
            h["sev_parsed"] = json.loads(h["severity_metrics"]) if h["severity_metrics"] else {}
            h["cat_parsed"] = json.loads(h["category_metrics"]) if h["category_metrics"] else {}
            h["mod_parsed"] = json.loads(h["module_metrics"]) if h["module_metrics"] else {}
            h["comp_parsed"] = json.loads(h["comparison_metrics"]) if h["comparison_metrics"] else {}
        except Exception:
            pass

    return render_template(
        "evaluation.html",
        metadata=metadata,
        history=history
    )

@evaluation_bp.route("/evaluation/retrain", methods=["POST"])
def retrain_model():
    sample_train_path = Path(__file__).resolve().parent.parent / "data" / "sample_training_data.csv"
    if not sample_train_path.exists():
        flash("Training dataset not found.", "danger")
        return redirect(url_for("evaluation.model_evaluation"))

    try:
        meta = train_and_save_pipeline(sample_train_path, dataset_name="sample_training_data.csv")
        reload_model_cache()
        flash(f"Model retrained successfully. New version: {meta['active_version']}.", "success")
    except Exception as e:
        flash(f"Retraining failed: {str(e)}", "danger")

    return redirect(url_for("evaluation.model_evaluation"))
