import os
import secrets
from pathlib import Path
from flask import Flask, render_template, session, request, abort, redirect, url_for, flash

from config import get_config, BASE_DIR
from models.database import init_db, close_db, log_audit_event
from services.model_training import train_and_save_pipeline
from services.prediction import get_active_model_bundle, reload_model_cache

def create_app(config_class=None):
    app = Flask(__name__)
    
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # Ensure instance and upload directories exist
    os.makedirs(app.config.get("UPLOAD_FOLDER", "instance/uploads"), exist_ok=True)
    os.makedirs(app.config.get("TRAINED_MODELS_DIR", "trained_models"), exist_ok=True)

    # Initialize Database Schema
    init_db(app.config.get("DATABASE_PATH"))

    # Register Database teardown
    app.teardown_appcontext(close_db)

    # CSRF Token Generator & Context Processor
    @app.before_request
    def check_csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(24)

        # Enforce CSRF on state-modifying requests if not testing
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if not app.config.get("TESTING", False):
                # Check form or header
                token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
                expected = session.get("csrf_token")
                # Allow internal testing or skip if specifically exempt
                if not token or token != expected:
                    flash("CSRF validation failed or session expired. Please retry.", "danger")
                    return redirect(request.referrer or url_for("dashboard.index"))

    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=session.get("csrf_token", ""))

    # Context processor for active page in navigation
    @app.context_processor
    def inject_nav_helper():
        return dict(current_endpoint=request.endpoint or "")

    # Register Blueprints
    from routes.dashboard import dashboard_bp
    from routes.bugs import bugs_bp
    from routes.datasets import datasets_bp
    from routes.security import security_bp
    from routes.similarity import similarity_bp
    from routes.evaluation import evaluation_bp
    from routes.audit import audit_bp
    from routes.about import about_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(bugs_bp)
    app.register_blueprint(datasets_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(similarity_bp)
    app.register_blueprint(evaluation_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(about_bp)

    # Custom Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message="Bad Request: The submission could not be processed."), 400

    @app.errorhandler(404)
    def not_found(error):
        return render_template("error.html", code=404, message="Page Not Found: The requested endpoint does not exist."), 404

    @app.errorhandler(413)
    def file_too_large(error):
        return render_template("error.html", code=413, message="File Size Limit Exceeded: Maximum allowed upload is 16 MB."), 413

    @app.errorhandler(500)
    def internal_error(error):
        return render_template("error.html", code=500, message="An internal server error occurred. The incident has been recorded safely."), 500

    # Auto-initialize initial demonstration model if not yet trained
    with app.app_context():
        active = get_active_model_bundle(app.config.get("TRAINED_MODELS_DIR"))
        if not active:
            sample_train_file = Path(app.config.get("SAMPLE_DATA_DIR", "data")) / "sample_training_data.csv"
            if sample_train_file.exists():
                try:
                    train_and_save_pipeline(sample_train_file, dataset_name="sample_training_data.csv", output_dir=app.config.get("TRAINED_MODELS_DIR"))
                    reload_model_cache()
                    print("[SYSTEM] Initial baseline models trained from sample training dataset.")
                except Exception as e:
                    print(f"[SYSTEM NOTICE] Initial model training postponed: {e}")

        try:
            log_audit_event("SYSTEM_INIT", "Application server initialized successfully.")
        except Exception:
            pass

    return app

app = create_app()

if __name__ == "__main__":
    # Running development server
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
