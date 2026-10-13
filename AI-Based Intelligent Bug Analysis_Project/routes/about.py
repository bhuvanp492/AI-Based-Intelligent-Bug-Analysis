from flask import Blueprint, render_template
from services.security_analysis import SECURITY_RULES
from services.risk_scoring import MODULE_CRITICALITY, SEVERITY_WEIGHTS

about_bp = Blueprint("about", __name__)

@about_bp.route("/about")
def about_page():
    return render_template(
        "about.html",
        security_rules=SECURITY_RULES,
        module_criticality=MODULE_CRITICALITY,
        severity_weights=SEVERITY_WEIGHTS
    )
