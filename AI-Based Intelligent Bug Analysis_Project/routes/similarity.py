from flask import Blueprint, render_template, request
from models.database import query_db
from services.similarity import find_similar_bugs

similarity_bp = Blueprint("similarity", __name__)

@similarity_bp.route("/similarity", methods=["GET", "POST"])
def similarity_tool():
    query_text = ""
    selected_bug_id = ""
    results = []

    # Get list of existing bugs for easy dropdown selection
    all_bugs = query_db("SELECT bug_id, title FROM bug_reports ORDER BY id DESC LIMIT 50")

    if request.method == "POST":
        selected_bug_id = request.form.get("selected_bug_id", "").strip()
        manual_query = request.form.get("manual_query", "").strip()

        if selected_bug_id:
            # Look up bug details to build search query
            bug = query_db("SELECT title, description FROM bug_reports WHERE bug_id = ?", (selected_bug_id,), one=True)
            if bug:
                query_text = f"{bug['title']} {bug['description']}"
                results = find_similar_bugs(query_text, exclude_bug_id=selected_bug_id, top_k=6)
        elif manual_query:
            query_text = manual_query
            results = find_similar_bugs(query_text, top_k=6)

    return render_template(
        "similarity.html",
        all_bugs=all_bugs,
        selected_bug_id=selected_bug_id,
        query_text=query_text,
        results=results
    )
