from typing import List, Dict, Any, Optional
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer

from models.database import query_db
from services.preprocessing import clean_text_for_ml, combine_bug_text
from services.prediction import get_active_model_bundle

def find_similar_bugs(
    query_text: str, 
    exclude_bug_id: Optional[str] = None, 
    top_k: int = 5,
    min_threshold: float = 0.05
) -> List[Dict[str, Any]]:
    """
    Finds top-K similar bug reports in the database using TF-IDF cosine similarity.
    """
    clean_query = clean_text_for_ml(query_text)
    if not clean_query:
        return []

    # Fetch all stored bugs
    rows = query_db("""
        SELECT id, bug_id, title, description, severity, category, affected_module, 
               risk_score, risk_level, triage_status, clean_text
        FROM bug_reports
    """)
    if not rows:
        return []

    candidates = [r for r in rows if r["bug_id"] != exclude_bug_id]
    if not candidates:
        return []

    bundle = get_active_model_bundle()
    
    # Use active vectorizer if available, else fit on current corpus
    if bundle and "vectorizer" in bundle:
        vectorizer = bundle["vectorizer"]
        corpus_texts = [c["clean_text"] or clean_text_for_ml(combine_bug_text(c["title"], c["description"])) for c in candidates]
        try:
            query_vec = vectorizer.transform([clean_query])
            corpus_vecs = vectorizer.transform(corpus_texts)
        except Exception:
            # Fallback local vectorizer if vocabulary mismatch
            vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
            corpus_vecs = vectorizer.fit_transform(corpus_texts)
            query_vec = vectorizer.transform([clean_query])
    else:
        corpus_texts = [c["clean_text"] or clean_text_for_ml(combine_bug_text(c["title"], c["description"])) for c in candidates]
        vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        corpus_vecs = vectorizer.fit_transform(corpus_texts + [clean_query])
        query_vec = corpus_vecs[-1:]
        corpus_vecs = corpus_vecs[:-1]

    # Compute cosine similarity
    similarities = cosine_similarity(query_vec, corpus_vecs)[0]

    # Rank results
    ranked_indices = np.argsort(similarities)[::-1]
    results = []

    for idx in ranked_indices:
        sim_score = float(similarities[idx])
        if sim_score < min_threshold and len(results) >= 2:
            break

        cand = candidates[idx]
        sim_percentage = round(sim_score * 100, 1)

        results.append({
            "id": cand["id"],
            "bug_id": cand["bug_id"],
            "title": cand["title"],
            "description": cand["description"][:120] + ("..." if len(cand["description"]) > 120 else ""),
            "severity": cand["severity"],
            "category": cand["category"],
            "affected_module": cand["affected_module"],
            "risk_score": cand["risk_score"],
            "risk_level": cand["risk_level"],
            "triage_status": cand["triage_status"],
            "similarity_score": sim_score,
            "similarity_percentage": sim_percentage
        })

        if len(results) >= top_k:
            break

    return results
