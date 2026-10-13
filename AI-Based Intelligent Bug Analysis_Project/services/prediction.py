import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import joblib

from services.preprocessing import clean_text_for_ml, combine_bug_text

MODELS_DIR = Path(__file__).resolve().parent.parent / "trained_models"

_CACHED_BUNDLE = None
_CACHED_BUNDLE_PATH = None

def get_active_model_bundle(custom_models_dir=None):
    """
    Returns the cached active model bundle, loading it from disk if needed.
    """
    global _CACHED_BUNDLE, _CACHED_BUNDLE_PATH
    models_dir = Path(custom_models_dir) if custom_models_dir else MODELS_DIR
    active_path = models_dir / "bug_models_active.joblib"

    if not active_path.exists():
        # Look for any versioned joblib
        candidates = list(models_dir.glob("bug_models_v_*.joblib"))
        if candidates:
            candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            active_path = candidates[0]
        else:
            return None

    if _CACHED_BUNDLE is not None and _CACHED_BUNDLE_PATH == str(active_path):
        return _CACHED_BUNDLE

    try:
        bundle = joblib.load(active_path)
        _CACHED_BUNDLE = bundle
        _CACHED_BUNDLE_PATH = str(active_path)
        return bundle
    except Exception as e:
        print(f"[MODEL LOAD ERROR] Could not load model from {active_path}: {e}")
        return None

def reload_model_cache():
    """Forces cache refresh when a new model is trained."""
    global _CACHED_BUNDLE, _CACHED_BUNDLE_PATH
    _CACHED_BUNDLE = None
    _CACHED_BUNDLE_PATH = None

def extract_top_contributing_words(vectorizer, model, text_clean: str, predicted_class: str, top_k=5) -> List[str]:
    """
    Identifies words in the text that most strongly contributed to the predicted class
    using TF-IDF weights multiplied by feature log-probabilities in MultinomialNB.
    """
    try:
        feature_names = np.array(vectorizer.get_feature_names_out())
        vec = vectorizer.transform([text_clean])
        non_zero_indices = vec.indices
        
        if len(non_zero_indices) == 0:
            return []

        class_idx = list(model.classes_).index(predicted_class)
        log_probs = model.feature_log_prob_[class_idx]

        # Score per word = tfidf_value * exp(log_prob)
        scores = []
        for idx in non_zero_indices:
            tfidf_val = vec[0, idx]
            word_score = tfidf_val * np.exp(log_probs[idx])
            scores.append((feature_names[idx], word_score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return [w[0] for w in scores[:top_k]]
    except Exception:
        # Fallback keyword extraction
        words = text_clean.split()
        return list(dict.fromkeys(words))[:top_k]

def predict_bug_properties(title: str, description: str, custom_models_dir=None) -> Dict[str, Any]:
    """
    Runs multi-task prediction on bug report text.
    Returns predicted severity, category, module, model confidences,
    top contributing features, and explanation.
    """
    combined_raw = combine_bug_text(title, description)
    text_clean = clean_text_for_ml(combined_raw)
    
    bundle = get_active_model_bundle(custom_models_dir)

    # Fallback if models are not yet trained
    if bundle is None:
        return {
            "model_trained": False,
            "severity": "Medium",
            "category": "Other",
            "affected_module": "Other",
            "confidence_severity": 0.50,
            "confidence_category": 0.50,
            "confidence_module": 0.50,
            "contributing_words": [],
            "explanation": "Predictions generated using default baseline heuristics because no machine learning model has been trained yet. Please train the model on the Training page.",
            "probabilities": {}
        }

    vectorizer = bundle["vectorizer"]
    models = bundle["models"]

    X_vec = vectorizer.transform([text_clean])

    # 1. Severity Prediction
    sev_model = models["severity"]
    sev_pred = sev_model.predict(X_vec)[0]
    sev_proba = sev_model.predict_proba(X_vec)[0]
    sev_conf = float(np.max(sev_proba))
    sev_words = extract_top_contributing_words(vectorizer, sev_model, text_clean, sev_pred, top_k=3)

    # 2. Category Prediction
    cat_model = models["category"]
    cat_pred = cat_model.predict(X_vec)[0]
    cat_proba = cat_model.predict_proba(X_vec)[0]
    cat_conf = float(np.max(cat_proba))
    cat_words = extract_top_contributing_words(vectorizer, cat_model, text_clean, cat_pred, top_k=4)

    # 3. Module Prediction
    mod_model = models["module"]
    mod_pred = mod_model.predict(X_vec)[0]
    mod_proba = mod_model.predict_proba(X_vec)[0]
    mod_conf = float(np.max(mod_proba))
    mod_words = extract_top_contributing_words(vectorizer, mod_model, text_clean, mod_pred, top_k=3)

    # Combined distinctive contributing words
    all_words = list(dict.fromkeys(cat_words + sev_words + mod_words))[:6]

    # Explanation generation
    words_quoted = ", ".join([f"'{w}'" for w in all_words[:4]]) if all_words else "general report phrasing"
    explanation_parts = [
        f"Classified as **{cat_pred}** ({round(cat_conf * 100, 1)}% confidence) based on characteristic phrasing such as {words_quoted}.",
        f"Predicted severity **{sev_pred}** ({round(sev_conf * 100, 1)}% confidence) reflecting the urgency and scope of impact described.",
        f"Mapped to the **{mod_pred}** module ({round(mod_conf * 100, 1)}% confidence)."
    ]
    explanation = " ".join(explanation_parts)

    return {
        "model_trained": True,
        "model_version": bundle.get("version", "v1"),
        "severity": str(sev_pred),
        "category": str(cat_pred),
        "affected_module": str(mod_pred),
        "confidence_severity": round(sev_conf, 4),
        "confidence_category": round(cat_conf, 4),
        "confidence_module": round(mod_conf, 4),
        "contributing_words": all_words,
        "explanation": explanation,
        "probabilities": {
            "severity": {cls: round(float(p), 4) for cls, p in zip(sev_model.classes_, sev_proba)},
            "category": {cls: round(float(p), 4) for cls, p in zip(cat_model.classes_, cat_proba)},
            "module": {cls: round(float(p), 4) for cls, p in zip(mod_model.classes_, mod_proba)}
        }
    }
