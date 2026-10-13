import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report

from services.preprocessing import clean_text_for_ml, combine_bug_text
from services.data_ingestion import read_csv_with_fallback, resolve_column_mapping
from models.database import execute_db, log_audit_event

MODELS_DIR = Path(__file__).resolve().parent.parent / "trained_models"

def compute_metrics(y_true, y_pred, labels=None) -> Dict[str, Any]:
    """Computes standard evaluation metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    
    unique_labels = sorted(list(set(y_true) | set(y_pred))) if labels is None else labels
    cm = confusion_matrix(y_true, y_pred, labels=unique_labels).tolist()
    
    report = classification_report(y_true, y_pred, labels=unique_labels, output_dict=True, zero_division=0)
    
    return {
        "accuracy": round(acc, 4),
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1_score": round(float(f1), 4),
        "labels": unique_labels,
        "confusion_matrix": cm,
        "classification_report": report
    }

def train_and_save_pipeline(csv_path_or_df, dataset_name="custom_dataset.csv", output_dir=None) -> Dict[str, Any]:
    """
    Trains TF-IDF vectorizer and Multinomial Naive Bayes models for:
    1. Severity
    2. Category
    3. Affected Module
    Also trains Logistic Regression models for side-by-side performance comparison.
    Saves serialized bundle with joblib.
    """
    if output_dir is None:
        target_models_dir = MODELS_DIR
    else:
        target_models_dir = Path(output_dir)
        
    target_models_dir.mkdir(parents=True, exist_ok=True)

    if isinstance(csv_path_or_df, (str, Path)):
        df = read_csv_with_fallback(csv_path_or_df)
    else:
        df = csv_path_or_df.copy()

    col_map = resolve_column_mapping(list(df.columns))
    
    # Verify required columns for training
    required = ["title", "description", "severity", "category", "affected_module"]
    missing = [req for req in required if not col_map[req]]
    if missing:
        raise ValueError(f"Training dataset is missing required labelled columns: {', '.join(missing)}. Please provide severity, category, and affected_module labels.")

    # Drop rows where target labels are null or empty
    df = df.dropna(subset=[col_map["severity"], col_map["category"], col_map["affected_module"]])
    if len(df) < 15:
        raise ValueError(f"Training dataset has only {len(df)} labelled records. At least 15 labelled records are required to train and evaluate models.")

    # Prepare features
    X_raw = []
    for _, row in df.iterrows():
        t = str(row[col_map["title"]]) if pd.notna(row[col_map["title"]]) else ""
        d = str(row[col_map["description"]]) if pd.notna(row[col_map["description"]]) else ""
        combined = combine_bug_text(t, d)
        X_raw.append(clean_text_for_ml(combined))

    y_sev = df[col_map["severity"]].astype(str).str.strip().tolist()
    y_cat = df[col_map["category"]].astype(str).str.strip().tolist()
    y_mod = df[col_map["affected_module"]].astype(str).str.strip().tolist()

    total_samples = len(X_raw)
    
    # Train / Test Split (80% train, 20% test)
    # Stratification check on category
    can_stratify = False
    try:
        cat_counts = pd.Series(y_cat).value_counts()
        if (cat_counts >= 2).all() and len(cat_counts) > 1:
            can_stratify = True
    except Exception:
        can_stratify = False

    indices = list(range(total_samples))
    try:
        idx_train, idx_test = train_test_split(
            indices, test_size=0.2, random_state=42, 
            stratify=y_cat if can_stratify else None
        )
    except Exception:
        idx_train, idx_test = train_test_split(indices, test_size=0.2, random_state=42)

    X_train_raw = [X_raw[i] for i in idx_train]
    X_test_raw = [X_raw[i] for i in idx_test]

    # TF-IDF Vectorizer fit strictly on training set to avoid data leakage
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=3000,
        sublinear_tf=True,
        stop_words="english",
        min_df=1
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_raw)
    X_test_tfidf = vectorizer.transform(X_test_raw)

    # 1. Severity Models
    y_sev_train = [y_sev[i] for i in idx_train]
    y_sev_test = [y_sev[i] for i in idx_test]
    nb_sev = MultinomialNB(alpha=0.5)
    nb_sev.fit(X_train_tfidf, y_sev_train)
    lr_sev = LogisticRegression(max_iter=1000, random_state=42)
    lr_sev.fit(X_train_tfidf, y_sev_train)

    y_sev_pred = nb_sev.predict(X_test_tfidf)
    y_sev_pred_lr = lr_sev.predict(X_test_tfidf)
    sev_metrics = compute_metrics(y_sev_test, y_sev_pred, labels=sorted(list(set(y_sev))))
    sev_lr_metrics = compute_metrics(y_sev_test, y_sev_pred_lr, labels=sorted(list(set(y_sev))))

    # 2. Category Models
    y_cat_train = [y_cat[i] for i in idx_train]
    y_cat_test = [y_cat[i] for i in idx_test]
    nb_cat = MultinomialNB(alpha=0.5)
    nb_cat.fit(X_train_tfidf, y_cat_train)
    lr_cat = LogisticRegression(max_iter=1000, random_state=42)
    lr_cat.fit(X_train_tfidf, y_cat_train)

    y_cat_pred = nb_cat.predict(X_test_tfidf)
    y_cat_pred_lr = lr_cat.predict(X_test_tfidf)
    cat_metrics = compute_metrics(y_cat_test, y_cat_pred, labels=sorted(list(set(y_cat))))
    cat_lr_metrics = compute_metrics(y_cat_test, y_cat_pred_lr, labels=sorted(list(set(y_cat))))

    # 3. Module Models
    y_mod_train = [y_mod[i] for i in idx_train]
    y_mod_test = [y_mod[i] for i in idx_test]
    nb_mod = MultinomialNB(alpha=0.5)
    nb_mod.fit(X_train_tfidf, y_mod_train)
    lr_mod = LogisticRegression(max_iter=1000, random_state=42)
    lr_mod.fit(X_train_tfidf, y_mod_train)

    y_mod_pred = nb_mod.predict(X_test_tfidf)
    y_mod_pred_lr = lr_mod.predict(X_test_tfidf)
    mod_metrics = compute_metrics(y_mod_test, y_mod_pred, labels=sorted(list(set(y_mod))))
    mod_lr_metrics = compute_metrics(y_mod_test, y_mod_pred_lr, labels=sorted(list(set(y_mod))))

    # Timestamp and versioning
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    version = f"v_{timestamp_str}"
    trained_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Model artifact bundle
    model_bundle = {
        "version": version,
        "trained_at": trained_at,
        "algorithm": "Multinomial Naive Bayes (Primary) / Logistic Regression (Comparison)",
        "vectorizer": vectorizer,
        "models": {
            "severity": nb_sev,
            "category": nb_cat,
            "module": nb_mod,
            "lr_severity": lr_sev,
            "lr_category": lr_cat,
            "lr_module": lr_mod
        },
        "classes": {
            "severity": list(nb_sev.classes_),
            "category": list(nb_cat.classes_),
            "module": list(nb_mod.classes_)
        },
        "sample_counts": {
            "total": total_samples,
            "train": len(idx_train),
            "test": len(idx_test)
        },
        "evaluation": {
            "severity": sev_metrics,
            "category": cat_metrics,
            "module": mod_metrics,
            "comparison": {
                "severity": {"naive_bayes": sev_metrics["macro_summary"] if "macro_summary" in sev_metrics else sev_metrics["accuracy"], "logistic_regression": sev_lr_metrics["accuracy"]},
                "category": {"naive_bayes": cat_metrics["accuracy"], "logistic_regression": cat_lr_metrics["accuracy"]},
                "module": {"naive_bayes": mod_metrics["accuracy"], "logistic_regression": mod_lr_metrics["accuracy"]}
            }
        }
    }

    # Save to disk
    bundle_path = target_models_dir / f"bug_models_{version}.joblib"
    active_path = target_models_dir / "bug_models_active.joblib"
    meta_path = target_models_dir / "active_model_meta.json"

    joblib.dump(model_bundle, bundle_path)
    joblib.dump(model_bundle, active_path)

    metadata = {
        "active_version": version,
        "trained_at": trained_at,
        "dataset_name": dataset_name,
        "total_samples": total_samples,
        "train_samples": len(idx_train),
        "test_samples": len(idx_test),
        "metrics": {
            "severity": sev_metrics,
            "category": cat_metrics,
            "module": mod_metrics,
            "lr_severity": sev_lr_metrics,
            "lr_category": cat_lr_metrics,
            "lr_module": mod_lr_metrics
        }
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Record in database history
    try:
        query = """
        INSERT INTO model_training_history 
        (model_version, dataset_name, total_samples, train_samples, test_samples, algorithm, 
         severity_metrics, category_metrics, module_metrics, comparison_metrics, trained_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        execute_db(query, (
            version,
            dataset_name,
            total_samples,
            len(idx_train),
            len(idx_test),
            "Multinomial Naive Bayes & Logistic Regression",
            json.dumps(sev_metrics),
            json.dumps(cat_metrics),
            json.dumps(mod_metrics),
            json.dumps({
                "severity_lr": sev_lr_metrics,
                "category_lr": cat_lr_metrics,
                "module_lr": mod_lr_metrics
            }),
            trained_at,
            "success"
        ))
        
        log_audit_event(
            "MODEL_TRAINING",
            f"Trained new model pipeline {version} on dataset '{dataset_name}' with {total_samples} samples.",
            metadata={"version": version, "accuracy_category": cat_metrics["accuracy"]}
        )
    except Exception as e:
        print(f"[DB LOG WARNING] Could not insert training history into DB: {e}")

    return metadata
