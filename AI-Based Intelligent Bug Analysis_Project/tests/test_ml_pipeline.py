import os
import shutil
from pathlib import Path
import pytest
from services.model_training import train_and_save_pipeline
from services.prediction import predict_bug_properties, get_active_model_bundle, reload_model_cache
from services.similarity import find_similar_bugs

TEST_MODELS_DIR = Path(__file__).resolve().parent / "test_models"
SAMPLE_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_training_data.csv"

@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown_models():
    TEST_MODELS_DIR.mkdir(parents=True, exist_ok=True)
    yield
    if TEST_MODELS_DIR.exists():
        shutil.rmtree(TEST_MODELS_DIR)

def test_pipeline_training_and_evaluation():
    metadata = train_and_save_pipeline(
        SAMPLE_DATA_PATH, 
        dataset_name="sample_training_data.csv",
        output_dir=TEST_MODELS_DIR
    )
    
    assert "active_version" in metadata
    assert metadata["total_samples"] >= 15
    assert metadata["train_samples"] > metadata["test_samples"]

    # Verify metrics for all 3 targets
    metrics = metadata["metrics"]
    for target in ["severity", "category", "module"]:
        assert target in metrics
        assert 0.0 <= metrics[target]["accuracy"] <= 1.0
        assert 0.0 <= metrics[target]["f1_score"] <= 1.0
        assert "confusion_matrix" in metrics[target]

    # Check comparison models
    assert "lr_category" in metrics
    assert 0.0 <= metrics["lr_category"]["accuracy"] <= 1.0

def test_prediction_service():
    reload_model_cache()
    
    # Test predicting a security injection bug
    pred_sec = predict_bug_properties(
        "SQL injection exploit in user authentication query",
        "Concatenated raw input allows bypassing password checks with admin'--",
        custom_models_dir=TEST_MODELS_DIR
    )
    assert pred_sec["model_trained"] is True
    assert "severity" in pred_sec
    assert "category" in pred_sec
    assert "affected_module" in pred_sec
    assert pred_sec["confidence_category"] > 0
    assert len(pred_sec["contributing_words"]) > 0
    assert isinstance(pred_sec["explanation"], str)

    # Test predicting a UI bug
    pred_ui = predict_bug_properties(
        "Navbar button overlapping logo on mobile viewport",
        "CSS flexbox issue causes hamburger icon to overlap the text header",
        custom_models_dir=TEST_MODELS_DIR
    )
    assert pred_ui["model_trained"] is True
    assert pred_ui["category"] in ["UI Issue", "Logic Error", "Other"]
