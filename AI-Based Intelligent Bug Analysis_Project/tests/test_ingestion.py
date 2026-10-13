import io
import pytest
from services.data_ingestion import ingest_csv_dataset, resolve_column_mapping, is_allowed_file

def test_is_allowed_file():
    assert is_allowed_file("dataset.csv") is True
    assert is_allowed_file("DATA.CSV") is True
    assert is_allowed_file("malicious.exe") is False
    assert is_allowed_file("script.py") is False
    assert is_allowed_file("no_extension") is False

def test_resolve_column_mapping_aliases():
    headers = ["Summary", "Details", "Priority", "Component", "Ticket_ID"]
    mapping = resolve_column_mapping(headers)
    assert mapping["title"] == "Summary"
    assert mapping["description"] == "Details"
    assert mapping["severity"] == "Priority"
    assert mapping["affected_module"] == "Component"
    assert mapping["bug_id"] == "Ticket_ID"

def test_valid_csv_ingestion():
    csv_data = """bug_id,title,description,severity,category,affected_module
BUG-01,Login crash,Server throws 500 when logging in,High,Logic Error,Authentication
BUG-02,Button misalignment,Submit button overlaps banner,Low,UI Issue,Dashboard
"""
    stream = io.BytesIO(csv_data.encode("utf-8"))
    res = ingest_csv_dataset(stream)
    assert res["success"] is True
    assert res["total_rows"] == 2
    assert res["accepted_count"] == 2
    assert res["rejected_count"] == 0
    assert len(res["accepted_records"]) == 2

def test_missing_required_columns_rejection():
    # Neither title nor description present
    csv_data = """status,author,date
open,alice,2026-01-01
closed,bob,2026-01-02
"""
    stream = io.BytesIO(csv_data.encode("utf-8"))
    res = ingest_csv_dataset(stream)
    assert res["success"] is False
    assert "Missing required columns" in res["error"]

def test_duplicate_row_detection_in_batch():
    csv_data = """title,description
Duplicate title,Duplicate description
Duplicate title,Duplicate description
Unique title,Unique description
"""
    stream = io.BytesIO(csv_data.encode("utf-8"))
    res = ingest_csv_dataset(stream)
    assert res["success"] is True
    assert res["accepted_count"] == 2
    assert res["duplicate_count"] == 1
