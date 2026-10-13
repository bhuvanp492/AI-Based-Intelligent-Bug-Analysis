import csv
import io
import os
import hashlib
from typing import Dict, List, Tuple, Any, Optional
import pandas as pd
from werkzeug.utils import secure_filename
from models.bug_report import BugReport, VALID_SEVERITIES, VALID_CATEGORIES, VALID_MODULES
from models.database import query_db, execute_db
from services.preprocessing import clean_text_for_ml, combine_bug_text

ALLOWED_EXTENSIONS = {'csv'}

# Column alias dictionary for flexible header mapping
COLUMN_ALIASES = {
    "bug_id": ["bug_id", "id", "issue_id", "bug id", "bugid", "ticket_id", "ticket", "key"],
    "title": ["title", "bug_title", "summary", "bug title", "issue_title", "subject", "name", "headline"],
    "description": ["description", "bug_description", "details", "bug description", "body", "issue_description", "comment", "problem_statement"],
    "severity": ["severity", "priority", "bug_severity", "level", "severity_level"],
    "category": ["category", "bug_category", "type", "bug_type", "classification", "issue_type"],
    "affected_module": ["affected_module", "module", "component", "subsystem", "affected module", "area", "service", "system_module"]
}

def is_allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def resolve_column_mapping(header_list: List[str]) -> Dict[str, Optional[str]]:
    """
    Maps user-provided column names to standard schema names using alias lookup.
    """
    clean_headers = {col.strip().lower(): col for col in header_list}
    resolved = {key: None for key in COLUMN_ALIASES}

    for standard_name, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in clean_headers:
                resolved[standard_name] = clean_headers[alias]
                break

    return resolved

def read_csv_with_fallback(file_stream_or_path) -> pd.DataFrame:
    """
    Reads a CSV file trying utf-8, utf-8-sig (Excel BOM), and latin-1.
    """
    encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']
    
    # If bytes or stream
    if hasattr(file_stream_or_path, 'read'):
        raw_bytes = file_stream_or_path.read()
        if hasattr(file_stream_or_path, 'seek'):
            file_stream_or_path.seek(0)
            
        for enc in encodings:
            try:
                text_stream = io.StringIO(raw_bytes.decode(enc))
                df = pd.read_csv(text_stream, dtype=str)
                return df
            except Exception:
                continue
        raise ValueError("Could not decode CSV file using supported encodings (UTF-8, UTF-8-SIG, Latin-1).")
    else:
        # File path
        for enc in encodings:
            try:
                df = pd.read_csv(file_stream_or_path, encoding=enc, dtype=str)
                return df
            except Exception:
                continue
        raise ValueError(f"Could not decode CSV file at {file_stream_or_path} with supported encodings.")

def get_existing_fingerprints() -> set:
    """Fetch SHA-256 fingerprints of existing bug reports in the database."""
    try:
        rows = query_db("SELECT title, description FROM bug_reports")
        fps = set()
        for r in rows:
            fps.add(BugReport.compute_content_hash(r["title"], r["description"]))
        return fps
    except Exception:
        return set()

def ingest_csv_dataset(file_stream_or_path, source_type="csv_upload") -> Dict[str, Any]:
    """
    Parses, validates, and cleans an uploaded CSV dataset of bug reports.
    Identifies valid records, rejection causes per row, and duplicates.
    """
    try:
        df = read_csv_with_fallback(file_stream_or_path)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to parse CSV file: {str(e)}",
            "total_rows": 0,
            "accepted_count": 0,
            "rejected_count": 0,
            "duplicate_count": 0,
            "accepted_records": [],
            "rejected_records": [{"row_number": 0, "reason": f"File parse error: {str(e)}"}],
            "duplicate_records": []
        }

    total_rows = len(df)
    if total_rows == 0:
        return {
            "success": False,
            "error": "The uploaded CSV file contains no data rows.",
            "total_rows": 0,
            "accepted_count": 0,
            "rejected_count": 0,
            "duplicate_count": 0,
            "accepted_records": [],
            "rejected_records": [],
            "duplicate_records": []
        }

    col_map = resolve_column_mapping(list(df.columns))
    
    # Validation: title and/or description must be identifiable
    if not col_map["title"] and not col_map["description"]:
        missing_headers = ", ".join(list(df.columns))
        return {
            "success": False,
            "error": f"Missing required columns. Uploaded columns ({missing_headers}) must contain at least 'title' (or summary) or 'description'.",
            "total_rows": total_rows,
            "accepted_count": 0,
            "rejected_count": total_rows,
            "duplicate_count": 0,
            "accepted_records": [],
            "rejected_records": [{"row_number": 1, "reason": "Missing required 'title' or 'description' columns."}],
            "duplicate_records": []
        }

    existing_hashes = get_existing_fingerprints()
    seen_in_batch = set()

    accepted_records = []
    rejected_records = []
    duplicate_records = []

    for idx, row in df.iterrows():
        row_num = idx + 2  # 1-indexed, accounting for header row
        
        # Extract title and description
        raw_title = str(row[col_map["title"]]).strip() if col_map["title"] and pd.notna(row[col_map["title"]]) else ""
        raw_desc = str(row[col_map["description"]]).strip() if col_map["description"] and pd.notna(row[col_map["description"]]) else ""

        # Validation: Both title and description cannot be empty
        if not raw_title and not raw_desc:
            rejected_records.append({
                "row_number": row_num,
                "reason": "Both title and description fields are empty or null."
            })
            continue

        # If title is missing, fallback to first 60 chars of description
        if not raw_title:
            raw_title = raw_desc[:60] + ("..." if len(raw_desc) > 60 else "")
        # If desc is missing, fallback to title
        if not raw_desc:
            raw_desc = raw_title

        # Check for duplicates
        content_hash = BugReport.compute_content_hash(raw_title, raw_desc)
        if content_hash in existing_hashes or content_hash in seen_in_batch:
            duplicate_records.append({
                "row_number": row_num,
                "title": raw_title[:70],
                "reason": "Duplicate content matching existing report in database or current file."
            })
            continue

        seen_in_batch.add(content_hash)

        # Extract optional fields with sensible defaults
        user_bug_id = str(row[col_map["bug_id"]]).strip() if col_map["bug_id"] and pd.notna(row[col_map["bug_id"]]) else None
        
        raw_sev = str(row[col_map["severity"]]).strip().capitalize() if col_map["severity"] and pd.notna(row[col_map["severity"]]) else None
        sev = raw_sev if raw_sev in VALID_SEVERITIES else None

        raw_cat = str(row[col_map["category"]]).strip() if col_map["category"] and pd.notna(row[col_map["category"]]) else None
        # Normalize category
        cat = None
        if raw_cat:
            for vc in VALID_CATEGORIES:
                if raw_cat.lower() == vc.lower():
                    cat = vc
                    break

        raw_mod = str(row[col_map["affected_module"]]).strip() if col_map["affected_module"] and pd.notna(row[col_map["affected_module"]]) else None
        mod = None
        if raw_mod:
            for vm in VALID_MODULES:
                if raw_mod.lower() == vm.lower():
                    mod = vm
                    break

        combined = combine_bug_text(raw_title, raw_desc)
        cleaned = clean_text_for_ml(combined)

        record = {
            "row_number": row_num,
            "bug_id": user_bug_id,
            "title": raw_title,
            "description": raw_desc,
            "clean_text": cleaned,
            "severity": sev,
            "category": cat,
            "affected_module": mod,
            "source_type": source_type
        }
        accepted_records.append(record)

    return {
        "success": True,
        "total_rows": total_rows,
        "accepted_count": len(accepted_records),
        "rejected_count": len(rejected_records),
        "duplicate_count": len(duplicate_records),
        "accepted_records": accepted_records,
        "rejected_records": rejected_records,
        "duplicate_records": duplicate_records,
        "column_mapping": col_map
    }
