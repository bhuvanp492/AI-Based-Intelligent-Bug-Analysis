import sqlite3
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from flask import g, current_app

def get_db_path(custom_path=None):
    if custom_path:
        return custom_path
    if current_app:
        return current_app.config.get("DATABASE_PATH")
    return os.environ.get("DATABASE_PATH", "instance/application.db")

def get_db(db_path=None):
    target_path = get_db_path(db_path)
    
    # In Flask request context, reuse connection on g
    if current_app:
        if 'db' not in g:
            g.db = sqlite3.connect(target_path, detect_types=sqlite3.PARSE_DECLTYPES)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON;")
        return g.db

    conn = sqlite3.connect(target_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(db_path=None):
    """Initialize database tables and indexes."""
    target_path = get_db_path(db_path)
    
    # Ensure directory exists if not in-memory
    if target_path != ":memory:":
        parent_dir = Path(target_path).parent
        parent_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(target_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS bug_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bug_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        clean_text TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        affected_module TEXT NOT NULL,
        is_security_related INTEGER DEFAULT 0,
        security_indicators TEXT,
        risk_score INTEGER DEFAULT 0,
        risk_level TEXT DEFAULT 'Low',
        triage_status TEXT DEFAULT 'Pending Review',
        confidence_severity REAL DEFAULT 0.0,
        confidence_category REAL DEFAULT 0.0,
        confidence_module REAL DEFAULT 0.0,
        explanation TEXT,
        recommended_action TEXT,
        source_type TEXT DEFAULT 'manual',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_bug_reports_severity ON bug_reports(severity);
    CREATE INDEX IF NOT EXISTS idx_bug_reports_category ON bug_reports(category);
    CREATE INDEX IF NOT EXISTS idx_bug_reports_risk_level ON bug_reports(risk_level);
    CREATE INDEX IF NOT EXISTS idx_bug_reports_is_security ON bug_reports(is_security_related);
    CREATE INDEX IF NOT EXISTS idx_bug_reports_triage ON bug_reports(triage_status);
    CREATE INDEX IF NOT EXISTS idx_bug_reports_created ON bug_reports(created_at);

    CREATE TABLE IF NOT EXISTS model_training_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_version TEXT NOT NULL,
        dataset_name TEXT NOT NULL,
        total_samples INTEGER NOT NULL,
        train_samples INTEGER NOT NULL,
        test_samples INTEGER NOT NULL,
        algorithm TEXT NOT NULL,
        severity_metrics TEXT,
        category_metrics TEXT,
        module_metrics TEXT,
        comparison_metrics TEXT,
        trained_at TEXT NOT NULL,
        status TEXT DEFAULT 'success'
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        ip_address TEXT,
        status TEXT DEFAULT 'SUCCESS',
        metadata TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs(event_type);

    CREATE TABLE IF NOT EXISTS ingestion_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        filename TEXT NOT NULL,
        total_rows INTEGER NOT NULL,
        accepted_count INTEGER NOT NULL,
        rejected_count INTEGER NOT NULL,
        duplicate_count INTEGER NOT NULL,
        details_json TEXT
    );
    """)

    conn.commit()
    conn.close()

def query_db(query, args=(), one=False, db_path=None):
    """Execute a parameterized query and return rows as dictionaries."""
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    if not current_app:
        conn.close()
    if rv:
        res = [dict(row) for row in rv]
        return res[0] if one else res
    return None if one else []

def execute_db(query, args=(), db_path=None):
    """Execute parameterized INSERT/UPDATE/DELETE statement."""
    conn = get_db(db_path)
    cur = conn.cursor()
    cur.execute(query, args)
    last_id = cur.lastrowid
    conn.commit()
    cur.close()
    if not current_app:
        conn.close()
    return last_id

def log_audit_event(event_type, description, ip_address="127.0.0.1", status="SUCCESS", metadata=None, db_path=None):
    """Record an audit trail event securely."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    meta_json = json.dumps(metadata) if metadata else "{}"
    query = """
    INSERT INTO audit_logs (timestamp, event_type, description, ip_address, status, metadata)
    VALUES (?, ?, ?, ?, ?, ?)
    """
    try:
        execute_db(query, (now_str, event_type, description, ip_address, status, meta_json), db_path=db_path)
    except Exception as e:
        # Fallback print to prevent crash if logging fails
        print(f"[AUDIT LOG ERROR] Failed to write audit event: {e}")
