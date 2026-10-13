import pytest
from app import create_app
from config import TestingConfig
from models.database import init_db, query_db

import os
from pathlib import Path

@pytest.fixture(scope="session")
def app():
    db_file = Path(TestingConfig.DATABASE_PATH)
    if db_file.exists():
        try:
            os.remove(db_file)
        except Exception:
            pass
    test_app = create_app(TestingConfig)
    with test_app.app_context():
        init_db(test_app.config["DATABASE_PATH"])
    yield test_app
    if db_file.exists():
        try:
            os.remove(db_file)
        except Exception:
            pass

@pytest.fixture
def client(app):
    return app.test_client()

def test_dashboard_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Bug Analysis" in response.data

def test_bugs_route(client):
    response = client.get("/bugs")
    assert response.status_code == 200
    assert b"Bug Reports Registry" in response.data

def test_analyse_get_and_post(client):
    # GET form
    get_res = client.get("/bugs/analyse")
    assert get_res.status_code == 200
    assert b"Bug Title" in get_res.data

    # POST submission
    post_res = client.post("/bugs/analyse", data={
        "title": "SQL Injection in Search Box",
        "description": "User input ' OR '1'='1 injected into raw SQL query dumping all accounts.",
        "module_hint": "Database"
    }, follow_redirects=True)
    assert post_res.status_code == 200
    assert b"SQL Injection in Search Box" in post_res.data

def test_security_dashboard_route(client):
    response = client.get("/security")
    assert response.status_code == 200
    assert b"Security Vulnerability Analysis" in response.data

def test_similarity_tool_route(client):
    response = client.get("/similarity")
    assert response.status_code == 200
    assert b"Similar Bug Report Retrieval" in response.data

def test_evaluation_route(client):
    response = client.get("/evaluation")
    assert response.status_code == 200
    assert b"Machine Learning Model Evaluation" in response.data

def test_audit_logs_route(client):
    response = client.get("/audit")
    assert response.status_code == 200
    assert b"Audit Logs" in response.data

def test_about_page_route(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"System Documentation" in response.data

def test_csv_export_route(client):
    response = client.get("/bugs/export/csv")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/csv")
    assert b"Bug ID" in response.data

def test_pdf_export_route(client):
    response = client.get("/bugs/export/pdf")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert response.data.startswith(b"%PDF")
