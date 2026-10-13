# AI-Based Intelligent Bug Analysis and Security Risk Prioritization System

**Final-Year Computer Science and Engineering (CSE) Capstone Project**  
*Project Category:* Data Engineering &bull; Artificial Intelligence Engineering &bull; Security Engineering &bull; Cloud Engineering (Deployment Readiness)

---

## 1. Project Abstract & Objectives

Software development teams receive hundreds of raw defect tickets weekly. Manually triaging each bug report to assess severity, identify root categories, assign software components, and isolate security vulnerabilities requires substantial cognitive effort.

The **AI-Based Intelligent Bug Analysis and Security Risk Prioritization System** automates this triage workflow:
1. **How severe is this bug likely to be?** &rarr; Multi-class ML model predicts severity (`Low`, `Medium`, `High`, `Critical`) with probability confidence.
2. **What category of bug does it belong to?** &rarr; Multi-class NLP classifier determines category (`Logic Error`, `UI Issue`, `Performance Issue`, `Network Error`, `Security Issue`, `Other`).
3. **Which software module is likely affected?** &rarr; Supervised classifier maps the report to components (`Authentication`, `Payment`, `Dashboard`, `Registration`, `API`, `Database`, `Other`).
4. **Does the report contain indicators of a possible security vulnerability?** &rarr; Hybrid engine combines ML predictions with 9 rule-based Common Weakness Enumeration (CWE) regex signature detectors and extracts contextual evidence snippets.
5. **How urgently should a developer review it?** &rarr; A documented, deterministic 0–100 Security Risk Prioritization Score ranks urgent remediation tasks.
6. **Why did the system assign this prediction or risk level?** &rarr; Explainability engine displays top contributing vocabulary features and itemized scoring breakdowns.
7. **Are there similar existing bugs?** &rarr; TF-IDF cosine similarity search retrieves related and duplicate reports.

> **Triage Policy Notice:** The system performs automated preliminary screening and prioritization. A suspected vulnerability is never marked as a confirmed exploit without human developer verification.

---

## 2. Architecture & Modular Structure

```
AI-Based Intelligent Bug Analysis_Project/
├── app.py                      # Flask Application Factory & CSRF Middleware
├── config.py                   # Configuration classes (Dev, Prod, Testing)
├── wsgi.py                     # WSGI Production Entry Point
├── requirements.txt            # Python dependencies
├── .env.example                # Sample environment variables
├── .gitignore                  # Git ignore rules
├── README.md                   # System documentation
├── models/
│   ├── database.py             # SQLite manager, parameterized queries & audit trail
│   └── bug_report.py           # BugReport dataclass & duplicate fingerprinting
├── services/
│   ├── preprocessing.py        # Text normalization & security token preservation
│   ├── data_ingestion.py       # CSV parser, encoding fallback & validation
│   ├── model_training.py       # Supervised ML training, metrics & joblib serialization
│   ├── prediction.py           # Multi-target ML inference, confidences & explanations
│   ├── security_analysis.py    # 9-rule CWE security signature scanner
│   ├── risk_scoring.py         # Documented 0-100 risk prioritization algorithm
│   ├── similarity.py           # TF-IDF cosine similarity search engine
│   └── report_export.py        # CSV & ReportLab PDF executive export
├── routes/
│   ├── dashboard.py            # Overview telemetry & Chart.js distributions
│   ├── bugs.py                 # Bug list, filters, pagination, detail & triage
│   ├── datasets.py             # CSV upload, validation report & sample loaders
│   ├── security.py             # Security Operations Center (SOC) triage view
│   ├── similarity.py           # Interactive similarity search interface
│   ├── evaluation.py           # ML test evaluation, confusion matrices & retrain
│   ├── audit.py                # System governance audit log viewer
│   └── about.py                # Architecture & methodology documentation
├── templates/                  # Professional, human-crafted HTML5 templates
│   ├── base.html               # Shared layout, sidebar & light/dark theme switch
│   ├── dashboard.html          # Operational dashboard & charts
│   ├── bugs.html               # Searchable bug registry with pagination
│   ├── bug_detail.html         # Full investigation view with risk meter & evidence
│   ├── analyse.html            # Manual bug submission with 1-click presets
│   ├── upload.html             # Dataset upload with validation reports
│   ├── security.html           # Security triage queue & CWE catalogs
│   ├── similarity.html         # Cosine similarity grouping tool
│   ├── evaluation.html         # ML metrics, confusion matrix & algorithm comparison
│   ├── audit.html              # Governance audit trail table
│   ├── about.html              # System architecture documentation
│   └── error.html              # Secure user-friendly error views
├── static/
│   ├── css/
│   │   └── style.css           # Professional developer design system (Light & Dark)
│   └── js/
│       ├── app.js              # Theme manager (localStorage persistence) & UI events
│       └── charts.js           # Theme-aware Chart.js integration
├── data/
│   ├── sample_bug_reports.csv   # 25 realistic demonstration bug reports
│   └── sample_training_data.csv # 100 labelled synthetic training records
├── instance/                   # Local SQLite storage (application.db)
├── trained_models/             # Serialized versioned ML models (.joblib)
└── tests/                      # Automated test suite (25 test cases)
```

---

## 3. Technology Stack

- **Backend:** Python 3.12, Flask, Werkzeug, WSGI.
- **Data Engineering:** Pandas, NumPy, SQLite, Parameterized SQL Queries.
- **Machine Learning & NLP:** scikit-learn, TF-IDF Vectorization, Multinomial Naive Bayes, Logistic Regression comparison, joblib serialization, Cosine Similarity.
- **Security Engineering:** 9-Rule CWE Signature Engine, Anti-CSRF Protection, Input Sanitization, Path Traversal Mitigation, Audit Logging, Human-in-the-Loop Triage Workflow.
- **Reporting & Data Viz:** Chart.js (with dynamic dark/light mode synchronization), CSV Exporter, ReportLab PDF Generation.

---

## 4. Engineering Module Details

### Module 1: Data Engineering
- **Encoding Resiliency:** Transparently decodes UTF-8, UTF-8 with BOM (Microsoft Excel), and Latin-1.
- **Flexible Column Aliases:** Recognizes variations including `Summary` &rarr; `title`, `Details` &rarr; `description`, `Priority` &rarr; `severity`, `Component` &rarr; `affected_module`.
- **Validation Pipeline:** Enforces non-empty title/description, isolates malformed rows, and generates itemized rejection diagnostics.
- **Duplicate Detection:** Generates SHA-256 content fingerprints on normalized `title || description` to flag duplicates.
- **Security Token Preservation:** Safe cleaning preserves SQL keywords (`SELECT`, `OR 1=1`), XSS scripts (`<script>`, `document.cookie`), traversal paths (`../`, `/etc/passwd`), and auth tokens (`jwt`, `bearer`).

### Module 2: AI Engineering
- **Strict Anti-Leakage Split:** 80% train / 20% test split with TF-IDF vectorizer fitted exclusively on training data.
- **Multi-Target Classification:**
  1. Severity: `Low`, `Medium`, `High`, `Critical`.
  2. Bug Category: `Logic Error`, `UI Issue`, `Performance Issue`, `Network Error`, `Security Issue`, `Other`.
  3. Affected Module: `Authentication`, `Payment`, `Dashboard`, `Registration`, `API`, `Database`, `Other`.
- **Algorithm Comparison:** Evaluates Multinomial Naive Bayes against Logistic Regression side-by-side on identical test splits.
- **Full Metrics Reporting:** Precision (macro), Recall (macro), Macro F1, Accuracy, and multi-class Confusion Matrices.
- **Feature Attribution:** Calculates TF-IDF weights multiplied by model feature log-probabilities to extract top contributing vocabulary words.

### Module 3: Security Engineering
#### 9 Implemented Security Vulnerability Engines:
1. **SQL Injection (SQLi) — CWE-89** (`+25 pts`): Detects UNION SELECT, OR 1=1, quote escaping, unparameterized raw SQL.
2. **Cross-Site Scripting (XSS) — CWE-79** (`+20 pts`): Detects unescaped `<script>`, `onerror=`, `alert()`, `document.cookie`.
3. **Authentication & Credential Weakness — CWE-287** (`+25 pts`): Detects hardcoded secrets, OTP bypass, brute-force lack of rate limits.
4. **Broken Access Control & IDOR — CWE-639** (`+25 pts`): Detects unauthorized user ID tampering, privilege escalation.
5. **Insecure File Upload — CWE-434** (`+25 pts`): Detects unvalidated file extensions (`.php`, `.exe`), webshells.
6. **Directory / Path Traversal — CWE-22** (`+25 pts`): Detects `../`, `..\`, `/etc/passwd`, arbitrary file download.
7. **Sensitive Information Exposure — CWE-200** (`+15 pts`): Detects leaked API keys (`sk_live_`, AWS keys), cleartext passwords in logs.
8. **Command Injection / RCE — CWE-78** (`+30 pts`): Detects unsanitized `subprocess.Popen(shell=True)`, `system()`, `eval()`.
9. **CSRF / Session Management Weakness — CWE-352** (`+20 pts`): Detects missing CSRF tokens, lack of HttpOnly/Secure cookie flags.

#### Deterministic 0–100 Risk Prioritization Formula:
$$\text{Risk Score} = \min(100, \text{BaseSeverity} + \text{MLSecurityScore} + \text{RuleIndicatorsScore} + \text{ModuleCriticality})$$

- **Base Severity (Max 40 pts):** Critical = 40, High = 25, Medium = 15, Low = 5.
- **ML Security Probability (Max 25 pts):** If category is `Security Issue`: $\text{round}(\text{Probability} \times 25)$, else 0.
- **Rule-Based CWE Indicators (Max 25 pts):** Sum of weights from detected vulnerability rules (clamped to 25 max).
- **Module Impact Factor (Max 10 pts):** Payment, Authentication, Database = 10; API, Registration = 5; Dashboard, UI, Other = 0.
- **Risk Bands:** Low (0–25), Medium (26–55), High (56–80), Critical (81–100).

---

## 5. Getting Started (Installation & Execution)

### Prerequisites
- Python 3.10+ (Tested on Python 3.12)
- pip package manager

### Step 1: Clone or Navigate to Project Directory
```powershell
cd "d:\AI-Based Intelligent Bug Analysis\AI-Based Intelligent Bug Analysis_Project"
```

### Step 2: Install Required Dependencies
```powershell
py -m pip install -r requirements.txt
```

### Step 3: Run Automated Verification Tests
```powershell
py -m pytest tests/ -v
```
*Expected Result:* All 25 test cases pass successfully.

### Step 4: Start the Development Server
```powershell
py app.py
```
Open your web browser and navigate to:
**http://127.0.0.1:5000**

---

## 6. Demonstration Workflows

### Workflow A: First-Time Use & Demo Data Initialization
1. Launch the application. The system initializes the SQLite database (`instance/application.db`) and automatically trains baseline models on `data/sample_training_data.csv`.
2. On the **Overview** dashboard, if empty, click **Load Sample Bug Reports (25 Issues)** to populate demonstration data.
3. Observe real distribution charts (Severity Doughnut and Bug Category Bar) rendered dynamically via Chart.js.

### Workflow B: Manual Bug Analysis
1. Navigate to **Analyse Bug** in the sidebar.
2. Select any **Quick Demo Preset** (e.g. *SQLi: Raw query parameter injection* or *XSS: Unescaped script payload*).
3. Click **Analyse & Prioritize Bug**.
4. Review:
   - Predicted Severity with model confidence.
   - Natural language explanation and keyword attribution.
   - Detected CWE indicators with contextual evidence snippets.
   - Itemized formula score breakdown.
   - Top similar bugs retrieved via TF-IDF cosine similarity.

### Workflow C: CSV Dataset Batch Ingestion
1. Navigate to **Upload Dataset**.
2. Select **Batch Bug Ingestion** mode.
3. Choose `data/sample_bug_reports.csv` or upload a custom CSV.
4. Click **Upload & Execute Pipeline**.
5. Inspect the validation report: Total rows parsed, accepted count, rejected count with exact row errors, and duplicate matches.

### Workflow D: Model Retraining & Evaluation
1. Navigate to **Model Evaluation**.
2. Inspect validation metrics for Severity, Category, and Module models.
3. Review the **Comparative Analysis** table contrasting Multinomial Naive Bayes and Logistic Regression.
4. Inspect the multi-class Confusion Matrix on the test split.
5. Click **Retrain Pipeline** to execute an on-demand training cycle and update serialized joblib artifacts.

### Workflow E: Security Operations Triage
1. Navigate to **Security Analysis**.
2. Review the prioritized triage queue sorted by risk score descending.
3. Click **Triage** on a critical vulnerability.
4. Update the review status (`Investigating`, `Confirmed Vulnerability`, or `Dismissed`).
5. Open **Audit Logs** to observe the logged event with timestamp, client IP, and state transition.

### Workflow F: Light / Dark Theme Switching
1. Click the **Theme Toggle** button in the top navigation bar.
2. The interface immediately switches between the clean developer Light theme and the muted dark surface theme.
3. Note that Chart.js fonts and gridlines update in real-time.
4. Refresh the page: your preference persists via `localStorage`.

### Workflow G: Executive Export
1. On **Bug Reports**, apply any filter (e.g. Severity = Critical).
2. Click **Export CSV** to download a sanitized CSV file.
3. Click **Export PDF** to generate an executive summary PDF with formatted KPI tables and risk breakdowns via ReportLab.

---

## 7. Cloud Deployment Preparation (Module 4)

The application is structured for production deployment without code changes:
- `wsgi.py`: Production WSGI entry point.
- `config.py`: Enforces `DEBUG=False` and production cookie settings when `FLASK_ENV=production`.
- Database & upload paths are configurable via environment variables.

### Running with Production WSGI Server

#### On Windows (using Waitress):
```powershell
py -m pip install waitress
waitress-serve --port=8000 wsgi:app
```

#### On Linux / Cloud VMs (using Gunicorn):
```bash
pip install gunicorn
gunicorn --workers 4 --bind 0.0.0.0:8000 wsgi:app
```

### Docker Deployment Guide

Create a `Dockerfile`:
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn
COPY . .
ENV FLASK_ENV=production
EXPOSE 8000
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:8000", "wsgi:app"]
```

### Persistent Storage Considerations
When deploying to cloud platforms (Render, Railway, Fly.io, AWS EC2):
- Mount a persistent volume to `/app/instance` so `application.db` and uploaded files persist across container restarts.
- Set `SECRET_KEY` in platform environment variables.

---

## 8. Test Suite Summary

Automated tests in `tests/` verify end-to-end correctness:
- `test_preprocessing.py`: Whitespace normalization, text combination, security token preservation.
- `test_ingestion.py`: Extension validation, alias mapping, encoding fallback, batch duplicate detection.
- `test_security_rules.py`: SQLi, XSS, Path traversal detection, 0–100 score bounding.
- `test_ml_pipeline.py`: Supervised training, evaluation metric computation, Naive Bayes prediction confidences, explanations.
- `test_routes.py`: Flask endpoints, manual bug entry, security dashboard, similarity tool, audit trail, CSV and PDF export.

```
============================= 25 passed in 2.07s ==============================
```

---

## 9. Academic Project Credits

- **Project Title:** AI-Based Intelligent Bug Analysis and Security Risk Prioritization System
- **Domain:** Software Engineering, Natural Language Processing, Application Security
- **Target Audience:** Final-Year Computer Science Engineering Review Board & Industry Practitioners
