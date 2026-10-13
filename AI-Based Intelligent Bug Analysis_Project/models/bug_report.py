import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

VALID_SEVERITIES = ["Low", "Medium", "High", "Critical"]
VALID_CATEGORIES = [
    "Logic Error", 
    "UI Issue", 
    "Performance Issue", 
    "Network Error", 
    "Security Issue", 
    "Other"
]
VALID_MODULES = [
    "Authentication", 
    "Payment", 
    "Dashboard", 
    "Registration", 
    "API", 
    "Database", 
    "Other"
]
VALID_TRIAGE_STATUSES = [
    "Pending Review", 
    "Investigating", 
    "Confirmed Vulnerability", 
    "Dismissed"
]

@dataclass
class BugReport:
    title: str
    description: str
    bug_id: Optional[str] = None
    clean_text: Optional[str] = None
    severity: str = "Medium"
    category: str = "Other"
    affected_module: str = "Other"
    is_security_related: int = 0
    security_indicators: Optional[str] = "[]"
    risk_score: int = 0
    risk_level: str = "Low"
    triage_status: str = "Pending Review"
    confidence_severity: float = 0.0
    confidence_category: float = 0.0
    confidence_module: float = 0.0
    explanation: Optional[str] = ""
    recommended_action: Optional[str] = ""
    source_type: str = "manual"
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    id: Optional[int] = None

    def __post_init__(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now
        if not self.bug_id:
            # Generate deterministic short ID hash
            h = hashlib.sha256(f"{self.title}{self.description}{self.created_at}".encode("utf-8")).hexdigest()[:8]
            self.bug_id = f"BUG-{h.upper()}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if isinstance(data.get("security_indicators"), str):
            try:
                data["security_indicators_parsed"] = json.loads(data["security_indicators"])
            except Exception:
                data["security_indicators_parsed"] = []
        return data

    @staticmethod
    def compute_content_hash(title: str, description: str) -> str:
        """Create SHA-256 fingerprint for duplicate detection."""
        norm_text = f"{title.strip().lower()}||{description.strip().lower()}"
        return hashlib.sha256(norm_text.encode("utf-8")).hexdigest()
