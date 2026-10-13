import re
import html
from typing import Optional

def normalize_whitespace(text: str) -> str:
    """Collapses multiple spaces, tabs, and newlines into single spaces."""
    if not text:
        return ""
    # Unescape HTML entities if any were passed in raw form (e.g. &lt; -> <)
    text = html.unescape(text)
    # Replace carriage returns and excessive whitespace
    return re.sub(r'\s+', ' ', text).strip()

def clean_text_for_ml(text: Optional[str]) -> str:
    """
    Cleans raw bug report text for machine learning features while strictly
    preserving critical security indicators, technical terms, and code snippets.
    
    Security terms preserved:
    - SQL constructs: SELECT, UNION, WHERE, OR 1=1, DROP, NULL, SLEEP
    - Web / XSS tokens: <script>, onerror, alert, document.cookie, iframe
    - Path traversal: ../, ..\\, /etc/passwd, boot.ini
    - Auth & access: jwt, bearer, authorization, unauthorized, 401, 403, idor, bypass
    """
    if text is None:
        return ""
    
    if not isinstance(text, str):
        text = str(text)

    # Whitespace cleanup
    text = normalize_whitespace(text)
    
    if not text:
        return ""

    # Convert to lowercase for uniform TF-IDF matching
    text_lower = text.lower()

    # Remove non-printable control characters, but keep technical punctuation like /, \, <, >, =, ', ", _, -
    text_cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' ', text_lower)
    
    # Strip non-informative repeated symbols (e.g. "!!!!!!!" -> "!")
    text_cleaned = re.sub(r'([!?.~_=-])\1{2,}', r'\1', text_cleaned)
    
    # Final whitespace trim
    return normalize_whitespace(text_cleaned)

def combine_bug_text(title: Optional[str], description: Optional[str]) -> str:
    """
    Combines bug title and description into a single cohesive representation
    for NLP feature extraction.
    """
    clean_title = (title or "").strip()
    clean_desc = (description or "").strip()
    
    if clean_title and clean_desc:
        return f"{clean_title}. {clean_desc}"
    elif clean_title:
        return clean_title
    elif clean_desc:
        return clean_desc
    return ""
