"""Pydantic schemas."""
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    FILE = "file"
    GIT = "git"
    URL = "url"


class Vulnerability(BaseModel):
    id: str
    rule_id: str
    severity: Severity
    title: str
    description: str
    scanner: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None


class CodeMetric(BaseModel):
    file_path: str
    language: str
    lines_of_code: int
    complexity: float = 0.0


class DependencyIssue(BaseModel):
    package: str
    version: str
    vulnerability_id: str
    severity: Severity
    description: str
    fix_version: Optional[str] = None


class URLScanResult(BaseModel):
    url: str
    status_code: int
    final_url: str
    headers: dict[str, str] = {}
    missing_security_headers: list[str] = []
    insecure_cookies: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    technologies: list[str] = []
    exposed_paths: list[dict[str, Any]] = []
    ssl_issues: list[str] = []
    reflected_xss: list[str] = []
    open_redirects: list[str] = []


class ScanResult(BaseModel):
    scan_id: str
    scan_type: ScanType
    status: ScanStatus
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    vulnerabilities: list[Vulnerability] = []
    metrics: dict[str, Any] = {}
    dependencies: list[DependencyIssue] = []
    code_metrics: list[CodeMetric] = []
    url_result: Optional[URLScanResult] = None
    security_score: float = 100.0
    quality_score: float = 100.0
    error: Optional[str] = None


class UploadResponse(BaseModel):
    scan_id: str
    workspace_id: str
    message: str
    files_count: int = 0


class URLScanRequest(BaseModel):
    url: str
    deep_scan: bool = True


class GitScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"


class ProgressMessage(BaseModel):
    type: str  # log | progress | status
    scan_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    message: Optional[str] = None
    level: Optional[str] = None
    progress: Optional[float] = None
    step: Optional[str] = None
    status: Optional[str] = None
