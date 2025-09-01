from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime

class AnalysisResponse(BaseModel):
    app_name: str
    package_name: str
    version_name: str
    version_code: Optional[int] = 0
    min_sdk: Optional[int] = 0
    target_sdk: Optional[int] = 0
    permissions: List[str]
    dangerous_permissions: Optional[List[str]] = []
    risk_score: float
    verdict: str
    top_features: List[Dict[str, Any]]
    certificate_info: Dict[str, Any]
    suspicious_strings: List[str]
    file_size_human: Optional[str] = "Unknown"
    install_location: Optional[str] = "auto"
    allows_backup: Optional[bool] = True
    is_debuggable: Optional[bool] = False
    component_summary: Optional[Dict[str, int]] = {}
    activities: Optional[List[str]] = []
    services: Optional[List[str]] = []

class ComparisonResponse(BaseModel):
    apk1: Dict[str, Any]
    apk2: Dict[str, Any]
    permission_differences: List[str]
    permissions_only_in_apk1: Optional[List[str]] = []
    dangerous_permission_differences: Optional[List[str]] = []
    risk_score_difference: float
    similarity_score: Optional[float] = 0.0
    version_comparison: Optional[Dict[str, Any]] = {}
    sdk_comparison: Optional[Dict[str, Any]] = {}

class HistoryResponse(BaseModel):
    id: int
    file_hash: str
    timestamp: datetime
    package_name: str
    risk_score: float
    verdict: str
