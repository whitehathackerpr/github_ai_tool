from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime

# Request Models

class RepositoryRequest(BaseModel):
    """Request model for repository analysis."""
    repo_url: str
    branch: Optional[str] = "main"
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo",
                "branch": "main"
            }
        }

class CodeQualityRequest(BaseModel):
    """Request model for code quality analysis."""
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "def add(a, b):\n    return a + b",
                "language": "python"
            }
        }

class SecurityScanRequest(BaseModel):
    """Request model for security scanning."""
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    """Request model for dependency analysis."""
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    """Request model for template generation."""
    repo_name: str
    repo_description: str
    template_type: str = Field(
        default="pr",
        description="Type of template to generate (pr, issue, contributing)"
    )
    issue_type: Optional[str] = Field(
        default="bug",
        description="Type of issue template (bug, feature)"
    )
    repo_type: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "repo_name": "awesome-project",
                "repo_description": "A Python library for machine learning",
                "template_type": "pr",
                "repo_type": "Python library"
            }
        }

# Authentication Models

class TokenRequest(BaseModel):
    """Request model for token authentication."""
    grant_type: str = "password"
    username: str
    password: str
    
    class Config:
        schema_extra = {
            "example": {
                "username": "github_username",
                "password": "password"
            }
        }

class TokenResponse(BaseModel):
    """Response model for token authentication."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshTokenRequest(BaseModel):
    """Request model for refreshing an access token."""
    refresh_token: str
    
    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }

class UserInfo(BaseModel):
    """Model containing user information."""
    username: str
    scopes: List[str] = []
    github_token: Optional[str] = None

# Response Models

class CodeIssue(BaseModel):
    """Model representing a code quality issue."""
    line: int
    column: Optional[int] = None
    message: str
    rule: Optional[str] = None
    severity: str = "medium"

class CodeAnalysisResponse(BaseModel):
    """Response model for code analysis."""
    suggestions: List[CodeIssue]
    warnings: List[CodeIssue]
    metrics: Dict[str, Any]
    summary: str

class Vulnerability(BaseModel):
    """Model representing a security vulnerability."""
    line: Optional[int] = None
    severity: str
    message: str
    code: Optional[str] = None
    confidence: Optional[str] = None
    recommendation: Optional[str] = None

class SecurityScanResponse(BaseModel):
    """Response model for security scanning."""
    vulnerabilities: List[Vulnerability]
    severity_counts: Dict[str, int]
    scan_coverage: float
    recommendations: List[str]

class Dependency(BaseModel):
    """Model representing a project dependency."""
    name: str
    current_version: str
    latest_version: Optional[str] = None
    is_outdated: bool = False
    is_vulnerable: bool = False
    licenses: List[str] = []
    
class DependencyAnalysisResponse(BaseModel):
    """Response model for dependency analysis."""
    dependencies: List[Dependency]
    outdated_count: int
    vulnerable_count: int
    recommendation_count: int
    upgrade_urgency: str  # "low", "medium", "high"
    recommendations: List[str]

class TemplateGenerationResponse(BaseModel):
    """Response model for template generation."""
    template: str
    file_path: str
    metadata: Dict[str, Any]

# Health Check Models

class ComponentHealth(BaseModel):
    """Model representing the health of a system component."""
    status: str  # "healthy", "unhealthy", "degraded", "unknown"
    message: str
    details: Optional[Dict[str, Any]] = None

class HealthResponse(BaseModel):
    """Response model for health check endpoint."""
    status: str  # "healthy", "unhealthy", "degraded"
    timestamp: str
    version: str
    services: Dict[str, ComponentHealth]
    system_metrics: Optional[Dict[str, float]] = None

# Error Response Models

class ErrorDetail(BaseModel):
    """Detailed error information."""
    code: str
    message: str
    param: Optional[str] = None
    
class ErrorResponse(BaseModel):
    """Standard error response model."""
    error: str
    message: str
    details: Optional[List[ErrorDetail]] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    path: Optional[str] = None
    request_id: Optional[str] = None

