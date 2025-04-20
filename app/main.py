"""
GitHub AI Tool - Main FastAPI Application
"""
import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
import logging
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import loggingslowapi
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

#----------------------------------------
# App Configuration and Initialization
#----------------------------------------

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Configure logger
logger = logging.getLogger(__name__)
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

#----------------------------------------
# Middleware
#----------------------------------------

# Import custom middleware
from app.middleware.auth import JWTAuthMiddleware, RateLimitByUserMiddleware
from app.middleware.security import SecurityHeadersMiddleware, RequestLoggingMiddleware, get_cors_middleware

# Add middleware in reverse order (last added = first executed)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Add request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# Configure CORS
app.add_middleware(
    get_cors_middleware(
        allowed_origins=getattr(settings, 'ALLOWED_ORIGINS', None)
    )
)

# Add rate limiting middleware if Redis is configured
if redis_instance:
    app.add_middleware(RateLimitByUserMiddleware, redis_client=redis_instance)

# Add authentication middleware
app.add_middleware(JWTAuthMiddleware)
app.add_middleware(SlowAPIMiddleware)

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# Include health router
app.include_router(health.router, prefix="")

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#----------------------------------------
# Authentication Utilities
#----------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

#----------------------------------------
# Models
#----------------------------------------

class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

#----------------------------------------
# Routes
#----------------------------------------

# Root endpoint
@app.get("/")
async def root():
    """Main landing page"""
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

#----- Authentication Routes -----

@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

#----- Repository Analysis Routes -----

@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

#----- Code Quality Routes -----

@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

#----- Security Scanner Routes -----

@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_

"""
GitHub AI Tool - Main FastAPI Application
"""
import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

#----------------------------------------
# App Configuration and Initialization
#----------------------------------------

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

#----------------------------------------
# Middleware
#----------------------------------------

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#----------------------------------------
# Authentication Utilities
#----------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

#----------------------------------------
# Models
#----------------------------------------

class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

#----------------------------------------
# Routes
#----------------------------------------

# Root endpoint
@app.get("/")
async def root():
    """Main landing page"""
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

#----- Authentication Routes -----

@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

#----- Repository Analysis Routes -----

@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

#----- Code Quality Routes -----

@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

#----- Security Scanner Routes -----

@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_

import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

#----------------------------------------
# App Configuration and Initialization
#----------------------------------------

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

#----------------------------------------
# Middleware
#----------------------------------------

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#----------------------------------------
# Authentication Utilities
#----------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

#----------------------------------------
# Models
#----------------------------------------

class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

#----------------------------------------
# Routes
#----------------------------------------

# Root endpoint
@app.get("/")
async def root():
    """Main landing page"""
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

#----- Authentication Routes -----

@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

#----- Repository Analysis Routes -----

@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

#----- Code Quality Routes -----

@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

#----- Security Scanner Routes -----

@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_request.language.lower() in ["javascript", "js"]:
                results = await security_scanner.scan_javascript_code(scan

import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

#----------------------------------------
# App Configuration and Initialization
#----------------------------------------

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

#----------------------------------------
# Middleware
#----------------------------------------

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#----------------------------------------
# Authentication Utilities
#----------------------------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

#----------------------------------------
# Models
#----------------------------------------

class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

#----------------------------------------
# Routes
#----------------------------------------

# Root endpoint
@app.get("/")
async def root():
    """Main landing page"""
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

#----- Authentication Routes -----

@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

#----- Repository Analysis Routes -----

@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

#----- Code Quality Routes -----

@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

#----- Security Scanner Routes -----

@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_request.language.lower() in ["javascript", "js"]:
                results = await security_scanner.scan

import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

# ----- Configuration -----

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

# ----- Middleware -----

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ----- Utilities -----

# Auth utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

# ----- Models -----

class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

# ----- Routes -----

# Root endpoint
@app.get("/")
async def root():
    """Main landing page"""
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

# Authentication routes
@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

# Repository Analysis Routes
@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

# Code Quality Routes
@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

# Security Scanner Routes
@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_request.language.lower() in ["javascript", "js"]:
                results = await security_scanner.scan_javascript_code(scan_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=

import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

# ----- Configuration -----

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

# ----- Middleware -----

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ----- Utilities -----

# Auth utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

# ----- Models -----

class RepositoryRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = "main"
    
    class Config:
        schema_extra = {
            "example": {
                "repo_

# ----- Routes -----

# Root endpoint
@app.get("/")
async def root():
    """Main landing page"""
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

# Authentication routes
@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

# Repository Analysis Routes
@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

# Code Quality Routes
@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

# Security Scanner Routes
@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_request.language.lower() in ["javascript", "js"]:
                results = await security_scanner.scan_javascript_code(scan_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {scan_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="

import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

# Auth utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

# Pydantic models
class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

# Routes
@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

# Authentication routes
@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

# Repository Analysis Routes
@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

# Code Quality Routes
@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

# Security Scanner Routes
@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_request.language.lower() in ["javascript", "js"]:
                results = await security_scanner.scan_javascript_code(scan_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {scan_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        

import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

# Initialize Redis connection for caching
redis_instance = None
try:
    if settings.REDIS_URL:
        redis_instance = redis.from_url(settings.REDIS_URL)
    else:
        redis_instance = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            decode_responses=True
        )
    logger.info("Redis connection initialized")
except Exception as e:
    logger.warning(f"Failed to initialize Redis connection: {str(e)}")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
        
        cache_key = f"cache:{request.url.path}:{request.query_params}"
        
        try:
            # Try to get cached response
            cached = await redis_instance.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {cache_key}")
                cached_data = json.loads(cached)
                return JSONResponse(content=cached_data)
            
            # If no cache hit, process the request
            response = await call_next(request)
            
            # Cache successful responses (status code 200)
            if response.status_code == 200:
                response_body = b""
                async for chunk in response.body_iterator:
                    response_body += chunk
                
                # Parse response body
                response_data = json.loads(response_body)
                
                # Cache the response
                await redis_instance.set(
                    cache_key,
                    json.dumps(response_data),
                    ex=settings.CACHE_EXPIRATION
                )
                logger.debug(f"Cached response for {cache_key}")
                
                # Return the response with the cached body
                return JSONResponse(content=response_data)
            
            return response
        except Exception as e:
            logger.error(f"Cache error: {str(e)}")
            return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# Auth utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

# Pydantic models
class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

# Routes
@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

# Authentication routes
@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

# Repository Analysis Routes
@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

# Code Quality Routes
@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

# Security Scanner Routes
@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_request.language.lower() in ["javascript", "js"]:
                results = await security_scanner.scan_javascript_code(scan_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {scan_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Security


import os
import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import httpx
from pydantic import BaseModel, Field, HttpUrl
import logging
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as redis
from jose import JWTError, jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Import app configuration
from app.config import settings

# Import services
from app.services.ai_service import AIService
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.dependency_analyzer import DependencyAnalyzer
from app.services.template_generator import TemplateGenerator

# Set up logger
logger = logging.getLogger(__name__)

# Initialize Redis connection for caching
redis_instance = None
if settings.REDIS_URL:
    redis_instance = redis.from_url(settings.REDIS_URL)
else:
    redis_instance = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        ssl=settings.REDIS_SSL,
        decode_responses=True
    )

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SlowAPIMiddleware)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize services
ai_service = AIService()
repo_analyzer = RepositoryAnalyzer()
code_quality_checker = CodeQualityChecker()
security_scanner = SecurityScanner()
dependency_analyzer = DependencyAnalyzer()
template_generator = TemplateGenerator()

# Cache middleware
class CacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip caching for non-GET methods or authentication endpoints
        if request.method != "GET" or request.url.path in ["/token", "/auth/login", "/auth/callback"]:
            return await call_next(request)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {scan_request.language}"
                )
                return results
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Code snippet is required"
                )
        except Exception as e:
            logger.error(f"Security scan error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Security scan error: {str(e)}",
            )

# Dependency Analysis Routes
@app.post("/api/dependencies/analyze")
@limiter.limit("5/minute")
async def analyze_dependencies(
    request: Request, 
    dependency_request: DependencyAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes project dependencies and suggests updates
    """
    try:
        # In a real implementation, this would clone the repo and analyze it
        # For now, we'll simulate the response
        repo_path = "/tmp/example_repo"  # This would be the path to the cloned repo
        
        results = await dependency_analyzer.analyze_project_dependencies(repo_path)
        return results
    except Exception as e:
        logger.error(f"Dependency analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dependency analysis error: {str(e)}",
        )

@app.post("/api/dependencies/suggestions")
@limiter.limit("5/minute")
async def get_dependency_suggestions(
    request: Request, 
    dependency_request: DependencyAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Suggests updates for project dependencies
    """
    try:
        # In a real implementation, this would clone the repo and analyze it
        # For now, we'll simulate the response
        repo_path = "/tmp/example_repo"  # This would be the path to the cloned repo
        
        results = await dependency_analyzer.suggest_dependency_updates(repo_path)
        return results
    except Exception as e:
        logger.error(f"Dependency suggestion error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Dependency suggestion error: {str(e)}",
        )

# Template Generation Routes
@app.post("/api/templates/generate")
@limiter.limit("10/minute")
async def generate_template(
    request: Request, 
    template_request: TemplateGenerationRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Generates GitHub templates (PR, issue, contributing guide)
    """
    try:
        if template_request.template_type.lower() == "pr":
            result = await template_generator.generate_pr_template(
                repo_name=template_request.repo_name,
                repo_description=template_request.repo_description,
                repo_type=template_request.repo_type
            )
        elif template_request.template_type.lower() == "issue":
            result = await template_generator.generate_issue_template(
                repo_name=template_request.repo_name,
                repo_description=template_request.repo_description,
                issue_type=template_request.issue_type
            )
        elif template_request.template_type.lower() == "contributing":
            result = await template_generator.generate_contributing_guide(
                repo_name=template_request.repo_name,
                repo_description=template_request.repo_description
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported template type: {template_request.template_type}"
            )
        
        return {"template": result}
    except Exception as e:
        logger.error(f"Template generation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Template generation error: {str(e)}",
        )

# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.APP_VERSION,
        "services": {
            "api": "ok",
            "redis": "unknown",
            "ai": "unknown"
        }
    }
    
    # Check Redis connection
    try:
        if redis_instance:
            await redis_instance.ping()
            health_status["services"]["redis"] = "ok"
    except Exception as e:
        logger.warning(f"Redis health check failed: {str(e)}")
        health_status["services"]["redis"] = "error"
    
    # Check AI service (lightweight check)
    try:
        if hasattr(ai_service, 'llm') and ai_service.llm:
            health_status["services"]["ai"] = "ok"
    except Exception as e:
        logger.warning(f"AI service health check failed: {str(e)}")
        health_status["services"]["ai"] = "error"
    
    # Determine overall status
    if "error" in health_status["services"].values():
        health_status["status"] = "degraded"
    
    return health_status

# Error handling for 404 Not Found
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": "Not Found",
            "message": "The requested resource does not exist",
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# Error handling for 500 Internal Server Error
@app.exception_handler(500)
async def server_error_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": str(exc.detail) if hasattr(exc, 'detail') else "An unexpected error occurred",
            "path": request.url.path,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    # Check Redis connection
    if redis_instance:
        try:
            await redis_instance.ping()
            logger.info("Redis connection successful")
        except Exception as e:
            logger.warning(f"Redis connection failed: {str(e)}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info(f"Shutting down {settings.APP_NAME}")
    # Close Redis connection
    if redis_instance:
        try:
            await redis_instance.close()
            logger.info("Redis connection closed")
        except Exception as e:
            logger.warning(f"Error closing Redis connection: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
            cache_key = f"cache:{request.url.path}:{request.query_params}"
            
            try:
                # Try to get cached response
                cached = await redis_instance.get(cache_key)
                if cached:
                    logger.debug(f"Cache hit for {cache_key}")
                    cached_data = json.loads(cached)
                    return JSONResponse(content=cached_data)
                
                # If no cache hit, process the request
                response = await call_next(request)
                
                # Cache successful responses (status code 200)
                if response.status_code == 200:
                    response_body = b""
                    async for chunk in response.body_iterator:
                        response_body += chunk
                    
                    # Parse response body
                    response_data = json.loads(response_body)
                    
                    # Cache the response
                    await redis_instance.set(
                        cache_key,
                        json.dumps(response_data),
                        ex=settings.CACHE_EXPIRATION
                    )
                    logger.debug(f"Cached response for {cache_key}")
                    
                    # Return the response with the cached body
                    return JSONResponse(content=response_data)
                
                return response
            except Exception as e:
                logger.error(f"Cache error: {str(e)}")
                return await call_next(request)

# Add cache middleware if Redis is configured
if redis_instance:
    app.add_middleware(CacheMiddleware)

# Auth utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return {"username": username}

# Pydantic models
class RepositoryRequest(BaseModel):
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
    repo_url: Optional[str] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None
    language: str = "python"
    
    class Config:
        schema_extra = {
            "example": {
                "code_snippet": "password = 'hardcoded_password'\napi_key = 'my_secret_key'",
                "language": "python"
            }
        }

class DependencyAnalysisRequest(BaseModel):
    repo_url: str
    
    class Config:
        schema_extra = {
            "example": {
                "repo_url": "https://github.com/username/repo"
            }
        }

class TemplateGenerationRequest(BaseModel):
    repo_name: str
    repo_description: str
    template_type: str = "pr"  # pr, issue, contributing
    issue_type: Optional[str] = "bug"  # bug, feature (used only for issue templates)
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

class TokenRequest(BaseModel):
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
    access_token: str
    token_type: str = "bearer"

# Routes
@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME} API. Visit /docs for documentation."}

# Authentication routes
@app.post("/token", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Get an access token for API authentication
    """
    # This is a simplified example. In production, validate against a database.
    if form_data.username != "demo" or form_data.password != "demo":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/login")
async def github_login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = settings.GITHUB_CLIENT_ID
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)

@app.get("/auth/callback")
async def github_callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = settings.GITHUB_CLIENT_ID
        github_client_secret = settings.GITHUB_CLIENT_SECRET
        
        if not github_client_id or not github_client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="GitHub OAuth credentials not configured",
            )
        
        # Exchange code for access token
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": github_client_id,
                    "client_secret": github_client_secret,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get access token: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Failed to authenticate with GitHub",
                )
            
            token_data = response.json()
            # Create JWT token for our API
            access_token = create_access_token(
                data={"sub": "github_user", "github_token": token_data.get("access_token")}
            )
            
            return {"access_token": access_token, "token_type": "bearer"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )

# Repository Analysis Routes
@app.post("/api/repos/analyze")
@limiter.limit("10/minute")
async def analyze_repository(
    request: Request, 
    repo_request: RepositoryRequest, 
    current_user: dict = Depends(get_current_user)
):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    try:
        # This would typically clone the repository and analyze it
        # For demo purposes, we'll return mock data
        analysis_result = await repo_analyzer.analyze_repository()
        return analysis_result
    except Exception as e:
        logger.error(f"Repository analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repository analysis error: {str(e)}",
        )

# Code Quality Routes
@app.post("/api/code/quality")
@limiter.limit("20/minute")
async def check_code_quality(
    request: Request, 
    code_request: CodeQualityRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """
    Checks code quality and provides suggestions for improvement
    """
    try:
        if code_request.code_snippet:
            if code_request.language.lower() == "python":
                results = await code_quality_checker.analyze_python_code(code_request.code_snippet)
            elif code_request.language.lower() in ["javascript", "js"]:
                results = await code_quality_checker.analyze_javascript_code(code_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported language: {code_request.language}"
                )
            return results
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Code snippet is required"
            )
    except Exception as e:
        logger.error(f"Code quality check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code quality check error: {str(e)}",
        )

# Security Scanner Routes
@app.post("/api/security/scan")
@limiter.limit("10/minute")
async def scan_for_vulnerabilities(
    request: Request, 
    scan_request: SecurityScanRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Scans code for security vulnerabilities
    """
    try:
        if scan_request.code_snippet:
            if scan_request.language.lower() == "python":
                results = await security_scanner.scan_python_code(scan_request.code_snippet)
            elif scan_request.language.lower() in ["javascript", "js"]:
                results = await security_scanner.scan_javascript_code(scan_request.code_snippet)
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"

