from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import logging
from typing import List, Optional
import secrets
import time

from app.config import settings

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next):
        # Generate request ID for tracing
        request_id = secrets.token_hex(8)
        request.state.request_id = request_id
        
        # Start timer for request duration
        start_time = time.time()
        
        response = await call_next(request)
        
        # Calculate request duration
        duration = time.time() - start_time
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = self._get_csp_policy()
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Add request tracking headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration:.3f}s"
        
        # Log request details
        logger.debug(
            f"Request: {request.method} {request.url.path} - "
            f"Status: {response.status_code} - "
            f"Duration: {duration:.3f}s - "
            f"ID: {request_id}"
        )
        
        return response
    
    def _get_csp_policy(self) -> str:
        """Get Content Security Policy based on environment."""
        if settings.DEBUG:
            # More permissive CSP for development
            return (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'"
            )
        else:
            # Strict CSP for production
            return (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self'; "
                "font-src 'self'; "
                "connect-src 'self'"
            )

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log request and response details."""
    
    async def dispatch(self, request: Request, call_next):
        # Log request
        logger.info(f"Request: {request.method} {request.url.path}")
        
        # Process request
        try:
            response = await call_next(request)
            
            # Log successful response
            logger.info(
                f"Response: {request.method} {request.url.path} - "
                f"Status: {response.status_code}"
            )
            
            return response
        except Exception as e:
            # Log exception
            logger.error(
                f"Error: {request.method} {request.url.path} - "
                f"Exception: {str(e)}"
            )
            raise

def get_cors_middleware(allowed_origins: Optional[List[str]] = None):
    """Configure CORS middleware based on environment."""
    if settings.DEBUG:
        # Development configuration
        return CORSMiddleware(
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        # Production configuration
        origins = allowed_origins or ["https://github.com"]
        return CORSMiddleware(
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "Accept",
                "Origin",
                "X-Requested-With"
            ],
            expose_headers=[
                "X-RateLimit-Limit",
                "X-RateLimit-Remaining",
                "X-RateLimit-Reset",
                "X-Request-ID",
                "X-Response-Time"
            ],
            max_age=3600
        )

