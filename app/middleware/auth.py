from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
import logging
from typing import Optional, Dict, Any

from app.config import settings

logger = logging.getLogger(__name__)

class JWTAuthMiddleware:
    """Middleware for JWT authentication."""
    
    def __init__(self):
        self.security = HTTPBearer()
        self.exempt_paths = {
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/health/redis",
            "/health/github",
            "/health/openai",
            "/health/disk",
            "/auth/login",
            "/auth/callback",
            "/token",
            "/"
        }
    
    async def __call__(self, request: Request, call_next):
        if request.url.path in self.exempt_paths or request.url.path.startswith("/static/"):
            return await call_next(request)
        
        try:
            # Get token from header
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
                
            scheme, token = auth_header.split()
            if scheme.lower() != "bearer":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication scheme",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Verify token
            try:
                payload = jwt.decode(
                    token, 
                    settings.SECRET_KEY, 
                    algorithms=["HS256"]
                )
                
                # Check if token is expired
                exp = payload.get("exp")
                if exp is None:
                    raise JWTError("Token has no expiration")
                
                if datetime.utcfromtimestamp(exp) < datetime.utcnow():
                    raise JWTError("Token has expired")
                
                # Add user info to request state
                request.state.user = payload
                
            except JWTError as e:
                logger.warning(f"JWT validation failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            response = await call_next(request)
            return response
            
        except HTTPException as e:
            if e.status_code == 401:
                logger.warning(f"Authentication failed for path {request.url.path}")
            raise e
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during authentication"
            )

class RateLimitByUserMiddleware:
    """Rate limiting middleware based on user identity."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.window_size = settings.RATE_LIMIT_WINDOW
        self.max_requests = settings.RATE_LIMIT_MAX_REQUESTS
        self.exempt_paths = {
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
            "/health/redis",
            "/health/github",
            "/health/openai",
            "/health/disk",
            "/"
        }
    
    async def __call__(self, request: Request, call_next):
        if not settings.RATE_LIMIT_ENABLED or request.url.path in self.exempt_paths:
            return await call_next(request)
        
        # Get user identity from token or IP
        user_id = None
        if hasattr(request.state, "user") and request.state.user:
            user_id = request.state.user.get("sub")
        
        # Fall back to IP address if no user ID is available
        if not user_id:
            user_id = f"ip:{request.client.host}"
        
        # Create rate limit key including the HTTP method
        key = f"rate_limit:{user_id}:{request.method}:{request.url.path}"
        
        try:
            # Get current request count
            current = await self.redis.get(key)
            current = int(current) if current else 0
            
            if current >= self.max_requests:
                logger.warning(f"Rate limit exceeded for user {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests",
                    headers={
                        "Retry-After": str(self.window_size),
                        "X-RateLimit-Limit": str(self.max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(self.window_size)
                    }
                )
            
            # Increment request count
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, self.window_size)
            await pipe.execute()
            
            response = await call_next(request)
            
            # Add rate limit headers
            remaining = self.max_requests - (current + 1)
            response.headers["X-RateLimit-Limit"] = str(self.max_requests)
            response.headers["X-RateLimit-Remaining"] = str(max(0, remaining))
            response.headers["X-RateLimit-Reset"] = str(self.window_size)
            
            return response
            
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Rate limiting error: {str(e)}")
            return await call_next(request)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    """Create a new JWT refresh token with longer expiration."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)  # Refresh tokens valid for 7 days
    to_encode.update({"exp": expire, "refresh": True})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

