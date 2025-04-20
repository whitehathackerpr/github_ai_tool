from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import logging
from typing import Dict, Any

from app.core.models import (
    TokenRequest, TokenResponse, RefreshTokenRequest,
    UserInfo, ErrorResponse
)
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

# TODO: Move these utility functions to app.core.auth
async def authenticate_github_user(username: str, password: str) -> Dict[str, Any]:
    """
    Authenticate a user against GitHub.
    
    Args:
        username: GitHub username
        password: GitHub password or personal access token
    
    Returns:
        Dict containing user information
    
    Raises:
        HTTPException: If authentication fails
    """
    # This is a placeholder - in a real implementation, this would verify GitHub credentials
    # Using GitHub's API or OAuth flow
    if username == "demo" and password == "demo":
        return {
            "sub": username,
            "scopes": ["user", "repo"],
            "type": "github"
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid GitHub credentials"
    )

def create_access_token(data: Dict[str, Any], expires_delta: timedelta = None) -> str:
    """
    Create a new JWT access token.
    
    Args:
        data: Payload data for the token
        expires_delta: Optional expiration time override
        
    Returns:
        Encoded JWT token as string
    """
    # This is a placeholder - move to app.core.auth
    from jose import jwt
    
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create a new JWT refresh token with extended expiration.
    
    Args:
        data: Payload data for the token
        
    Returns:
        Encoded JWT refresh token as string
    """
    # Add refresh token type indicator
    refresh_data = data.copy()
    refresh_data.update({"token_type": "refresh"})
    
    # Use longer expiration for refresh tokens
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return create_access_token(data=refresh_data, expires_delta=expires_delta)

async def verify_refresh_token(token: str) -> Dict[str, Any]:
    """
    Verify a refresh token and return the user data.
    
    Args:
        token: The refresh token to verify
        
    Returns:
        Dict containing user information from the token
    
    Raises:
        HTTPException: If token is invalid or not a refresh token
    """
    from jose import jwt, JWTError
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        
        # Verify this is a refresh token
        if payload.get("token_type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not a refresh token"
            )
        
        # Extract user info
        user_data = {
            "sub": payload.get("sub"),
            "scopes": payload.get("scopes", []),
            "type": payload.get("type")
        }
        
        return user_data
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

def verify_access_token(token: str) -> Dict[str, Any]:
    """
    Verify an access token and return the payload.
    
    Args:
        token: The access token to verify
        
    Returns:
        Dict containing token payload
    
    Raises:
        HTTPException: If token is invalid
    """
    from jose import jwt, JWTError
    
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token"
        )

async def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Get current user from the request's state.
    
    Args:
        request: The request object
        
    Returns:
        Dict containing user information
        
    Raises:
        HTTPException: If user is not authenticated
    """
    # In a middleware-based auth system, this would just return request.state.user
    # This is a placeholder for direct use
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    try:
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme"
            )
        
        payload = verify_access_token(token)
        return {
            "username": payload.get("sub"),
            "scopes": payload.get("scopes", []),
            "github_token": payload.get("github_token")
        }
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format"
        )

@router.post("/login", response_model=TokenResponse)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()) -> Dict[str, Any]:
    """
    OAuth2 compatible token login, get an access token for future requests.
    
    This endpoint validates the provided username and password with GitHub
    and returns JWT access and refresh tokens for API authentication.
    """
    try:
        # Validate GitHub credentials
        user_data = await authenticate_github_user(form_data.username, form_data.password)
        
        # Create tokens
        access_token = create_access_token(data=user_data)
        refresh_token = create_refresh_token(data=user_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    refresh_token_req: RefreshTokenRequest
) -> Dict[str, Any]:
    """
    Get a new access token using a refresh token.
    
    This endpoint validates the provided refresh token and issues a new
    access token if the refresh token is valid and not blacklisted.
    """
    try:
        # Validate refresh token
        user_data = await verify_refresh_token(refresh_token_req.refresh_token)
        
        # Check if token is blacklisted
        if hasattr(request.app.state, "redis"):
            is_blacklisted = await request.app.state.redis.get(
                f"blacklist:{refresh_token_req.refresh_token}"
            )
            if is_blacklisted:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked"
                )
        
        # Create new access token
        access_token = create_access_token(data=user_data)
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

@router.post("/logout")
async def logout(request: Request) -> Dict[str, str]:
    """
    Logout user by invalidating their tokens.
    
    This endpoint adds the current token to a blacklist to prevent its further use.
    Note: In a stateless JWT system, we can't truly invalidate tokens without a blacklist.
    """
    try:
        auth_header = request.headers.get("Authorization")
        if auth_header:
            scheme, token = auth_header.split()
            if scheme.lower() == "bearer":
                # Add token to blacklist if Redis is available
                if hasattr(request.app.state, "redis"):
                    # Get token expiration
                    try:
                        payload = verify_access_token(token)
                        exp = payload.get("exp", 0)
                        ttl = max(1, int(exp - datetime.utcnow().timestamp()))
                    except:
                        ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
                    
                    # Blacklist token
                    await request.app.state.redis.setex(
                        f"blacklist:{token}",
                        ttl,
                        "1"
                    )
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        return {"message": "Successfully logged out"}  # Always return success for security

@router.get("/me", response_model=UserInfo)
async def get_user_info(request: Request) -> Dict[str, Any]:
    """
    Get current user information.
    
    This endpoint returns information about the currently authenticated user.
    """
    return await get_current_user(request)

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging

from app.core.config import settings
from app.middleware.auth import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> Dict[str, Any]:
    """
    OAuth2 compatible token login, get an access token for future requests.
    
    This endpoint validates user credentials and returns JWT access and refresh tokens.
    
    Args:
        form_data: OAuth2 password request form with username and password
        
    Returns:
        Dictionary containing access token, refresh token, and token type
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Validate GitHub credentials (implement GitHub OAuth flow)
        # This is a placeholder - implement actual GitHub OAuth validation
        user_data = {
            "sub": form_data.username,
            "scopes": form_data.scopes if hasattr(form_data, "scopes") else [],
            "type": "github"
        }
        
        # Create access and refresh tokens
        access_token = create_access_token(data=user_data)
        refresh_token = create_refresh_token(data=user_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/refresh")
async def refresh_token(request: Request) -> Dict[str, Any]:
    """
    Get a new access token using a refresh token.
    
    This endpoint validates a refresh token and issues a new access token.
    
    Args:
        request: The HTTP request containing the refresh token in the Authorization header
        
    Returns:
        Dictionary containing the new access token and token type
        
    Raises:
        HTTPException: If token validation fails
    """
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Validate refresh token and get new access token
        from jose import jwt, JWTError
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            
            # Verify this is a refresh token
            if not payload.get("token_type") == "refresh":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Check if token is blacklisted (if Redis is available)
            if hasattr(request.app.state, "redis"):
                redis = request.app.state.redis
                blacklisted = await redis.get(f"blacklist:{token}")
                if blacklisted:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has been revoked",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            
            # Create new access token
            user_data = {
                "sub": payload.get("sub"),
                "scopes": payload.get("scopes", []),
                "type": payload.get("type")
            }
            
            access_token = create_access_token(data=user_data)
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
            
        except JWTError as e:
            logger.warning(f"Refresh token validation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post("/logout")
async def logout(request: Request) -> Dict[str, str]:
    """
    Logout the user by invalidating their tokens.
    
    Note: In a stateless JWT system, we can't truly invalidate tokens.
    Best practice is to maintain a blacklist of logged-out tokens until they expire.
    
    Args:
        request: The HTTP request containing the token to invalidate
        
    Returns:
        Dictionary with success message
    """
    try:
        # Get the token from the authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header:
            scheme, token = auth_header.split()
            if scheme.lower() == "bearer":
                # Add token to blacklist if Redis is available
                if hasattr(request.app.state, "redis"):
                    redis = request.app.state.redis
                    # Extract token expiration time if possible
                    try:
                        from jose import jwt
                        payload = jwt.decode(
                            token,
                            settings.SECRET_KEY,
                            algorithms=[settings.JWT_ALGORITHM],
                            options={"verify_exp": False}
                        )
                        exp = payload.get("exp")
                        if exp:
                            # Calculate seconds until expiration
                            now = datetime.utcnow().timestamp()
                            ttl = max(1, int(exp - now))
                        else:
                            ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
                    except Exception:
                        ttl = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
                    
                    # Add token to blacklist with expiry
                    await redis.setex(
                        f"blacklist:{token}",
                        ttl,
                        "1"
                    )
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        return {"message": "Successfully logged out"}  # Always return success for security

@router.post("/github/callback")
async def github_oauth_callback(code: str, state: Optional[str] = None) -> Dict[str, Any]:
    """
    Handle GitHub OAuth callback.
    
    This endpoint processes the callback from GitHub OAuth and generates tokens.
    
    Args:
        code: Authorization code from GitHub
        state: State parameter for CSRF protection
        
    Returns:
        Dictionary containing access token, refresh token, and token type
        
    Raises:
        HTTPException: If OAuth validation fails
    """
    try:
        # Placeholder for GitHub OAuth implementation
        # In a real implementation, you would:
        # 1. Exchange the code for an access token with GitHub
        # 2. Fetch the user profile with the access token
        # 3. Create or update the user in your database
        # 4. Create JWT tokens for your app
        
        # Placeholder user data
        user_data = {
            "sub": "github_user_id",  # Use actual GitHub user ID
            "scopes": ["repo", "user"],  # Use actual scopes granted
            "type": "github"
        }
        
        # Create access and refresh tokens
        access_token = create_access_token(data=user_data)
        refresh_token = create_refresh_token(data=user_data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
        
    except Exception as e:
        logger.error(f"GitHub OAuth callback failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

