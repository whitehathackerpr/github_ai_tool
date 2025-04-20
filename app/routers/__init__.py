from fastapi import APIRouter
from . import health, auth

# Create API router
api_router = APIRouter()

# Include health check routes
api_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health"]
)

# Include auth routes
api_router.include_router(
    auth.router,
    prefix="/auth", 
    tags=["Authentication"]
)

# Additional routers will be included as they are implemented

