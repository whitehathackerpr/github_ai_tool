from fastapi import APIRouter, Response, status, Request
from typing import Dict, Any
import logging
from datetime import datetime
import psutil
import httpx

from app.core.models import HealthResponse, ComponentHealth
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

async def check_redis_health(request: Request) -> ComponentHealth:
    """
    Check Redis connection health.
    
    Args:
        request: FastAPI request object with app state
        
    Returns:
        ComponentHealth object with Redis status
    """
    try:
        if hasattr(request.app.state, "redis"):
            redis_client = request.app.state.redis
            await redis_client.ping()
            return ComponentHealth(
                status="healthy",
                message="Redis connection is healthy",
                details={
                    "host": settings.REDIS_HOST,
                    "port": settings.REDIS_PORT
                }
            )
        return ComponentHealth(
            status="unknown",
            message="Redis not configured"
        )
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")
        return ComponentHealth(
            status="unhealthy",
            message=f"Redis connection failed: {str(e)}",
            details={
                "error": str(e)
            }
        )

async def check_github_api() -> ComponentHealth:
    """
    Check GitHub API health.
    
    Returns:
        ComponentHealth object with GitHub API status
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/zen",
                timeout=5.0
            )
            if response.status_code == 200:
                return ComponentHealth(
                    status="healthy",
                    message="GitHub API is accessible",
                    details={
                        "status_code": response.status_code,
                        "response_time": f"{response.elapsed.total_seconds():.3f}s"
                    }
                )
            return ComponentHealth(
                status="unhealthy",
                message=f"GitHub API returned status {response.status_code}",
                details={
                    "status_code": response.status_code,
                    "response_time": f"{response.elapsed.total_seconds():.3f}s"
                }
            )
    except Exception as e:
        logger.error(f"GitHub API health check failed: {str(e)}")
        return ComponentHealth(
            status="unhealthy",
            message=f"GitHub API check failed: {str(e)}",
            details={
                "error": str(e)
            }
        )

def get_system_metrics() -> Dict[str, float]:
    """
    Get system resource metrics.
    
    Returns:
        Dictionary of system metrics (CPU, memory, disk usage)
    """
    try:
        return {
            "cpu_usage": psutil.cpu_percent(interval=0.1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "load_avg": psutil.getloadavg()[0]  # 1-minute load average
        }
    except Exception as e:
        logger.error(f"Error getting system metrics: {str(e)}")
        return {
            "cpu_usage": 0.0,
            "memory_usage": 0.0,
            "disk_usage": 0.0
        }

@router.get("/", response_model=HealthResponse)
async def health_check(request: Request, response: Response) -> Dict[str, Any]:
    """
    Check the overall health status of all system components.
    
    This endpoint performs health checks on all critical components
    and returns a comprehensive health status report.
    """
    # Check individual components
    redis_health = await check_redis_health(request)
    github_health = await check_github_api()
    
    # Get system metrics
    system_metrics = get_system_metrics()
    
    # Determine overall status
    services = {
        "redis": redis_health,
        "github_api": github_health
    }
    
    # Critical services that must be healthy
    critical_services = ["redis"]
    critical_healthy = all(
        services[name].status == "healthy" 
        for name in critical_services
        if name in services
    )
    
    # Determine overall status
    if all(service.status == "healthy" for service in services.values()):
        overall_status = "healthy"
    elif any(service.status == "unhealthy" for service in services.values()):
        overall_status = "unhealthy" if not critical_healthy else "degraded"
    else:
        overall_status = "degraded"
    
    health

from fastapi import APIRouter, Response, status
from typing import Dict, Any
import psutil
import os
from datetime import datetime

from app.config import settings
from app.core.health import (
    check_redis_connection,
    check_github_api,
    check_openai_api,
    check_disk_space
)

router = APIRouter(tags=["Health"])

@router.get("/health")
async def health_check(response: Response) -> Dict[str, Any]:
    """
    Check the overall health status of all system components.
    """
    try:
        redis_health = await check_redis_connection()
        github_health = await check_github_api()
        openai_health = await check_openai_api()
        disk_health = check_disk_space(settings.TEMP_DIR)
        
        # Check service status
        services_health = {
            "redis": redis_health["status"] == "healthy",
            "github_api": github_health["status"] == "healthy",
            "openai_api": openai_health["status"] == "healthy",
            "disk": disk_health["status"] == "healthy"
        }
        
        # Get system metrics
        system_metrics = {
            "cpu_usage": psutil.cpu_percent(),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent
        }
        
        health_status = {
            "status": "healthy" if all(services_health.values()) else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "version": settings.APP_VERSION,
            "services": {
                "redis": redis_health,
                "github_api": github_health,
                "openai_api": openai_health,
                "disk": disk_health
            },
            "system_metrics": system_metrics
        }
        
        if health_status["status"] != "healthy":
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
            
        return health_status
        
    except Exception as e:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "version": settings.APP_VERSION,
            "error": str(e)
        }

@router.get("/health/redis")
async def redis_health(response: Response) -> Dict[str, Any]:
    """
    Check Redis connection health specifically.
    """
    health_status = await check_redis_connection()
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health_status

@router.get("/health/github")
async def github_health(response: Response) -> Dict[str, Any]:
    """
    Check GitHub API health specifically.
    """
    health_status = await check_github_api()
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health_status

@router.get("/health/openai")
async def openai_health(response: Response) -> Dict[str, Any]:
    """
    Check OpenAI API health specifically.
    """
    health_status = await check_openai_api()
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health_status

@router.get("/health/disk")
async def disk_health(response: Response) -> Dict[str, Any]:
    """
    Check disk space health specifically.
    """
    health_status = check_disk_space(settings.TEMP_DIR)
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return health_status

from fastapi import APIRouter, Response, status, Depends
from typing import Dict, Any, Optional
import logging
import time

from app.core.health import (
    get_system_health,
    check_redis_connection,
    check_github_api,
    check_openai_api,
    check_disk_space
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Health"])

@router.get("/health", summary="Get system health status")
async def health_check(response: Response) -> Dict[str, Any]:
    """
    Get the health status of all system components.
    
    This endpoint checks all critical system components and returns their health status.
    The HTTP status code will be 200 if all critical components are healthy,
    or 503 Service Unavailable if any critical component is unhealthy.
    
    Returns:
        dict: Health status of all components and overall system health
    """
    start_time = time.time()
    health_status = await get_system_health()
    
    # Log health check results
    execution_time = time.time() - start_time
    logger.info(
        f"Health check completed in {execution_time:.2f}s. "
        f"Status: {health_status['status']}. "
        f"Component statuses: {health_status['status_counts']}"
    )
    
    # Set appropriate status code
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    
    return health_status

@router.get("/health/redis", summary="Check Redis health")
async def redis_health(response: Response) -> Dict[str, Any]:
    """
    Check Redis connection health specifically.
    
    This endpoint tests the connection to the Redis server configured in the application.
    
    Returns:
        dict: Redis connection health status
    """
    health_status = await check_redis_connection()
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning(f"Redis health check failed: {health_status['message']}")
    
    return health_status

@router.get("/health/github", summary="Check GitHub API health")
async def github_health(response: Response) -> Dict[str, Any]:
    """
    Check GitHub API health specifically.
    
    This endpoint verifies that the GitHub API is accessible from the application.
    
    Returns:
        dict: GitHub API health status
    """
    health_status = await check_github_api()
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning(f"GitHub API health check failed: {health_status['message']}")
    
    return health_status

@router.get("/health/openai", summary="Check OpenAI API health")
async def openai_health(response: Response) -> Dict[str, Any]:
    """
    Check OpenAI API health specifically.
    
    This endpoint verifies that the OpenAI API is accessible using the configured API key.
    
    Returns:
        dict: OpenAI API health status
    """
    health_status = await check_openai_api()
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        if health_status["status"] == "unconfigured":
            logger.info("OpenAI API health check skipped: API key not configured")
        else:
            logger.warning(f"OpenAI API health check failed: {health_status['message']}")
    
    return health_status

@router.get("/health/disk", summary="Check disk space")
def disk_space_health(response: Response) -> Dict[str, Any]:
    """
    Check available disk space.
    
    This endpoint checks the available disk space in the temporary directory
    used for repository cloning and other file operations.
    
    Returns:
        dict: Disk space health status
    """
    health_status = check_disk_space()
    if health_status["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        logger.warning(f"Disk space check failed: {health_status['message']}")
    
    return health_status

