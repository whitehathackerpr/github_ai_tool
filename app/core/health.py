import logging
from typing import Dict, Any, List
import httpx
import redis
from app.config import settings

logger = logging.getLogger(__name__)

async def check_redis_connection() -> Dict[str, Any]:
    """
    Check Redis connection health.
    
    Returns:
        dict: Status of Redis connection with health indicators
    """
    try:
        # Create Redis connection
        redis_client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            ssl=settings.REDIS_SSL,
            db=settings.REDIS_DB,
            socket_timeout=5.0,
            socket_connect_timeout=5.0
        )
        
        # Ping Redis to check connection
        response = redis_client.ping()
        redis_client.close()
        
        if response:
            return {
                "status": "healthy",
                "message": "Redis connection is healthy",
                "details": {
                    "host": settings.REDIS_HOST,
                    "port": settings.REDIS_PORT,
                    "ssl": settings.REDIS_SSL
                }
            }
        else:
            return {
                "status": "unhealthy",
                "message": "Redis ping failed",
                "details": {
                    "host": settings.REDIS_HOST,
                    "port": settings.REDIS_PORT,
                    "ssl": settings.REDIS_SSL
                }
            }
    except Exception as e:
        logger.error(f"Redis health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "message": f"Redis connection failed: {str(e)}",
            "details": {
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "ssl": settings.REDIS_SSL,
                "error": str(e)
            }
        }

async def check_github_api() -> Dict[str, Any]:
    """
    Check GitHub API health.
    
    Returns:
        dict: Status of GitHub API with health indicators
    """
    try:
        timeout = httpx.Timeout(10.0, connect=5.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get("https://api.github.com/zen")
            
            if response.status_code == 200:
                return {
                    "status": "healthy",
                    "message": "GitHub API is accessible",
                    "details": {
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds()
                    }
                }
            else:
                return {
                    "status": "unhealthy",
                    "message": f"GitHub API returned status {response.status_code}",
                    "details": {
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "response": response.text[:100]  # Include first 100 chars of response
                    }
                }
    except Exception as e:
        logger.error(f"GitHub API health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "message": f"GitHub API check failed: {str(e)}",
            "details": {
                "error": str(e)
            }
        }

async def check_openai_api() -> Dict[str, Any]:
    """
    Check OpenAI API health.
    
    Returns:
        dict: Status of OpenAI API with health indicators
    """
    if not settings.OPENAI_API_KEY:
        return {
            "status": "unconfigured",
            "message": "OpenAI API key not configured"
        }
    
    try:
        timeout = httpx.Timeout(10.0, connect=5.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.openai.com/v1/models",
                headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"}
            )
            
            if response.status_code == 200:
                return {
                    "status": "healthy",
                    "message": "OpenAI API is accessible",
                    "details": {
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "models_available": True
                    }
                }
            else:
                return {
                    "status": "unhealthy",
                    "message": f"OpenAI API returned status {response.status_code}",
                    "details": {
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "error": response.text[:100]  # Include first 100 chars of response
                    }
                }
    except Exception as e:
        logger.error(f"OpenAI API health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "message": f"OpenAI API check failed: {str(e)}",
            "details": {
                "error": str(e)
            }
        }

def check_disk_space() -> Dict[str, Any]:
    """
    Check available disk space.
    
    Returns:
        dict: Status of disk space with health indicators
    """
    try:
        import shutil
        
        # Get disk usage for temp directory
        total, used, free = shutil.disk_usage(settings.TEMP_DIR)
        
        # Convert to GB for readability
        total_gb = total / (1024 ** 3)
        used_gb = used / (1024 ** 3)
        free_gb = free / (1024 ** 3)
        
        # Calculate percentage used
        percent_used = (used / total) * 100
        
        # Check if space is sufficient (less than 90% used)
        status = "healthy" if percent_used < 90 else "unhealthy"
        
        return {
            "status": status,
            "message": f"Disk space: {free_gb:.2f}GB free of {total_gb:.2f}GB ({percent_used:.1f}% used)",
            "details": {
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(free_gb, 2),
                "percent_used": round(percent_used, 1)
            }
        }
    except Exception as e:
        logger.error(f"Disk space check failed: {str(e)}")
        return {
            "status": "unknown",
            "message": f"Disk space check failed: {str(e)}",
            "details": {
                "error": str(e)
            }
        }

async def get_system_health() -> Dict[str, Any]:
    """
    Get overall system health status.
    
    Returns:
        dict: Complete health status of all system components
    """
    # Run all health checks
    redis_health = await check_redis_connection()
    github_health = await check_github_api()
    openai_health = await check_openai_api()
    disk_health = check_disk_space()
    
    # Collect all components
    components = {
        "redis": redis_health,
        "github_api": github_health,
        "openai_api": openai_health,
        "disk_space": disk_health
    }
    
    # Determine overall status
    # System is healthy only if all critical components are healthy
    critical_components = ["redis", "github_api", "disk_space"]
    critical_healthy = all(
        components[comp]["status"] == "healthy" 
        for comp in critical_components
    )
    
    # OpenAI is considered optional
    overall_status = "healthy" if critical_healthy else "unhealthy"
    
    # Count statuses
    status_counts = {
        "healthy": sum(1 for comp in components.values() if comp["status"] == "healthy"),
        "unhealthy": sum(1 for comp in components.values() if comp["status"] == "unhealthy"),
        "unconfigured": sum(1 for comp in components.values() if comp["status"] == "unconfigured"),
        "unknown": sum(1 for comp in components.values() if comp["status"] == "unknown")
    }
    
    return {
        "status": overall_status,
        "status_counts": status_counts,
        "components": components,
        "version": settings.APP_VERSION,
        "environment": "production" if not settings.DEBUG else "development"
    }

