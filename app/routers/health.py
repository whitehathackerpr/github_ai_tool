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

