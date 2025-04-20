from fastapi import APIRouter, HTTPException, status, Depends, BackgroundTasks, Query
from typing import Dict, Any, Optional, List
import logging
from datetime import datetime

from app.core.models import (
    RepositoryRequest,
    CodeQualityRequest,
    SecurityScanRequest,
    CodeAnalysisResponse
)
from app.services.code_quality_checker import CodeQualityChecker
from app.services.security_scanner import SecurityScanner
from app.services.repository_analyzer import RepositoryAnalyzer
from app.services.dependency_analyzer import DependencyAnalyzer
from app.middleware.auth import get_current_user
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Analysis"])

@router.post("/repository", response_model=CodeAnalysisResponse, status_code=status.HTTP_202_ACCEPTED)
async def analyze_repository(
    request: RepositoryRequest,
    background_tasks: BackgroundTasks,
    include_security: bool = Query(True, description="Include security scan in analysis"),
    include_dependencies: bool = Query(True, description="Include dependency analysis"),
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Analyze a GitHub repository for code quality and security issues.
    
    This endpoint performs a comprehensive analysis of the specified repository,
    including code quality checks, security scanning, and dependency analysis.
    
    Args:
        request: Repository analysis request containing repo URL and branch
        background_tasks: FastAPI background tasks handler
        include_security: Whether to include security scanning
        include_dependencies: Whether to include dependency analysis
        current_user: Current authenticated user
        
    Returns:
        Dict[str, Any]: Analysis results including suggestions and metrics
    """
    try:
        # Initialize analyzers
        repo_analyzer = RepositoryAnalyzer()
        code_checker = CodeQualityChecker()
        security_scanner = SecurityScanner()
        dependency_analyzer = DependencyAnalyzer()
        
        # Start analysis
        logger.info(f"Starting analysis for repository: {request.repo_url}")
        analysis_id = f"analysis_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{current_user.get('sub', 'anonymous')}"
        
        # Clone repository
        repo_path = await repo_analyzer.clone_repository(
            request.repo_url,
            branch=request.branch
        )
        
        # Perform code quality analysis
        quality_results = await code_checker.analyze_repository(repo_path)
        
        # Collect analysis results
        analysis_results = {
            "id": analysis_id,
            "repository": request.repo_url,
            "branch": request.branch,
            "timestamp": datetime.utcnow().isoformat(),
            "quality_analysis": quality_results,
        }
        
        # Perform security scan if requested
        if include_security:
            security_results = await security_scanner.scan_repository(repo_path)
            analysis_results["security_analysis"] = security_results
        
        # Perform dependency analysis if requested
        if include_dependencies:
            dependency_results = await dependency_analyzer.analyze_dependencies(repo_path)
            analysis_results["dependency_analysis"] = dependency_results
        
        # Generate summary
        analysis_results["summary"] = await repo_analyzer.generate_analysis_summary(
            quality_results=quality_results,
            security_results=analysis_results.get("security_analysis"),
            dependency_results=analysis_results.get("dependency_analysis")
        )
        
        # Store results for later retrieval
        # This would typically involve saving to a database or cache
        # For now, just log that we would store it
        logger.info(f"Would store analysis results with ID: {analysis_id}")
        
        # Clean up repository in background
        background_tasks.add_task(repo_analyzer.cleanup_repository, repo_path)
        
        logger.info(f"Analysis completed for repository: {request.repo_url}")
        return analysis_results
        
    except Exception as e:
        logger.error(f"Repository analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )

@router.post("/code-quality", response_model=CodeAnalysisResponse)
async def check_code_quality(
    request: CodeQualityRequest,
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Analyze code quality for a specific file or code snippet.
    
    This endpoint performs code quality analysis on the provided code,
    including style checks, complexity analysis, and best practice recommendations.
    
    Args:
        request: Code quality analysis request
        current_user: Current authenticated user
        
    Returns:
        Dict[str, Any]: Code quality analysis results
    """
    try:
        code_checker = CodeQualityChecker()
        
        if request.repo_url:
            # Analyze specific file in repository
            results = await code_checker.analyze_repository_file(
                request.repo_url,
                request.file_path
            )
        elif request.code_snippet:
            # Analyze code snippet
            results = await code_checker.analyze_code(
                request.code_snippet,
                language=request.language
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either repo_url with file_path or code_snippet must be provided"
            )
        
        analysis_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "language": request.language,
            "analysis": results,
            "summary": await code_checker.generate_summary(results)
        }
        
        logger.info(f"Code quality analysis completed for language: {request.language}")
        return analysis_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Code quality analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )

@router.post("/security-scan", response_model=CodeAnalysisResponse)
async def scan_security(
    request: SecurityScanRequest,
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Perform security analysis on code or repository.
    
    This endpoint scans for security vulnerabilities, including potential
    secrets, insecure patterns, and known vulnerability patterns.
    
    Args:
        request: Security scan request
        current_user: Current authenticated user
        
    Returns:
        Dict[str, Any]: Security scan results
    """
    try:
        security_scanner = SecurityScanner()
        
        if request.repo_url:
            # Scan specific file in repository
            if request.file_path:
                results = await security_scanner.scan_repository_file(
                    request.repo_url,
                    request.file_path
                )
            else:
                # Scan entire repository
                results = await security_scanner.scan_repository(request.repo_url)
        elif request.code_snippet:
            # Scan code snippet
            results = await security_scanner.scan_code(
                request.code_snippet,
                language=request.language
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either repo_url or code_snippet must be provided"
            )
        
        scan_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "language": request.language,
            "scan_results": results,
            "summary": await security_scanner.generate_summary(results)
        }
        
        logger.info(f"Security scan completed for language: {request.language}")
        return scan_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Security scan failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security scan failed: {str(e)}"
        )

@router.get("/analysis/{analysis_id}")
async def get_analysis_results(
    analysis_id: str,
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Retrieve results of a previous analysis.
    
    This endpoint retrieves the results of a previously run analysis by its ID.
    
    Args:
        analysis_id: ID of the analysis to retrieve
        current_user: Current authenticated user
        
    Returns:
        Dict[str, Any]: Analysis results if found
    """
    try:
        # This would typically involve retrieving from a database or cache
        # For now, just return a not implemented error
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Result retrieval not yet implemented"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve analysis results: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve results: {str(e)}"
        )

@router.get("/analysis/search", response_model=List[Dict[str, Any]])
async def search_analyses(
    repository: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = Query(10, ge=1, le=100),
    current_user: Dict = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """
    Search for previous analyses with filtering options.
    
    This endpoint allows searching for analysis results based on repository,
    date range, and other criteria.
    
    Args:
        repository: Optional repository URL to filter by
        start_date: Optional start date (ISO format) for filtering
        end_date: Optional end date (ISO format) for filtering
        limit: Maximum number of results to return (1-100)
        current_user: Current authenticated user
        
    Returns:
        List[Dict[str, Any]]: List of matching analysis results
    """
    try:
        # This would typically involve searching in a database
        # For now, just return a not implemented error
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Search functionality not yet implemented"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis search failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Search failed: {str(e)}"
        )

