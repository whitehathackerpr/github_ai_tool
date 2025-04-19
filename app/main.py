import os
from typing import Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="GitHub AI Tool",
    description="AI-powered tool for GitHub repository analysis, code review, documentation generation, and issue/PR summarization",
    version="0.1.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class RepositoryRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = "main"


class CodeReviewRequest(BaseModel):
    repo_url: str
    pull_request_number: Optional[int] = None
    file_path: Optional[str] = None
    code_snippet: Optional[str] = None


class DocumentationRequest(BaseModel):
    repo_url: str
    file_path: Optional[str] = None
    directory_path: Optional[str] = None


class IssueRequest(BaseModel):
    repo_url: str
    issue_number: int


# Routes
@app.get("/")
async def root():
    return {"message": "Welcome to GitHub AI Tool API. Visit /docs for documentation."}


# Authentication routes
@app.get("/auth/login")
async def login():
    """
    Redirects user to GitHub OAuth login page
    """
    github_client_id = os.getenv("GITHUB_CLIENT_ID")
    if not github_client_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub client ID not configured",
        )
    
    redirect_uri = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&scope=repo user"
    return RedirectResponse(url=redirect_uri)


@app.get("/auth/callback")
async def callback(code: str):
    """
    Handles GitHub OAuth callback and exchanges code for access token
    """
    try:
        github_client_id = os.getenv("GITHUB_CLIENT_ID")
        github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
        
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
            # In a real application, you would store this token securely and use it for API requests
            # You would also create a session for the user
            
            # For demo purposes, just return success
            return {"message": "Authentication successful"}
    
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Authentication error: {str(e)}",
        )


# GitHub AI feature routes
@app.post("/repos/analyze")
async def analyze_repository(request: RepositoryRequest):
    """
    Analyzes a GitHub repository structure and provides insights
    """
    # TODO: Implement repository analysis with AI
    return {"message": "Repository analysis feature will be implemented here"}


@app.post("/repos/review")
async def review_code(request: CodeReviewRequest):
    """
    Provides AI-powered code review for a pull request or code snippet
    """
    # TODO: Implement code review with AI
    return {"message": "Code review feature will be implemented here"}


@app.post("/repos/documentation")
async def generate_documentation(request: DocumentationRequest):
    """
    Generates documentation for a repository, file, or directory
    """
    # TODO: Implement documentation generation with AI
    return {"message": "Documentation generation feature will be implemented here"}


@app.post("/repos/issues/summarize")
async def summarize_issue(request: IssueRequest):
    """
    Summarizes GitHub issues or PRs
    """
    # TODO: Implement issue summarization with AI
    return {"message": "Issue summarization feature will be implemented here"}


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

