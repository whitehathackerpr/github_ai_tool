import os
import shutil
import tempfile
import logging
from typing import Dict, Any, List, Optional
from git import Repo
from collections import Counter, defaultdict
import re
from datetime import datetime
import asyncio

from app.core.config import settings

logger = logging.getLogger(__name__)

class RepositoryAnalyzer:
    """Analyzes GitHub repositories to extract useful metrics and insights."""
    
    def __init__(self):
        """Initialize the repository analyzer."""
        self.repo_path = None
        self.repo_url = None
        self.repo = None
        self.temp_dir = settings.TEMP_DIR
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # File extension to language mapping
        self.language_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.jsx': 'JavaScript React',
            '.ts': 'TypeScript',
            '.tsx': 'TypeScript React',
            '.java': 'Java',
            '.cpp': 'C++',
            '.hpp': 'C++ Header',
            '.c': 'C',
            '.h': 'C/C++ Header',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.cs': 'C#',
            '.scala': 'Scala',
            '.kt': 'Kotlin',
            '.swift': 'Swift',
            '.m': 'Objective-C',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SCSS',
            '.sass': 'Sass',
            '.sql': 'SQL',
            '.sh': 'Shell',
            '.bash': 'Shell',
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.json': 'JSON',
            '.md': 'Markdown',
            '.xml': 'XML',
            '.txt': 'Text'
        }
    
    async def clone_repository(
        self,
        repo_url: str,
        branch: Optional[str] = None
    ) -> str:
        """
        Clone a GitHub repository to a temporary directory.
        
        Args:
            repo_url: URL of the repository to clone
            branch: Optional branch name to checkout
            
        Returns:
            str: Path to the cloned repository
            
        Raises:
            ValueError: If repository cloning fails
        """
        self.repo_url = repo_url
        repo_dir = None
        
        try:
            # Create temporary directory
            repo_dir = tempfile.mkdtemp(dir=self.temp_dir)
            logger.info(f"Cloning repository {repo_url} to {repo_dir}")
            
            # Use asyncio subprocess for non-blocking clone
            clone_cmd = ["git", "clone"]
            if branch:
                clone_cmd.extend(["--branch", branch])
            clone_cmd.extend([repo_url, repo_dir])
            
            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                logger.error(f"Git clone failed: {error_msg}")
                raise ValueError(f"Failed to clone repository: {error_msg}")
            
            self.repo_path = repo_dir
            
            # Load repository
            self.repo = Repo(repo_dir)
            
            logger.info(f"Successfully cloned repository: {repo_url}")
            return repo_dir
            
        except Exception as e:
            logger.error(f"Failed to clone repository {repo_url}: {str(e)}")
            if repo_dir and os.path.exists(repo_dir):
                shutil.rmtree(repo_dir, ignore_errors=True)
            raise ValueError(f"Repository cloning failed: {str(e)}")
    
    async def cleanup_repository(self) -> None:
        """
        Clean up the cloned repository.
        
        Removes the temporary directory containing the repository clone.
        """
        try:
            if self.repo_path and os.path.exists(self.repo_path):
                shutil.rmtree(self.repo_path, ignore_errors=True)
                logger.info(f"Cleaned up repository: {self.repo_path}")
                self.repo_path = None
                self.repo = None
        except Exception as e:
            logger.error(f"Failed to clean up repository: {str(e)}")
    
    async def get_repository_info(self) -> Dict[str, Any]:

