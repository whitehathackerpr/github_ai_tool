import os
import shutil
import tempfile
import logging
from typing import Dict, Any, Optional, List
import asyncio
import git
from datetime import datetime

from app.core.config import settings

logger = logging.getLogger(__name__)

class RepositoryAnalyzer:
    """Service for analyzing GitHub repositories."""
    
    def __init__(self):
        """Initialize the repository analyzer."""
        self.temp_dir = settings.TEMP_DIR
        os.makedirs(self.temp_dir, exist_ok=True)
    
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
        """
        repo_dir = None
        try:
            # Create temporary directory
            repo_dir = tempfile.mkdtemp(dir=self.temp_dir)
            logger.info(f"Cloning repository {repo_url} to {repo_dir}")
            
            # Use a subprocess with asyncio to clone the repository asynchronously
            # This avoids blocking the event loop with potentially slow git operations
            clone_cmd = ["git", "clone"]
            if branch:
                clone_cmd.extend(["--branch", branch])
            clone_cmd.extend([repo_url, repo_dir])
            
            # Run the clone operation
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
            
            logger.info(f"Successfully cloned repository: {repo_url}")
            return repo_dir
            
        except Exception as e:
            logger.error(f"Failed to clone repository {repo_url}: {str(e)}")
            # Clean up if clone failed
            if repo_dir and os.path.exists(repo_dir):
                shutil.rmtree(repo_dir, ignore_errors=True)
            raise ValueError(f"Repository cloning failed: {str(e)}")
    
    async def cleanup_repository(self, repo_path: str) -> None:
        """
        Clean up a cloned repository.
        
        Args:
            repo_path: Path to the repository to clean up
        """
        try:
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path, ignore_errors=True)
                logger.info(f"Cleaned up repository: {repo_path}")
        except Exception as e:
            logger.error(f"Failed to clean up repository {repo_path}: {str(e)}")
    
    async def get_repository_info(self, repo_path: str) -> Dict[str, Any]:
        """
        Get basic information about a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dict[str, Any]: Repository information
        """
        try:
            repo = git.Repo(repo_path)
            
            # Get commit information
            latest_commit = repo.head.commit
            
            # Get basic statistics
            stats = {
                "total_files": sum(1 for _ in repo.tree().traverse()),
                "branches": len(repo.refs),
                "active_branch": repo.active_branch.name,
                "total_commits": sum(1 for _ in repo.iter_commits()),
            }
            
            # Get language statistics
            languages = await self._get_language_stats(repo_path)
            
            return {
                "repository_info": {
                    "latest_commit": {
                        "hash": str(latest_commit),
                        "author": str(latest_commit.author),
                        "date": latest_commit.committed_datetime.isoformat(),
                        "message": latest_commit.message.strip()
                    },
                    "statistics": stats,
                    "languages": languages
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get repository info: {str(e)}")
            raise
    
    async def _get_language_stats(self, repo_path: str) -> Dict[str, int]:
        """
        Get language statistics for a repository.
        
        Args:
            repo_path: Path to the repository
            
        Returns:
            Dict[str, int]: Language statistics (bytes per language)
        """
        try:
            # File extension to language mapping
            extension_map = {
                '.py': 'Python',
                '.js': 'JavaScript',
                '.ts': 'TypeScript',
                '.java': 'Java',
                '.cpp': 'C++',
                '.c': 'C',
                '.go': 'Go',
                '.rs': 'Rust',
                '.rb': 'Ruby',
                '.php': 'PHP',
                '.html': 'HTML',
                '.css': 'CSS',
                '.md': 'Markdown'
            }
            
            language_stats = {}
            
            for root, _, files in os.walk(repo_path):
                if '.git' in root:
                    continue
                    
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext in extension_map:
                        lang = extension_map[ext]
                        file_path = os.path.join(root, file)
                        try:
                            size = os.path.getsize(file_path)
                            language_stats[lang] = language_stats.get(lang, 0) + size
                        except OSError:
                            continue
            
            return language_stats
            
        except Exception as e:
            logger.error(f"Failed to get language statistics: {str(e)}")
            return {}
    
    async def generate_analysis_summary(
        self,
        quality_results: Dict[str, Any],
        security_results: Optional[Dict[str, Any]] = None,
        dependency_results: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a summary of all analysis results.
        
        Args:
            quality_results: Results from code quality analysis
            security_results: Optional results from security scan
            dependency_results: Optional results from dependency analysis
            
        Returns:
            Dict[str, Any]: Summary of analysis results
        """
        try:
            summary = {
                "quality_summary": {
                    "total_issues": len(quality_results.get("issues", [])),
                    "critical_issues": sum(1 for issue in quality_results.get("issues", [])
                                        if issue.get("severity") == "critical"),
                    "major_issues": sum(1 for issue in quality_results.get("issues", [])
                                    if issue.get("severity") == "major"),
                    "minor_issues": sum(1 for issue in quality_results.get("issues", [])
                                    if issue.get("severity") == "minor")
                }
            }
            
            if security_results:
                summary["security_summary"] = {
                    "total_vulnerabilities": security_results.get("vulnerability_count", 0),
                    "high_severity": security_results.get("high_severity_count", 0),
                    "medium_severity": security_results.get("medium_severity_count", 0),
                    "low_severity": security_results.get("low_severity_count", 0)
                }
            
            if dependency_results:
                summary["dependency_summary"] = {
                    "total_dependencies": dependency_results.get("total_dependencies", 0),
                    "outdated_dependencies": dependency_results.get("outdated_count", 0),
                    "vulnerable_dependencies": dependency_results.get("vulnerable_count", 0)
                }
            
            # Generate risk score based on issues and vulnerabilities
            # Higher score means higher risk (0-100 scale)
            risk_score = 0
            
            # Calculate quality risk (0-40 points)
            total_issues = summary["quality_summary"]["total_issues"]
            critical_issues = summary["quality_summary"]["critical_issues"]
            major_issues = summary["quality_summary"]["major_issues"]
            
            # Weight issues by severity
            quality_score = min(40, (critical_issues * 5 + major_issues * 2 + total_issues * 0.5))
            risk_score += quality_score
            
            # Calculate security risk (0-60 points)
            if "security_summary" in summary:
                high_vulns = summary["security_summary"]["high_severity"]
                medium_vulns = summary["security_summary"]["medium_severity"]
                total_vulns = summary["security_summary"]["total_vulnerabilities"]
                
                # Weight vulnerabilities by severity
                security_score = min(60, (high_vulns * 10 + medium_vulns * 3 + total_vulns))
                risk_score += security_score
            
            # Add overall summary
            summary["overall_summary"] = {
                "risk_score": round(risk_score, 1),
                "risk_level": "High" if risk_score > 70 else "Medium" if risk_score > 30 else "Low",
                "timestamp": datetime.utcnow().isoformat(),
                "total_issues_and_vulnerabilities": (
                    total_issues + 
                    (summary.get("security_summary", {}).get("total_vulnerabilities", 0))
                )
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to generate analysis summary: {str(e)}")
            return {
                "error": "Failed to generate summary",
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

import os
import logging
from typing import Dict, Any, List, Tuple
from git import Repo
from collections import Counter, defaultdict
import re
import datetime

logger = logging.getLogger(__name__)

class RepositoryAnalyzer:
    """Analyzes GitHub repositories to extract useful metrics and insights."""
    
    def __init__(self, repo_path: str = None, repo_url: str = None):
        """Initialize with either a local repo path or a remote URL."""
        self.repo_path = repo_path
        self.repo_url = repo_url
        self.repo = None
        
    async def clone_repository(self, target_path: str) -> str:
        """Clone a repository if URL is provided."""
        if not self.repo_url:
            raise ValueError("Repository URL is required for cloning")
        
        try:
            logger.info(f"Cloning repository from {self.repo_url} to {target_path}")
            self.repo = Repo.clone_from(self.repo_url, target_path)
            self.repo_path = target_path
            return target_path
        except Exception as e:
            logger.error(f"Failed to clone repository: {str(e)}")
            raise
    
    async def load_repository(self) -> Repo:
        """Load a repository object from the repo path."""
        if not self.repo_path:
            raise ValueError("Repository path is required")
        
        try:
            logger.info(f"Loading repository from {self.repo_path}")
            self.repo = Repo(self.repo_path)
            return self.repo
        except Exception as e:
            logger.error(f"Failed to load repository: {str(e)}")
            raise
    
    async def get_contributor_stats(self) -> List[Dict[str, Any]]:
        """Get contributor statistics."""
        if not self.repo:
            await self.load_repository()
        
        try:
            contributors = []
            commit_counts = {}
            
            for commit in self.repo.iter_commits():
                name = commit.author.name
                email = commit.author.email
                date = commit.committed_datetime
                
                # Find existing contributor or create new one
                contributor_key = f"{name}:{email}"
                if contributor_key in commit_counts:
                    commit_counts[contributor_key]['commits'] += 1
                    commit_counts[contributor_key]['last_commit'] = max(
                        commit_counts[contributor_key]['last_commit'], 
                        date
                    )
                    commit_counts[contributor_key]['first_commit'] = min(
                        commit_counts[contributor_key]['first_commit'], 
                        date
                    )
                else:
                    commit_counts[contributor_key] = {
                        'name': name,
                        'email': email,
                        'commits': 1,
                        'first_commit': date,
                        'last_commit': date
                    }
            
            # Convert to list and calculate days active
            for contributor_data in commit_counts.values():
                delta = contributor_data['last_commit'] - contributor_data['first_commit']
                contributor_data['days_active'] = delta.days + 1
                
                # Convert datetime to string for JSON serialization
                contributor_data['first_commit'] = contributor_data['first_commit'].isoformat()
                contributor_data['last_commit'] = contributor_data['last_commit'].isoformat()
                
                contributors.append(contributor_data)
            
            return contributors
        except Exception as e:
            logger.error(f"Failed to get contributor stats: {str(e)}")
            raise
    
    async def get_commit_frequency(self) -> Dict[str, int]:
        """Get commit frequency over time."""
        if not self.repo:
            await self.load_repository()
        
        try:
            frequency = defaultdict(int)
            for commit in self.repo.iter_commits():
                date_str = commit.committed_datetime.strftime('%Y-%m-%d')
                frequency[date_str] += 1
            
            return dict(frequency)
        except Exception as e:
            logger.error(f"Failed to get commit frequency: {str(e)}")
            raise
    
    async def get_file_type_distribution(self) -> Dict[str, int]:
        """Get distribution of file types in the repository."""
        if not self.repo:
            await self.load_repository()
        
        try:
            file_types = Counter()
            for root, _, files in os.walk(self.repo_path):
                if '.git' in root:
                    continue
                
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext:
                        file_types[ext] += 1
                    else:
                        file_types['no_extension'] += 1
            
            return dict(file_types)
        except Exception as e:
            logger.error(f"Failed to get file type distribution: {str(e)}")
            raise
    
    async def get_code_complexity_metrics(self) -> Dict[str, Any]:
        """Get code complexity metrics."""
        if not self.repo:
            await self.load_repository()
        
        try:
            # This is a simplified implementation
            # In a real implementation, you might use tools like radon or lizard
            metrics = {
                'avg_file_size': 0,
                'max_file_size': 0,
                'total_files': 0,
                'total_lines': 0,
                'avg_function_length': 0,
                'max_function_length': 0,
                'total_functions': 0
            }
            
            file_sizes = []
            total_files = 0
            total_lines = 0
            
            function_pattern = re.compile(r'(def|function|class|\w+\s*=\s*function)\s+\w+\s*\(')
            function_lengths = []
            
            for root, _, files in os.walk(self.repo_path):
                if '.git' in root:
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.readlines()
                            
                            file_size = len(content)
                            file_sizes.append(file_size)
                            total_files += 1
                            total_lines += file_size
                            
                            content_str = ''.join(content)
                            functions = function_pattern.findall(content_str)
                            
                            if functions:
                                # Simple heuristic: estimate function length as 10 lines
                                function_lengths.extend([10] * len(functions))
                    except Exception:
                        # Skip files that can't be read
                        pass
            
            if file_sizes:
                metrics['avg_file_size'] = sum(file_sizes) / len(file_sizes)
                metrics['max_file_size'] = max(file_sizes)
                metrics['total_files'] = total_files
                metrics['total_lines'] = total_lines
            
            if function_lengths:
                metrics['avg_function_length'] = sum(function_lengths) / len(function_lengths)
                metrics['max_function_length'] = max(function_lengths)
                metrics['total_functions'] = len(function_lengths)
            
            return metrics
        except Exception as e:
            logger.error(f"Failed to get code complexity metrics: {str(e)}")
            raise
    
    async def analyze_repository(self) -> Dict[str, Any]:
        """Perform comprehensive repository analysis."""
        try:
            if not self.repo:
                await self.load_repository()
            
            return {
                'contributor_stats': await self.get_contributor_stats(),
                'commit_frequency': await self.get_commit_frequency(),
                'file_type_distribution': await self.get_file_type_distribution(),
                'code_complexity_metrics': await self.get_code_complexity_metrics()
            }
        except Exception as e:
            logger.error(f"Failed to analyze repository: {str(e)}")
            raise

import os
import logging
from typing import Dict, Any, List, Tuple
from git import Repo
from collections import Counter, defaultdict
import re
import datetime

logger = logging.getLogger(__name__)

class RepositoryAnalyzer:
    """Analyzes GitHub repositories to extract useful metrics and insights."""
    
    def __init__(self, repo_path: str = None, repo_url: str = None):
        """Initialize with either a local repo path or a remote URL."""
        self.repo_path = repo_path
        self.repo_url = repo_url
        self.repo = None
        
    async def clone_repository(self, target_path: str) -> str:
        """Clone a repository if URL is provided."""
        if not self.repo_url:
            raise ValueError("Repository URL is required for cloning")
        
        try:
            logger.info(f"Cloning repository from {self.repo_url} to {target_path}")
            self.repo = Repo.clone_from(self.repo_url, target_path)
            self.repo_path = target_path
            return target_path
        except Exception as e:
            logger.error(f"Failed to clone repository: {str(e)}")
            raise
    
    async def load_repository(self) -> Repo:
        """Load a repository object from the repo path."""
        if not self.repo_path:
            raise ValueError("Repository path is required")
        
        try:
            logger.info(f"Loading repository from {self.repo_path}")
            self.repo = Repo(self.repo_path)
            return self.repo
        except Exception as e:
            logger.error(f"Failed to load repository: {str(e)}")
            raise
    
    async def get_contributor_stats(self) -> List[Dict[str, Any]]:
        """Get contributor statistics."""
        if not self.repo:
            await self.load_repository()
        
        try:
            contributors = []
            for commit in self.repo.iter_commits():
                name = commit.author.name
                email = commit.author.email
                date = commit.committed_datetime
                
                # Find existing contributor or create new one
                contributor = next((c for c in contributors if c['email'] == email), None)
                if contributor:
                    contributor['commits'] += 1
                    contributor['last_commit'] = max(contributor['last_commit'], date)
                    contributor['first_commit'] = min(contributor['first_commit'], date)
                else:
                    contributors.append({
                        'name': name,
                        'email': email,
                        'commits': 1,
                        'first_commit': date,
                        'last_commit': date
                    })
            
            # Calculate days active
            for contributor in contributors:
                delta = contributor['last_commit'] - contributor['first_commit']
                contributor['days_active'] = delta.days + 1
                
                # Convert datetime to string for JSON serialization
                contributor['first_commit'] = contributor['first_commit'].isoformat()
                contributor['last_commit'] = contributor['last_commit'].isoformat()
            
            return contributors
        except Exception as e:
            logger.error(f"Failed to get contributor stats: {str(e)}")
            raise
    
    async def get_commit_frequency(self) -> Dict[str, int]:
        """Get commit frequency over time."""
        if not self.repo:
            await self.load_repository()
        
        try:
            frequency = defaultdict(int)
            for commit in self.repo.iter_commits():
                date_str = commit.committed_datetime.strftime('%Y-%m-%d')
                frequency[date_str] += 1
            
            return dict(frequency)
        except Exception as e:
            logger.error(f"Failed to get commit frequency: {str(e)}")
            raise
    
    async def get_file_type_distribution(self) -> Dict[str, int]:
        """Get distribution of file types in the repository."""
        if not self.repo:
            await self.load_repository()
        
        try:
            file_types = Counter()
            for root, _, files in os.walk(self.repo_path):
                if '.git' in root:
                    continue
                
                for file in files:
                    ext = os.path.splitext(file)[1].lower()
                    if ext:
                        file_types[ext] += 1
                    else:
                        file_types['no_extension'] += 1
            
            return dict(file_types)
        except Exception as e:
            logger.error(f"Failed to get file type distribution: {str(e)}")
            raise
    
    async def get_code_complexity_metrics(self) -> Dict[str, Any]:
        """Get code complexity metrics."""
        if not self.repo:
            await self.load_repository()
        
        try:
            # This is a simplified implementation
            # In a real implementation, you might use tools like radon or lizard
            metrics = {
                'avg_file_size': 0,
                'max_file_size': 0,
                'total_files': 0,
                'total_lines': 0,
                'avg_function_length': 0,
                'max_function_length': 0,
                'total_functions': 0
            }
            
            file_sizes = []
            total_files = 0
            total_lines = 0
            
            function_pattern = re.compile(r'(def|function|class|\w+\s*=\s*function)\s+\w+\s*\(')
            function_lengths = []
            
            for root, _, files in os.walk(self.repo_path):
                if '.git' in root:
                    continue
                
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.readlines()
                            
                            file_size = len(content)
                            file_sizes.append(file_size)
                            total_files += 1
                            total_lines += file_size
                            
                            content_str = ''.join(content)
                            functions = function_pattern.findall(content_str)
                            
                            if functions:
                                # Simple heuristic: estimate function length as 10 lines
                                function_lengths.extend([10] * len(functions))
                    except Exception:
                        # Skip files that can't be read
                        pass
            
            if file_sizes:
                metrics['avg_file_size'] = sum(file_sizes) / len(file_sizes)
                metrics['max_file_size'] = max(file_sizes)
                metrics['total_files'] = total_files
                metrics['total_lines'] = total_lines
            
            if function_lengths:
                metrics['avg_function_length'] = sum(function_lengths) / len(function_lengths)
                metrics['max_function_length'] = max(function_lengths)
                metrics['total_functions'] = len(function_lengths)
            
            return metrics
        except Exception as e:
            logger.error(f"Failed to get code complexity metrics: {str(e)}")
            raise
    
    async def analyze_repository(self) -> Dict[str, Any]:
        """Perform comprehensive repository analysis."""
        try:
            if not self.repo:
                await self.load_repository()
            
            return {
                'contributor_stats': await self.get_contributor_stats(),
                'commit_frequency': await self.get_commit_frequency(),
                'file_type_distribution': await self.get_file_type_distribution(),
                'code_complexity_metrics': await self.get_code_complexity_metrics()
            }
        except Exception as e:
            logger.error(f"Failed to analyze repository: {str(e)}")
            raise

