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
                "analysis_metadata": {
                    "timestamp": analysis_start.isoformat(),
                    "duration_seconds": round((datetime.utcnow() - analysis_start).total_seconds(), 2),
                    "analyzer_version": "1.0.0"
                }
            }
            
            # Add summary statistics
            analysis_results["summary"] = {
                "total_files": file_distribution["totals"]["files"],
                "total_lines": file_distribution["totals"]["lines"],
                "total_size_bytes": file_distribution["totals"]["size"],
                "active_contributors": len(contributor_stats),
                "total_commits": repo_info["commits_count"],
                "primary_language": max(
                    file_distribution["by_language"].items(),
                    key=lambda x: x[1]["lines"],
                    default=("Unknown", {"lines": 0})
                )[0],
                "code_quality": {
                    "comment_ratio": round(
                        code_metrics["file_metrics"]["comment_lines"] / 
                        max(1, code_metrics["file_metrics"]["total_lines"]) * 100,
                        2
                    ),
                    "average_file_size": code_metrics["file_metrics"]["avg_file_size"],
                    "complexity_score": code_metrics["complexity_metrics"]["avg_complexity_per_file"]
                }
            }
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Failed to analyze repository: {str(e)}")
            raise
            branches = []
            for branch in self.repo.refs:
                if not isinstance(branch, type(self.repo.head)):
                    continue
                branch_info = {
                    "name": branch.name,
                    "is_active": branch.name == default_branch,
                    "last_commit": {
                        "hash": str(branch.commit),
                        "message": branch.commit.message.strip(),
                        "date": branch.commit.committed_datetime.isoformat()
                    }
                }
                branches.append(branch_info)
            
            repo_info["branches"] = branches
            
            # Get file and language statistics
            file_stats = await self.get_file_distribution()
            repo_info["file_stats"] = file_stats
            
            return repo_info
            
        except Exception as e:
            logger.error(f"Failed to get repository info: {str(e)}")
            raise
    
    async def get_file_distribution(self) -> Dict[str, Any]:
        """
        Get detailed statistics about file types and languages in the repository.
        
        Returns:
            Dict[str, Any]: File and language distribution statistics
        """
        try:
            stats = {
                "by_extension": defaultdict(lambda: {"count": 0, "size": 0, "lines": 0}),
                "by_language": defaultdict(lambda: {"count": 0, "size": 0, "lines": 0}),
                "totals": {"files": 0, "size": 0, "lines": 0}
            }
            
            # Process all files in repository
            for root, _, files in os.walk(self.repo_path):
                if '.git' in root:
                    continue
                    
                for filename in files:
                    try:
                        file_path = os.path.join(root, filename)
                        ext = os.path.splitext(filename)[1].lower()
                        
                        # Get file size
                        size = os.path.getsize(file_path)
                        
                        # Try to count lines for text files
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                lines = sum(1 for _ in f)
                        except (UnicodeDecodeError, IOError):
                            lines = 0
                            
                        # Update extension statistics
                        stats["by_extension"][ext or "no_extension"].update({
                            "count": stats["by_extension"][ext or "no_extension"]["count"] + 1,
                            "size": stats["by_extension"][ext or "no_extension"]["size"] + size,
                            "lines": stats["by_extension"][ext or "no_extension"]["lines"] + lines
                        })
                        
                        # Update language statistics if extension is mapped
                        if ext in self.language_map:
                            lang = self.language_map[ext]
                            stats["by_language"][lang].update({
                                "count": stats["by_language"][lang]["count"] + 1,
                                "size": stats["by_language"][lang]["size"] + size,
                                "lines": stats["by_language"][lang]["lines"] + lines
                            })
                        
                        # Update totals
                        stats["totals"]["files"] += 1
                        stats["totals"]["size"] += size
                        stats["totals"]["lines"] += lines
                        
                    except Exception as e:
                        logger.debug(f"Error processing file {filename}: {str(e)}")
                        continue
            
            # Calculate percentages
            total_size = stats["totals"]["size"] or 1  # Avoid division by zero
            total_lines = stats["totals"]["lines"] or 1
            
            for lang_stats in stats["by_language"].values():
                lang_stats["size_percentage"] = round((lang_stats["size"] / total_size) * 100, 2)
                lang_stats["lines_percentage"] = round((lang_stats["lines"] / total_lines) * 100, 2)
            
            # Convert defaultdict to regular dict for JSON serialization
            return {
                "by_extension": dict(stats["by_extension"]),
                "by_language": dict(stats["by_language"]),
                "totals": stats["totals"]
            }
            
        except Exception as e:
            logger.error(f"Failed to get file distribution: {str(e)}")
            raise
    
    async def get_contributor_stats(self) -> List[Dict[str, Any]]:
        """
        Get detailed statistics about repository contributors.
        
        Returns:
            List[Dict[str, Any]]: List of contributor statistics
        """
        try:
            contributors = defaultdict(lambda: {
                "name": "",
                "email": "",
                "commits": 0,
                "lines_added": 0,
                "lines_deleted": 0,
                "files_changed": set(),
                "first_commit": datetime.max,
                "last_commit": datetime.min
            })
            
            for commit in self.repo.iter_commits():
                email = commit.author.email
                contrib = contributors[email]
                
                # Update basic stats
                contrib["name"] = commit.author.name
                contrib["email"] = email
                contrib["commits"] += 1
                contrib["first_commit"] = min(contrib["first_commit"], commit.committed_datetime)
                contrib["last_commit"] = max(contrib["last_commit"], commit.committed_datetime)
                
                # Update detailed stats if available
                if hasattr(commit, "stats"):
                    contrib["lines_added"] += commit.stats.total.get("insertions", 0)
                    contrib["lines_deleted"] += commit.stats.total.get("deletions", 0)
                    contrib["files_changed"].update(commit.stats.files.keys())
            
            # Process and format contributor data for JSON serialization
            result = []
            for email, data in contributors.items():
                # Calculate time span of contribution
                delta = data["last_commit"] - data["first_commit"]
                days_active = max(1, delta.days)  # Ensure at least 1 day
                
                # Format dates for output
                first_commit = data["first_commit"].isoformat() if data["first_commit"] != datetime.max else None
                last_commit = data["last_commit"].isoformat() if data["last_commit"] != datetime.min else None
                
                # Create contributor entry
                contributor = {
                    "name": data["name"],
                    "email": email,
                    "commits": data["commits"],
                    "lines_added": data["lines_added"],
                    "lines_deleted": data["lines_deleted"],
                    "files_changed": len(data["files_changed"]),
                    "days_active": days_active,
                    "first_commit": first_commit,
                    "last_commit": last_commit,
                    "commits_per_day": round(data["commits"] / days_active, 2)
                }
                result.append(contributor)
            
            # Sort by number of commits (most active contributors first)
            return sorted(result, key=lambda x: x["commits"], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to get contributor stats: {str(e)}")
            raise
    
    async def get_code_complexity_metrics(self) -> Dict[str, Any]:
        """
        Calculate basic code complexity metrics for the repository.
        
        Returns:
            Dict[str, Any]: Code complexity metrics
        """
        try:
            metrics = {
                "file_metrics": {
                    "total_files": 0,
                    "total_lines": 0,
                    "code_lines": 0,
                    "comment_lines": 0,
                    "blank_lines": 0,
                    "avg_file_size": 0,
                    "max_file_size": 0
                },
                "function_metrics": {
                    "total_functions": 0,
                    "avg_function_length": 0,
                    "max_function_length": 0
                },
                "complexity_metrics": {
                    "cyclomatic_complexity": 0,
                    "nested_blocks": 0
                }
            }
            
            # Regex patterns for code analysis
            patterns = {
                "function": re.compile(r'(def|function|class|\w+\s*=\s*function)\s+\w+\s*\('),
                "comment": re.compile(r'^\s*(#|//|/\*|\*|\'\'\'|""").*'),
                "complexity": re.compile(r'\b(if|else|for|while|try|catch|switch|case)\b')
            }
            
            file_sizes = []
            function_lengths = []
            complexity_scores = []
            
            # Process code files
            for root, _, files in os.walk(self.repo_path):
                if '.git' in root:
                    continue
                
                for filename in files:
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in ['.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.cs', '.go', '.rb', '.php']:
                        continue
                    
                    try:
                        file_path = os.path.join(root, filename)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.readlines()
                            content_str = ''.join(content)
                            
                            # Basic file metrics
                            file_size = len(content)
                            file_sizes.append(file_size)
                            
                            # Line classification
                            blank_lines = sum(1 for line in content if not line.strip())
                            comment_lines = sum(1 for line in content if patterns["comment"].match(line))
                            code_lines = file_size - (blank_lines + comment_lines)
                            
                            # Update metrics
                            metrics["file_metrics"]["blank_lines"] += blank_lines
                            metrics["file_metrics"]["comment_lines"] += comment_lines
                            metrics["file_metrics"]["code_lines"] += code_lines
                            
                            # Function analysis
                            functions = list(patterns["function"].finditer(content_str))
                            metrics["function_metrics"]["total_functions"] += len(functions)
                            
                            # Calculate function lengths
                            for i, match in enumerate(functions):
                                start = match.start()
                                end = functions[i+1].start() if i+1 < len(functions) else len(content_str)
                                length = content_str[start:end].count('\n')
                                function_lengths.append(length)
                            
                            # Complexity metrics
                            complexity_count = len(patterns["complexity"].findall(content_str))
                            complexity_scores.append(complexity_count)
                            metrics["complexity_metrics"]["cyclomatic_complexity"] += complexity_count
                            
                    except Exception as e:
                        logger.debug(f"Error analyzing file {filename}: {str(e)}")
                        continue
            
            # Calculate summary metrics
            if file_sizes:
                metrics["file_metrics"].update({
                    "total_files": len(file_sizes),
                    "total_lines": sum(file_sizes),
                    "avg_file_size": round(sum(file_sizes) / len(file_sizes), 2),
                    "max_file_size": max(file_sizes)
                })
            
            if function_lengths:
                metrics["function_metrics"].update({
                    "avg_function_length": round(sum(function_lengths) / len(function_lengths), 2),
                    "max_function_length": max(function_lengths)
                })
            
            # Calculate averages
            metrics["complexity_metrics"]["avg_complexity_per_file"] = round(
                metrics["complexity_metrics"]["cyclomatic_complexity"] / max(1, metrics["file_metrics"]["total_files"]), 
                2
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to calculate code complexity metrics: {str(e)}")
            raise
    
    async def analyze_repository(self) -> Dict[str, Any]:
        """
        Perform comprehensive repository analysis.
        
        This method combines various analysis techniques to provide a complete
        assessment of the repository's structure, content, and quality.
        
        Returns:
            Dict[str, Any]: Complete analysis results
        """
        try:
            analysis_start = datetime.utcnow()
            
            # Perform various analyses
            repo_info = await self.get_repository_info()
            contributor_stats = await self.get_contributor_stats()
            file_distribution = await self.get_file_distribution()
            code_metrics = await self.get_code_complexity_metrics()
            
            # Compile results
            analysis_results = {
                "repository_info": repo_info,
                "contributor_stats": contributor_stats,
                "file_distribution": file_distribution,
                "code_metrics": code_metrics,
                "analysis_metadata": {
                    "timestamp": analysis_start.isoformat(),
                    "duration_seconds": round((datetime.utcnow() - analysis_start).total_seconds(), 2),
                    "analyzer_version": "1.0.0"
                
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

