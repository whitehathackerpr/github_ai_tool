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

