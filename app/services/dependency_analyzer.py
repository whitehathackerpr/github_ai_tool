import os
import logging
import json
import re
import subprocess
import tempfile
from typing import Dict, Any, List, Optional, Tuple
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

class DependencyAnalyzer:
    """Analyzes project dependencies and suggests updates."""
    
    def __init__(self):
        """Initialize dependency analyzer."""
        self.pypi_url = "https://pypi.org/pypi/{package}/json"
        self.npm_url = "https://registry.npmjs.org/{package}"
    
    async def analyze_python_dependencies(self, requirements_content: str) -> Dict[str, Any]:
        """Analyze Python dependencies in a requirements.txt file."""
        try:
            dependencies = []
            outdated = []
            vulnerable = []
            
            # Parse requirements.txt content
            for line in requirements_content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Extract package name and version
                match = re.match(r'^([a-zA-Z0-9_\-\.]+)([<>=!~]+)?([\d\.\*]+)?', line)
                if match:
                    package = match.group(1)
                    operator = match.group(2) or ''
                    version = match.group(3) or ''
                    
                    package_info = {
                        'name': package,
                        'current_version': version,
                        'constraint': operator,
                        'latest_version': '',
                        'is_outdated': False,
                        'is_vulnerable': False
                    }
                    
                    # Get latest version from PyPI
                    try:
                        response = requests.get(self.pypi_url.format(package=package), timeout=5)
                        if response.status_code == 200:
                            data = response.json()
                            latest_version = data.get('info', {}).get('version', '')
                            release_date = None
                            
                            # Get release date
                            releases = data.get('releases', {})
                            if latest_version in releases:
                                release_info = releases[latest_version]
                                if release_info and isinstance(release_info, list) and len(release_info) > 0:
                                    upload_time = release_info[0].get('upload_time')
                                    if upload_time:
                                        release_date = upload_time
                            
                            package_info['latest_version'] = latest_version
                            package_info['release_date'] = release_date
                            
                            # Check if outdated
                            if version and latest_version and version != latest_version:
                                package_info['is_outdated'] = True
                                outdated.append(package_info.copy())
                    except Exception as e:
                        logger.warning(f"Failed to get latest version for {package}: {str(e)}")
                    
                    dependencies.append(package_info)
            
            # Check for safety issues using pip-audit (simulated)
            try:
                with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as temp:
                    temp.write(requirements_content.encode('utf-8'))
                    temp_path = temp.name
                
                # This would normally call pip-audit or safety check
                # For demo purposes, we'll simulate the response
                for package_info in dependencies:
                    # Simulate: Let's pretend 5% of packages have vulnerabilities
                    import random
                    if random.random() < 0.05:
                        package_info['is_vulnerable'] = True
                        vulnerable.append(package_info.copy())
                
                # Clean up
                os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Failed to check vulnerabilities: {str(e)}")
            
            return {
                'dependencies': dependencies,
                'dependency_count': len(dependencies),
                'outdated_count': len(outdated),
                'outdated': outdated,
                'vulnerable_count': len(vulnerable),
                'vulnerable': vulnerable
            }
        except Exception as e:
            logger.error(f"Failed to analyze Python dependencies: {str(e)}")
            return {'error': str(e)}
    
    async def analyze_node_dependencies(self, package_json_content: str) -> Dict[str, Any]:
        """Analyze Node.js dependencies in a package.json file."""
        try:
            dependencies = []
            outdated = []
            vulnerable = []
            
            # Parse package.json content
            try:
                data = json.loads(package_json_content)
                deps = {}
                
                # Combine dependencies and devDependencies
                if 'dependencies' in data and isinstance(data['dependencies'], dict):
                    deps.update(data['dependencies'])
                
                if 'devDependencies' in data and isinstance(data['devDependencies'], dict):
                    deps.update(data['devDependencies'])
                
                # Analyze each dependency
                for package, version in deps.items():
                    # Strip version constraints
                    clean_version = re.sub(r'^[~^]', '', version)
                    
                    package_info = {
                        'name': package,
                        'current_version': clean_version,
                        'constraint': version[0] if version[0] in ['~', '^'] else '',
                        'latest_version': '',
                        'is_outdated': False,
                        'is_vulnerable': False,
                        'is_dev': package in data.get('devDependencies', {})
                    }
                    
                    # Get latest version from npm registry
                    try:
                        response = requests.get(self.npm_url.format(package=package), timeout=5)
                        if response.status_code == 200:
                            npm_data = response.json()
                            latest_version = npm_data.get('dist-tags', {}).get('latest', '')
                            
                            if latest_version:
                                package_info['latest_version'] = latest_version
                                
                                # Check if outdated
                                if clean_version and clean_version != latest_version:
                                    package_info['is_outdated'] = True
                                    outdated.append(package_info.copy())
                    except Exception as e:
                        logger.warning(f"Failed to get latest version for {package}: {str(e)}")
                    
                    dependencies.append(package_info)
            except json.JSONDecodeError as e:
                return {'error': f"Invalid package.json format: {str(e)}"}
            
            # Check for vulnerabilities using npm audit (simulated)
            try:
                # This would normally call npm audit
                # For demo purposes, we'll simulate the response
                for package_info in dependencies:
                    # Simulate: Let's pretend 5% of packages have vulnerabilities
                    import random
                    if random.random() < 0.05:
                        package_info['is_vulnerable'] = True
                        vulnerable.append(package_info.copy())
            except Exception as e:
                logger.warning(f"Failed to check vulnerabilities: {str(e)}")
            
            return {
                'dependencies': dependencies,
                'dependency_count': len(dependencies),
                'outdated_count': len(outdated),
                'outdated': outdated,
                'vulnerable_count': len(vulnerable),
                'vulnerable': vulnerable
            }
        except Exception as e:
            logger.error(f"Failed to analyze Node.js dependencies: {str(e)}")
            return {'error': str(e)}
    
    async def analyze_project_dependencies(self, repo_path: str) -> Dict[str, Any]:
        """Analyze dependencies in a project directory."""
        try:
            results = {
                'python': None,
                'node': None,
                'other': []
            }
            
            # Check for Python dependencies
            requirements_files = ['requirements.txt', 'requirements-dev.txt', 'dev-requirements.txt']
            for req_file in requirements_files:
                req_path = os.path.join(repo_path, req_file)
                if os.path.exists(req_path):
                    with open(req_path, 'r') as f:
                        content = f.read()
                    results['python'] = {
                        'file': req_file,
                        'analysis': await self.analyze_python_dependencies(content)
                    }
                    break
            
            # Check for Pipenv
            pipfile_path = os.path.join(repo_path, 'Pipfile')
            if os.path.exists(pipfile_path) and not results['python']:
                results['other'].append({
                    'type': 'pipenv',
                    'file': 'Pipfile',
                    'message': 'Pipenv dependencies found. Detailed analysis not implemented.'
                })
            
            # Check for Poetry
            pyproject_path = os.path.join(repo_path, 'pyproject.toml')
            if os.path.exists(pyproject_path) and not results['python']:
                results['other'].append({
                    'type': 'poetry',
                    'file': 'pyproject.toml',
                    'message': 'Poetry dependencies found. Detailed analysis not implemented.'
                })
            
            # Check for Node.js dependencies
            package_json_path = os.path.join(repo_path, 'package.json')
            if os.path.exists(package_json_path):
                with open(package_json_path, 'r') as f:
                    content = f.read()
                results['node'] = {
                    'file': 'package.json',
                    'analysis': await self.analyze_node_dependencies(content)
                }
            
            # Summary
            dependency_count = 0
            outdated_count = 0
            vulnerable_count = 0
            
            if results['python'] and 'analysis' in results['python']:
                analysis = results['python']['analysis']
                dependency_count += analysis.get('dependency_count', 0)
                outdated_count += analysis.get('outdated_count', 0)
                vulnerable_count += analysis.get('vulnerable_count', 0)
            
            if results['node'] and 'analysis' in results['node']:
                analysis = results['node']['analysis']
                dependency_count += analysis.get('dependency_count', 0)
                outdated_count += analysis.get('outdated_count', 0)
                vulnerable_count += analysis.get('vulnerable_count', 0)
            
            results['summary'] = {
                'dependency_count': dependency_count,
                'outdated_count': outdated_count,
                'vulnerable_count': vulnerable_count
            }
            
            return results
        except Exception as e:
            logger.error(f"Failed to analyze project dependencies: {str(e)}")
            return {'error': str(e)}
    
    async def suggest_dependency_updates(self, repo_path: str) -> Dict[str, Any]:
        """Suggest dependency updates for a project."""
        try:
            analysis = await self.analyze_project_dependencies(repo_path)
            suggestions = []
            
            # Process Python dependencies
            if analysis.get('python') and 'analysis' in analysis['python']:
                python_analysis = analysis['python']['analysis']
                for pkg in python_analysis.get('outdated', []):
                    suggestion = {
                        'name': pkg['name'],
                        'type': 'python',
                        'current_version': pkg['current_version'],
                        'suggested_version': pkg['latest_version'],
                        'reason': 'Update to latest version for new features and security fixes.',
                        'priority': 'medium'
                    }
                    
                    # Set higher priority for vulnerable packages
                    if pkg.get('is_vulnerable', False):
                        suggestion['reason'] = 'Critical: This package has known vulnerabilities.'
                        suggestion['priority'] = 'high'
                    
                    suggestions.append(suggestion)
            
            # Process Node.js dependencies
            if analysis.get('node') and 'analysis' in analysis['node']:
                node_analysis = analysis['node']['analysis']
                for pkg in node_analysis.get('outdated', []):
                    suggestion = {
                        'name': pkg['name'],
                        'type': 'node',
                        'current_version': pkg['current_version'],
                        'suggested_version': pkg['latest_version'],
                        'reason': 'Update to latest version for new features and security fixes.',
                        'priority': 'medium'
                    }
                    
                    # Lower priority for dev dependencies
                    if pkg.get('is_dev', False):
                        suggestion['priority'] = 'low'
                    
                    # Set higher priority for vulnerable packages
                    if pkg.get('is_vulnerable', False):
                        suggestion['reason'] = 'Critical: This package has known vulnerabilities.'
                        suggestion['priority'] = 'high'
                    
                    suggestions.append(suggestion)
            
            return {
                'suggestions': suggestions,
                'suggestion_count': len(suggestions)
            }
        except Exception as e:
            logger.error(f"Failed to suggest dependency updates: {str(e)}")
            return {'error': str(e)}

