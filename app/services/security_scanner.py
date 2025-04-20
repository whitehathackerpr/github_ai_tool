    
    async def _find_files(self, directory: str, extension: str) -> List[str]:
        """Find all files with a given extension in a directory recursively."""
        try:
            files = []
            for root, _, filenames in os.walk(directory):
                # Skip hidden directories and virtual environments
                if ('/.git/' in root + '/' or 
                    '/node_modules/' in root + '/' or
                    '/venv/' in root + '/' or
                    '/.venv/' in root + '/'):
                    continue
                
                for filename in filenames:
                    if filename.endswith(extension):
                        files.append(os.path.join(root, filename))
            return files
        except Exception as e:
            logger.error(f"Error finding files: {str(e)}")
            return []
    
    async def _find_potential_secrets(self, directory: str) -> Dict[str, Any]:
        """Scan files for potential secrets like API keys, tokens, and credentials."""
        try:
            # Define patterns for potential secrets
            secret_patterns = [
                # API Keys
                r'api[_-]?key[^a-zA-Z0-9]([a-zA-Z0-9]{16,})',
                r'api[_-]?secret[^a-zA-Z0-9]([a-zA-Z0-9]{16,})',
                # AWS Keys
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'aws[_-]?access[_-]?key[^a-zA-Z0-9]([a-zA-Z0-9\/+=]{40,})',  # AWS Secret Access Key
                # Database connection strings
                r'(?:mongodb|mysql|postgresql|redis):\/\/[^\s"\']+',
                # Passwords
                r'password[^a-zA-Z0-9]([a-zA-Z0-9!@#$%^&*()_+]{8,})',
                r'passwd[^a-zA-Z0-9]([a-zA-Z0-9!@#$%^&*()_+]{8,})',
                r'pwd[^a-zA-Z0-9]([a-zA-Z0-9!@#$%^&*()_+]{8,})',
                # Private keys
                r'-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY[A-Za-z0-9+\/=\s]+-----END',
                # Authorization tokens
                r'authorization[^a-zA-Z0-9]([a-zA-Z0-9]{32,})',
                r'auth[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9]{32,})',
                r'bearer[^a-zA-Z0-9]([a-zA-Z0-9_\-\.=]{30,})',
                # GitHub tokens
                r'github[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9_]{40,})',
                # General tokens
                r'token[^a-zA-Z0-9]([a-zA-Z0-9_\-\.=]{20,})',
            ]
            
            # Compile all patterns
            patterns = [re.compile(pattern, re.IGNORECASE) for pattern in secret_patterns]
            
            # Find all text files
            text_extensions = ['.txt', '.md', '.py', '.js', '.ts', '.java', '.c', '.cpp', 
                             '.h', '.cs', '.php', '.rb', '.go', '.rs', '.yaml', '.yml', 
                             '.json', '.xml', '.html', '.css', '.sh', '.bat', '.ps1',
                             '.env', '.config', '.ini', '.properties']
            
            text_files = []
            for ext in text_extensions:
                text_files.extend(await self._find_files(directory, ext))
            
            # Scan files for secrets
            potential_secrets = []
            
            for file_path in text_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Check each pattern
                        for i, pattern in enumerate(patterns):
                            matches = pattern.finditer(content)
                            for match in matches:
                                potential_secrets.append({
                                    'file': file_path,
                                    'line': content.count('\n', 0, match.start()) + 1,
                                    'pattern_type': i,  # Index of the pattern that matched
                                    'pattern': secret_patterns[i],
                                    'match': match.group(0)[:50] + ('...' if len(match.group(0)) > 50 else ''),
                                    'severity': 'HIGH'  # Secrets are always high severity
                                })
                except Exception as e:
                    logger.warning(f"Error scanning file {file_path}: {str(e)}")
            
            return {
                'potential_secrets': potential_secrets,
                'count': len(potential_secrets),
                'files_scanned': len(text_files)
            }
        except Exception as e:
            logger.error(f"Error scanning for secrets: {str(e)}")
            return {'error': str(e), 'potential_secrets': [], 'count': 0, 'files_scanned': 0}

import os
import logging
import subprocess
import tempfile
import re
import json
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class SecurityScanner:
    """Scan code and repositories for security vulnerabilities."""
    
    def __init__(self):
        """Initialize security scanner."""
        pass
    
    async def scan_python_code(self, code: str) -> Dict[str, Any]:
        """Scan Python code for security vulnerabilities using bandit."""
        try:
            # Create a temporary file to hold the code
            with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
                temp.write(code.encode('utf-8'))
                temp_path = temp.name
            
            results = await self._run_bandit(temp_path)
            
            # Clean up temporary file
            os.unlink(temp_path)
            
            return results
        except Exception as e:
            logger.error(f"Failed to scan Python code: {str(e)}")
            return {'error': str(e)}
    
    async def scan_javascript_code(self, code: str) -> Dict[str, Any]:
        """Scan JavaScript code for security vulnerabilities using npm audit."""
        try:
            # Create a temporary directory and file
            temp_dir = tempfile.mkdtemp()
            temp_file = os.path.join(temp_dir, 'index.js')
            
            with open(temp_file, 'w') as f:
                f.write(code)
            
            # Create minimal package.json
            package_json = os.path.join(temp_dir, 'package.json')
            with open(package_json, 'w') as f:
                f.write('{"name":"temp","version":"1.0.0"}')
            
            results = await self._run_npm_audit(temp_dir)
            
            # Clean up temporary directory
            for file in os.listdir(temp_dir):
                os.unlink(os.path.join(temp_dir, file))
            os.rmdir(temp_dir)
            
            return results
        except Exception as e:
            logger.error(f"Failed to scan JavaScript code: {str(e)}")
            return {'error': str(e)}
    
    async def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan an entire repository for security vulnerabilities."""
        try:
            python_files = await self._find_files(repo_path, '.py')
            js_files = await self._find_files(repo_path, '.js')
            
            results = {
                'python_results': [],
                'js_results': [],
                'vulnerability_count': 0,
                'high_severity_count': 0,
                'medium_severity_count': 0,
                'low_severity_count': 0
            }
            
            # Scan Python files
            for file_path in python_files:
                file_result = await self._run_bandit(file_path)
                if 'vulnerabilities' in file_result and file_result['vulnerabilities']:
                    results['python_results'].append({
                        'file': file_path,
                        'results': file_result
                    })
                    results['vulnerability_count'] += file_result.get('vulnerability_count', 0)
                    results['high_severity_count'] += file_result.get('high_severity_count', 0)
                    results['medium_severity_count'] += file_result.get('medium_severity_count', 0)
                    results['low_severity_count'] += file_result.get('low_severity_count', 0)
            
            # Scan JS files if package.json exists
            package_json = os.path.join(repo_path, 'package.json')
            if os.path.exists(package_json):
                js_result = await self._run_npm_audit(repo_path)
                results['js_results'].append({
                    'directory': repo_path,
                    'results': js_result
                })
                results['vulnerability_count'] += js_result.get('vulnerability_count', 0)
                results['high_severity_count'] += js_result.get('high_severity_count', 0)
                results['medium_severity_count'] += js_result.get('medium_severity_count', 0)
                results['low_severity_count'] += js_result.get('low_severity_count', 0)
            
            # Check for secrets/credentials using a simple regex pattern
            secrets_results = await self._find_potential_secrets(repo_path)
            results['secrets_scan'] = secrets_results
            results['vulnerability_count'] += len(secrets_results.get('potential_secrets', []))
            
            return results
        except Exception as e:
            logger.error(f"Failed to scan repository: {str(e)}")
            return {'error': str(e)}
    
    async def _run_bandit(self, file_path: str) -> Dict[str, Any]:
        """Run bandit on a Python file."""
        try:
            # Check if bandit is installed
            result = subprocess.run(['which', 'bandit'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'bandit not installed'}
            
            # Run bandit with JSON output format
            result = subprocess.run(
                ['bandit', '-f', 'json', file_path], 
                capture_output=True, 
                text=True
            )
            
            # Parse the output
            vulnerabilities = []
            high_severity_count = 0
            medium_severity_count = 0
            low_severity_count = 0
            
            try:
                if result.stdout.strip():
                    bandit_result = json.loads(result.stdout)
                    for issue in bandit_result.get('results', []):
                        severity = issue.get('issue_severity', 'LOW')
                        if severity == 'HIGH':
                            high_severity_count += 1
                        elif severity == 'MEDIUM':
                            medium_severity_count += 1
                        else:
                            low_severity_count += 1
                        
                        vulnerabilities.append({
                            'line': issue.get('line_number', 0),
                            'severity': severity,
                            'confidence': issue.get('issue_confidence', 'LOW'),
                            'message': issue.get('issue_text', ''),
                            'code': issue.get('code', '')
                        })
            except json.JSONDecodeError:
                logger.warning("Failed to parse Bandit JSON output")
            
            return {
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'high_severity_count': high_severity_count,
                'medium_severity_count': medium_severity_count,
                'low_severity_count': low_severity_count
            }
        except Exception as e:
            logger.error(f"Failed to run bandit: {str(e)}")
            return {'error': str(e)}
    
    async def _run_npm_audit(self, directory: str) -> Dict[str, Any]:
        """Run npm audit on a JavaScript project directory."""
        try:
            # Check if npm is installed
            result = subprocess.run(['which', 'npm'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'npm not installed'}
            
            # Run npm audit
            result = subprocess.run(
                ['npm', 'audit', '--json'], 
                cwd=directory,
                capture_output=True, 
                text=True
            )
            
            # Parse the output
            vulnerabilities = []
            high_severity_count = 0
            medium_severity_count = 0
            low_severity_count = 0
            
            try:
                if result.stdout.strip():
                    audit_result = json.loads(result.stdout)
                    
                    # Extract vulnerabilities from npm audit output
                    for vuln_id, vuln_data in audit_result.get('vulnerabilities', {}).items():
                        severity = vuln_data.get('severity', 'low').upper()
                        if severity == 'HIGH' or severity == 'CRITICAL':
                            high_severity_count += 1
                        elif severity == 'MEDIUM':
                            medium_severity_count += 1
                        else:
                            low_severity_count += 1
                        
                        vulnerabilities.append({
                            'id': vuln_id,
                            'severity': severity,
                            'package': vuln_data.get('name', ''),
                            'path': vuln_data.get('path', ''),
                            'message': vuln_data.get('title', ''),
                            'overview': vuln_data.get('overview', ''),
                            'recommendation': vuln_data.get('recommendation', ''),
                        })
            except json.JSONDecodeError:
                logger.warning("Failed to parse npm audit JSON output")
                # Handle case where npm audit doesn't produce JSON
                if "found 0 vulnerabilities" in result.stderr:
                    return {
                        'vulnerabilities': [],
                        'vulnerability_count': 0,
                        'high_severity_count': 0,
                        'medium_severity_count': 0,
                        'low_severity_count': 0
                    }
            
            return {
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'high_severity_count': high_severity_count,
                'medium_severity_count': medium_severity_count,
                'low_severity_count': low_severity_count
            }
        except Exception as e:
            logger.error(f"Failed to run npm audit: {str(e)}")
            return {'error': str(e)}
    
    async def _find_files(self, directory: str, extension: str) -> List[str]:
        """Find all files with a given extension in a directory recursively."""
        try:
            files = []
            for root, _, filenames in os.walk(directory):
                # Skip hidden directories and virtual environments
                if ('/.git/' in root + '/' or 
                    '/node_modules/' in root + '/' or
                    '/venv/' in root + '/' or
                    '/.venv/' in root + '/'):
                    continue
                
                for filename in filenames:
                    if filename.endswith(extension):
                        files.append(os.path.join(root, filename))
            return files
        except Exception as e:
            logger.error(f"Error finding files: {str(e)}")
            return []
    
    async def _find_potential_secrets(self, directory: str) -> Dict[str, Any]:
        """Scan files for potential secrets like API keys, tokens, and credentials."""
        try:
            # Define patterns for potential secrets
            secret_patterns = [
                # API Keys
                r'api[_-]?key[^a-zA-Z0-9]([a-zA-Z0-9]{16,})',
                r'api[_-]?secret[^a-zA-Z0-9]([a-zA-Z0-9]{16,})',
                # AWS Keys
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'aws[_-]?access[_-]?key[^a-zA-Z0-9]([a-zA-Z0-9\/+=]{40,})',  # AWS Secret Access Key
                # Database connection strings
                r'(?:mongodb|mysql|postgresql|redis):\/\/[^\s"\']+',
                # Passwords
                r'password[^a-zA-Z0-9]([a-zA-Z0-9!@#$%^&*()_+]{8,})',
                r'passwd[^a-zA-Z0-9]([a-zA-Z0-9!@#$%^&*()_+]{8,})',
                r'pwd[^a-zA-Z0-9]([a-zA-Z0-9!@#$%^&*()_+]{8,})',
                # Private keys
                r'-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY[A-Za-z0-9+\/=\s]+-----END',
                # Authorization tokens
                r'authorization[^a-zA-Z0-9]([a-zA-Z0-9]{32,})',
                r'auth[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9]{32,})',
                r'bearer[^a-zA-Z0-9]([a-zA-Z0-9_\-\.=]{30,})',
                # GitHub tokens
                r'github[_-]?token[^a-zA-Z0-9]([a-zA-Z0-9_]{40,})',
                # General tokens
                r'token[^a-zA-Z0-9]([a-zA-Z0-9_\-\.=]{20,})',
            ]
            
            # Compile all patterns
            patterns = [re.compile(pattern, re.IGNORECASE) for pattern in secret_patterns]
            
            # Find all text files
            text_extensions = ['.txt', '.md', '.py', '.js', '.ts', '.java', '.c', '.cpp', 
                             '.h', '.cs', '.php', '.rb', '.go', '.rs', '.yaml', '.yml', 
                             '.json', '.xml', '.html', '.css', '.sh', '.bat', '.ps1',
                             '.env', '.config', '.ini', '.properties']
            
            text_files = []
            for ext in text_extensions:
                text_files.extend(await self._find_files(directory, ext))
            
            # Scan files for secrets
            potential_secrets = []
            
            for file_path in text_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Check each pattern
                        for i, pattern in enumerate(patterns):
                            matches = pattern.finditer(content)
                            for match in matches:
                                potential_secrets.append({
                                    'file': file_path,
                                    'line': content.count('\n', 0, match.start()) + 1,
                                    'pattern_type': i,  # Index of the pattern that matched
                                    'pattern': secret_patterns[i],
                                    'match': match.group(0)[:50] + ('...' if len(match.group(0)) > 50 else ''),
                                    'severity': 'HIGH'  # Secrets are always high severity
                                })
                except Exception as e:
                    logger.warning(f"Error scanning file {file_path}: {str(e)}")
            
            return {
                'potential_secrets': potential_secrets,
                'count': len(potential_secrets),
                'files
        """Scan Python code for security vulnerabilities using bandit."""
        try:
            # Create a temporary file to hold the code
            with tempfile.NamedTemporaryFile(suffix='.py', delete=False) as temp:
                temp.write(code.encode('utf-8'))
                temp_path = temp.name
            
            results = await self._run_bandit(temp_path)
            
            # Clean up temporary file
            os.unlink(temp_path)
            
            return results
        except Exception as e:
            logger.error(f"Failed to scan Python code: {str(e)}")
            return {'error': str(e)}
    
    async def scan_javascript_code(self, code: str) -> Dict[str, Any]:
        """Scan JavaScript code for security vulnerabilities using npm audit."""
        try:
            # Create a temporary directory and file
            temp_dir = tempfile.mkdtemp()
            temp_file = os.path.join(temp_dir, 'index.js')
            
            with open(temp_file, 'w') as f:
                f.write(code)
            
            # Create minimal package.json
            package_json = os.path.join(temp_dir, 'package.json')
            with open(package_json, 'w') as f:
                f.write('{"name":"temp","version":"1.0.0"}')
            
            results = await self._run_npm_audit(temp_dir)
            
            # Clean up temporary directory
            for file in os.listdir(temp_dir):
                os.unlink(os.path.join(temp_dir, file))
            os.rmdir(temp_dir)
            
            return results
        except Exception as e:
            logger.error(f"Failed to scan JavaScript code: {str(e)}")
            return {'error': str(e)}
    
    async def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan an entire repository for security vulnerabilities."""
        try:
            python_files = await self._find_files(repo_path, '.py')
            js_files = await self._find_files(repo_path, '.js')
            
            results = {
                'python_results': [],
                'js_results': [],
                'vulnerability_count': 0,
                'high_severity_count': 0,
                'medium_severity_count': 0,
                'low_severity_count': 0
            }
            
            # Scan Python files
            for file_path in python_files:
                file_result = await self._run_bandit(file_path)
                if 'vulnerabilities' in file_result and file_result['vulnerabilities']:
                    results['python_results'].append({
                        'file': file_path,
                        'results': file_result
                    })
                    results['vulnerability_count'] += file_result.get('vulnerability_count', 0)
                    results['high_severity_count'] += file_result.get('high_severity_count', 0)
                    results['medium_severity_count'] += file_result.get('medium_severity_count', 0)
                    results['low_severity_count'] += file_result.get('low_severity_count', 0)
            
            # Scan JS files if package.json exists
            package_json = os.path.join(repo_path, 'package.json')
            if os.path.exists(package_json):
                js_result = await self._run_npm_audit(repo_path)
                results['js_results'].append({
                    'directory': repo_path,
                    'results': js_result
                })
                results['vulnerability_count'] += js_result.get('vulnerability_count', 0)
                results['high_severity_count'] += js_result.get('high_severity_count', 0)
                results['medium_severity_count'] += js_result.get('medium_severity_count', 0)
                results['low_severity_count'] += js_result.get('low_severity_count', 0)
            
            # Check for secrets/credentials using a simple regex pattern
            secrets_results = await self._find_potential_secrets(repo_path)
            results['secrets_scan'] = secrets_results
            results['vulnerability_count'] += len(secrets_results.get('potential_secrets', []))
            
            return results
        except Exception as e:
            logger.error(f"Failed to scan repository: {str(e)}")
            return {'error': str(e)}
    
    async def _run_bandit(self, file_path: str) -> Dict[str, Any]:
        """Run bandit on a Python file."""
        try:
            # Check if bandit is installed
            result = subprocess.run(['which', 'bandit'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'bandit not installed'}
            
            # Run bandit with JSON output format
            result = subprocess.run(
                ['bandit', '-f', 'json', file_path], 
                capture_output=True, 
                text=True
            )
            
            # Parse the output
            vulnerabilities = []
            high_severity_count = 0
            medium_severity_count = 0
            low_severity_count = 0
            
            try:
                if result.stdout.strip():
                    bandit_result = json.loads(result.stdout)
                    for issue in bandit_result.get('results', []):
                        severity = issue.get('issue_severity', 'LOW')
                        if severity == 'HIGH':
                            high_severity_count += 1
                        elif severity == 'MEDIUM':
                            medium_severity_count += 1
                        else:
                            low_severity_count += 1
                        
                        vulnerabilities.append({
                            'line': issue.get('line_number', 0),
                            'severity': severity,
                            'confidence': issue.get('issue_confidence', 'LOW'),
                            'message': issue.get('issue_text', ''),
                            'code': issue.get('code', '')
                        })
            except json.JSONDecodeError:
                logger.warning("Failed to parse Bandit JSON output")
            
            return {
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'high_severity_count': high_severity_count,
                'medium_severity_count': medium_severity_count,
                'low_severity_count': low_severity_count
            }
        except Exception as e:
            logger.error(f"Failed to run bandit: {str(e)}")
            return {'error': str(e)}
    
    async def _run_npm_audit(self, directory: str) -> Dict[str, Any]:
        """Run npm audit on a JavaScript project directory."""
        try:
            # Check if npm is installed
            result = subprocess.run(['which', 'npm'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'npm not installed'}
            
            # Run npm audit
            result = subprocess.run(
                ['npm', 'audit', '--json'], 
                cwd=directory,
                capture_output=True, 
                text=True
            )
            
            # Parse the output
            vulnerabilities = []
            high_severity_count = 0
            medium_severity_count = 0
            low_severity_count = 0
            
            try:
                if result.stdout.strip():
                    audit_result = json.loads(result.stdout)
                    
                    # Extract vulnerabilities from npm audit output
                    for vuln_id, vuln_data in audit_result.get('vulnerabilities', {}).items():
                        severity = vuln_data.get('severity', 'low').upper()
                        if severity == 'HIGH' or severity == 'CRITICAL':
                            high_severity_count += 1
                        elif severity == 'MEDIUM':
                            medium_severity_count += 1
                        else:
                            low_severity_count += 1
                        
                        vulnerabilities.append({
                            'id': vuln_id,
                            'severity': severity,
                            'package': vuln_data.get('name', ''),
                            'path': vuln_data.get('path', ''),
                            'message': vuln_data.get('title', ''),
                            'overview': vuln_data.get('overview', ''),
                            'recommendation': vuln_data.get('recommendation', ''),
                        })
            except json.JSONDecodeError:
                logger.warning("Failed to parse npm audit JSON output")
                # Handle case where npm audit doesn't produce JSON
                if "found 0 vulnerabilities" in result.stderr:
                    return {
                        'vulnerabilities': [],
                        'vulnerability_count': 0,
                        'high_severity_count': 0,
                        'medium_severity_count': 0,
                        'low_severity_count': 0
                    }
            
            return {
                'vulnerabilities': vulnerabilities,
                'vulnerability_count': len(vulnerabilities),
                'high_severity_count': high_severity_count,
                'medium_severity_count': medium_severity_count,
                'low_severity_count': low_severity_count
            }
        except Exception as e:
            logger.error(f"Failed to run npm audit: {str(e)}")
            return {'error': str(e)}
    
    async def _find_files(self

